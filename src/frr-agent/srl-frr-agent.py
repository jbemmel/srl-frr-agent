#!/usr/bin/env python
# coding=utf-8

import grpc
import datetime
import time
import sys
import logging
import os
import ipaddress
import json
import signal
import traceback
import subprocess

# sys.path.append('/usr/lib/python3.6/site-packages/sdk_protos')
from sdk_protos import sdk_service_pb2, sdk_service_pb2_grpc,config_service_pb2

from grpc._channel import _InactiveRpcError

# import sdk_common_pb2

# To report state back
import telemetry_service_pb2,telemetry_service_pb2_grpc

from pygnmi.client import gNMIclient

# pygnmi does not support multithreading, so we need to build it
from pygnmi.spec.v080.gnmi_pb2_grpc import gNMIStub
from pygnmi.spec.v080.gnmi_pb2 import SetRequest, Update, TypedValue
from pygnmi.create_gnmi_path import gnmi_path_generator

from logging.handlers import RotatingFileHandler

############################################################
## Agent will start with this name
############################################################
agent_name='srl_frr_agent'

############################################################
## Open a GRPC channel to connect to sdk_mgr on the dut
## sdk_mgr will be listening on 50053
############################################################
#channel = grpc.insecure_channel('unix:///opt/srlinux/var/run/sr_sdk_service_manager:50053')
channel = grpc.insecure_channel('127.0.0.1:50053')
metadata = [('agent_name', agent_name)]
stub = sdk_service_pb2_grpc.SdkMgrServiceStub(channel)

# Global gNMI channel, used by multiple threads
gnmi_options = [('username', 'admin'), ('password', 'admin')]
gnmi_channel = grpc.insecure_channel(
   'unix:///opt/srlinux/var/run/sr_gnmi_server', options = gnmi_options )
# Postpone connect
# grpc.channel_ready_future(gnmi_channel).result(timeout=5)

############################################################
## Subscribe to required event
## This proc handles subscription of: Interface, LLDP,
##                      Route, Network Instance, Config
############################################################
def Subscribe(stream_id, option):
    # XXX Does not pass pylint
    op = sdk_service_pb2.NotificationRegisterRequest.AddSubscription
    if option == 'cfg':
        entry = config_service_pb2.ConfigSubscriptionRequest()
        # entry.key.js_path = '.' + agent_name
        request = sdk_service_pb2.NotificationRegisterRequest(op=op, stream_id=stream_id, config=entry)

    subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    print('Status of subscription response for {}:: {}'.format(option, subscription_response.status))

############################################################
## Subscribe to all the events that Agent needs
############################################################
def Subscribe_Notifications(stream_id):
    '''
    Agent will receive notifications to what is subscribed here.
    '''
    if not stream_id:
        logging.info("Stream ID not sent.")
        return False

    # Subscribe to config changes, first
    Subscribe(stream_id, 'cfg')
    # Subscribe(stream_id, 'nexthop_group')

############################################################
## Function to populate state of agent config
## using telemetry -- add/update info from state
############################################################
def Add_Telemetry(js_path, js_data):
    telemetry_stub = telemetry_service_pb2_grpc.SdkMgrTelemetryServiceStub(channel)
    telemetry_update_request = telemetry_service_pb2.TelemetryUpdateRequest()
    telemetry_info = telemetry_update_request.state.add()
    telemetry_info.key.js_path = js_path
    telemetry_info.data.json_content = json.dumps(js_data)
    logging.info(f"Telemetry_Update_Request :: {telemetry_update_request}")
    telemetry_response = telemetry_stub.TelemetryAddOrUpdate(request=telemetry_update_request, metadata=metadata)
    return telemetry_response

#
# Uses gNMI to get /platform/chassis/mac-address and format as hhhh.hhhh.hhhh
#
def GetSystemMAC():
   path = '/platform/chassis/mac-address'
   with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                            username="admin",password="admin",
                            insecure=True, debug=False) as gnmi:
      result = gnmi.get( encoding='json_ietf', path=[path] )
      for e in result['notification']:
         if 'update' in e:
           logging.info(f"GetSystemMAC GOT Update :: {e['update']}")
           m = e['update'][0]['val'] # aa:bb:cc:dd:ee:ff
           return f'{m[0]}{m[1]}.{m[2]}{m[3]}.{m[4]}{m[5]}'

   return "0000.0000.0000"

def ipv6_2_mac(ipv6):
    # remove subnet info if given
    subnetIndex = ipv6.find("/")
    if subnetIndex != -1:
        ipv6 = ipv6[:subnetIndex]

    ipv6Parts = ipv6.split(":")
    macParts = []
    for ipv6Part in ipv6Parts[-4:]:
        while len(ipv6Part) < 4:
            ipv6Part = "0" + ipv6Part
        macParts.append(ipv6Part[:2])
        macParts.append(ipv6Part[-2:])

    # modify parts to match MAC value
    macParts[0] = "%02x" % (int(macParts[0], 16) ^ 2)
    del macParts[4]
    del macParts[3]

    return ":".join(macParts)

#
# Runs as a separate thread
#
# Responsible for (re)starting FRR daemon(s) to update their config, and
# monitoring ipdb for route updates.
#
# Multi-threading logic quickly gets complicated; simpler to restart the
# daemon each time an interface is added/removed, rather than call vtysh with
# dynamic updates
#
from threading import Thread, Event
class MonitoringThread(Thread):
   def __init__(self, state, net_inst, interfaces):
       Thread.__init__(self)
       self.daemon = True # Mark thread as a daemon thread
       self.state = state
       self.event = Event()
       self.net_inst = net_inst
       self.interfaces = interfaces # dict of intf->as

       # Wait for gNMI to connect
       while True:
         try:
           grpc.channel_ready_future(gnmi_channel).result(timeout=5)
           logging.info( "gRPC unix socket connected" )
           break
         except grpc.FutureTimeoutError:
           logging.warning( "gRPC timeout, continue waiting 5s..." )

   def gNMI_Set( self, updates ):
      #with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
      #                       username="admin",password="admin",
      #                       insecure=True, debug=True) as gnmic:
      #  logging.info( f"Sending gNMI SET: {path} {config} {gnmic}" )
      update_msg = []
      for path,data in updates:
        u_path = gnmi_path_generator( path )
        u_val = bytes( json.dumps(data), 'utf-8' )
        update_msg.append(Update(path=u_path, val=TypedValue(json_ietf_val=u_val)))
      update_request = SetRequest( update=update_msg )
      try:
            # Leaving out 'metadata' does return an error, so the call goes through
            # It just doesn't show up in CLI (cached), logout+login fixes it
            res = self.gnmi_stub.Set( update_request, metadata=gnmi_options )
            logging.info( f"After gnmi.Set {updates}: {res}" )
            return res
      except _InactiveRpcError as err:
            logging.error(err)
            # May happen during system startup, retry once
            if err.code() == grpc.StatusCode.FAILED_PRECONDITION:
                logging.info("Exception during startup? Retry in 5s...")
                time.sleep( 5 )
                res = self.gnmi_stub.Set( update_request, metadata=gnmi_options )
                logging.info(f"OK, success? {res}")
                return res
            raise err

   #
   # Configure 'linux' protocol in given namespace, to import FRR routes
   # - no ECMP
   # - IPv4 next hops are invalid, only works for IPv6
   #
   def ConfigureLinuxRouteImport( self ):
       path = f"/network-instance[name={self.net_inst}]/protocols/linux"
       return self.gNMI_Set( updates=[(path,{ 'import-routes' : True })] )

   def ConfigureIPv4UsingIPv6Nexthops( self ):
       path = f"/network-instance[name={self.net_inst}]/ip-forwarding"
       return self.gNMI_Set( updates=[(path,{ 'receive-ipv4-check': False } )] )

   #
   # Statically configures an IPv6 address on the given interface
   #
   # IPv4: for local resolution to the nexthop MAC, now removed
   # IPv6: SRL NDK does not support using link local IPv6 address as next hop
   #
   # Returns (ipv4,ipv6) nexthop addresses for peer
   #
   def ConfigurePeerIPMAC( self, intf, local_ip, peer_ip, mac, local_v6, ni_config ):
      logging.info( f"ConfigurePeerIPMAC on {intf}: ip={peer_ip} mac={mac} local_ip={local_ip}" )
      phys_sub = intf.split('.') # e.g. e1-1.0 => ethernet-1/1.0
      base_if = phys_sub[0].replace('-','/').replace('e',"ethernet-")

      #
      # Calculate pair of /31 IPs for given interface (e.g. e1-1 => peerlinks[0])
      #
      def GetLinkLocalIPs( phys_intf, link_local_range ):
          peerlinks = list(ipaddress.ip_network(link_local_range).subnets(new_prefix=31))
          peer_link = peerlinks[ int(phys_intf.split('-')[1]) - 1 ]
          return list( map( str, peer_link.hosts() ) )

      # Calculates a /127 to use in fc00::/7 private space, based on node IDs
      # See RFC4193 https://datatracker.ietf.org/doc/html/rfc4193
      def CalcIPv6LinkIPs():
         lo_ip = min( ipaddress.ip_address(local_ip),ipaddress.ip_address(peer_ip) )
         hi_ip = max( ipaddress.ip_address(local_ip),ipaddress.ip_address(peer_ip) )
         lo = '{:02X}{:02X}:{:02X}{:02X}'.format(*map(int, str(lo_ip).split('.')))
         hi = '{:02X}{:02X}:{:02X}{:02X}'.format(*map(int, str(hi_ip).split('.')))
         # Local private ipv6 address based on RFC4193, generated from both router IDs
         # Use 2 * last octet of smaller router ID as unique link distinguisher
         # On cSRL MACs start with :01 on e1-1, but this may not be universal -> no -1
         link_octet = int( (local_v6 if local_ip == str(lo_ip) else mac).split(':')[-1], 16 )
         private_v6 = ipaddress.ip_address( f"fd00:{hi}:{lo}::{(2*link_octet):x}" )
         logging.info( f"ConfigurePeerIPMAC selecting private RFC4193 IPv6: {private_v6}" )
         v6_subnet = ipaddress.ip_network( str(private_v6) + '/127', strict=False )
         i6 = list( map( str, v6_subnet.hosts() ) )
         return ( i6[0], i6[1] ) if local_ip == str(lo_ip) else ( i6[1], i6[0] )

      # intip = int(router_id)
      # last_octet = (intip % 256)
      #  ip2 = intip + last_octet # Double last octet, may overflow into next
      #  return ipaddress.ip_address( ip2 )

      # For IPv6, build a /127 based on mapped ipv4 of  2 * highest ID
      # (assuming leaves have higher IDs than spines)
      # highest_ip = max( ipaddress.ip_address(local_ip),ipaddress.ip_address(peer_ip) )
      # ip31 = str( ShiftIP(highest_ip) ) # Create room for /31
      # mapped_v4 = '::ffff:' + ip31 # Or 'regular' v6: '2001::ffff:'
      # v6_subnet = ipaddress.ip_network( mapped_v4 + '/127', strict=False )
      # v6_ips = list( map( str, v6_subnet.hosts() ) )
      local_v6, peer_v6 = CalcIPv6LinkIPs()
      logging.info( f"ConfigurePeerIPMAC local[v6]={local_v6} peer[v6]={peer_v6}" )

      path = f'/interface[name={base_if}]/subinterface[index={phys_sub[1]}]'
      desc = f"auto-configured by SRL FRR agent peer={peer_ip}"
      config = {
        "admin-state" : "enable",
        "description" : desc,
        "ipv6" : {
          "address" : [
             { "ip-prefix" : local_v6 + "/127",
               "primary": '[null]'  # type 'empty'
             }
             # Could configure a static MAC here too, but better to use default mechanisms
          ],
          "router-advertisement": { "router-role": { "admin-state": "disable" } }
        }
      }
      updates=[ (path, config) ]

      if ni_config["use_ipv6_nexthops_for_ipv4"]:
          result = (None,peer_v6)
      else:
          ips = GetLinkLocalIPs( phys_sub[0], ni_config["bgp_link_local_range"] )
          config['ipv4'] = {
             "address" : [
                { "ip-prefix" : ips[ 0 ] + "/31",
                  "primary": '[null]'  # type 'empty'
                }
             ],
             "arp" : {
                "duplicate-address-detection" : False, # Need to disable DAD
                "neighbor": [
                  {
                    "ipv4-address": ips[ 1 ],
                    "link-layer-address": mac, # Because dynamic ARP wont work
                    "_annotate_link-layer-address": desc
                  }
                ]
             }
          }
          result = ( ips[1], peer_v6 ) # ipv4+ipv6 nexthops

      self.gNMI_Set( updates=updates )
      return result

   #
   # Called by another thread to wake up this one
   #
   def CheckForUpdatedInterfaces(self):
      ni = self.state.network_instances[ self.net_inst ]
      cfg = ni['config']
      cli = cfg['bgp_neighbor_lines'] if 'bgp_neighbor_lines' in cfg else ""
      changes = 0
      for i,peer_as in self.interfaces.items():
        if i not in cli:
           # ipdb, use_ipv4 = self.state.ipdbs[ self.net_inst ]
           logging.info( f"UpdateInterfaces: activate BGP interface {i}" )
           self.todo.append( i )
           changes += 1
        else:
           logging.info( f"UpdateInterfaces: already have {i}: {cli}" )

      if changes > 0 or ni['frr']=='restart':
         logging.info( f"UpdateInterfaces: Signalling update event changes={changes}" )
         self.event.set()

   def run(self):
      logging.info( f"MonitoringThread run(): {self.net_inst} {self.interfaces}")
      ni = self.state.network_instances[ self.net_inst ]
      try:
        cfg = ni['config']

        # Create per-thread gNMI stub, using a global channel
        self.gnmi_stub = gNMIStub( gnmi_channel )

        # Create Prefix manager, this starts listening to netlink route events
        if cfg['route_import'] == "ndk":
          from prefix_mgr import PrefixManager # pylint: disable=import-error
          self.prefix_mgr = PrefixManager( self.net_inst, channel, metadata, cfg )
        else:
          self.ConfigureLinuxRouteImport()

        if cfg['use_ipv6_nexthops_for_ipv4']:
            # Could combine gNMI calls
            self.ConfigureIPv4UsingIPv6Nexthops()

        # moved to auto-config agent
        # ConfigureImportPolicyToAvoidBGPManagerCrash( gnmi_stub )

        def add_interface_to_config(i):
          """
          Updates FRR config lines that specify interfaces to listen/connect on
          and (re)starts the daemon for changes to take effect
          """
          if 'bgp_neighbor_lines' not in cfg or i not in cfg['bgp_neighbor_lines']:
             lines = ""
             for name,peer_as in ni['bgp_interfaces'].items():
               # Add single indent space at end
               lines += f'neighbor {name} interface v6only remote-as {peer_as}\n '
               # Use configured BGP port, custom patch
               lines += f'neighbor {name} port {cfg["frr_bgpd_port"]}\n '

             # Add 'regular' bgp groups and peers
             for g,gs in (cfg['groups'].items() if 'groups' in cfg else []):
               # remote-as must come first
               remote_as = 'internal' if 'peer_as' not in gs else gs['peer_as']['value']
               lines += f' neighbor {g} peer-group\n'
               lines += f' neighbor {g} remote-as {remote_as}\n'
               if remote_as=="internal":
                  lines += f' neighbor {g} update-source lo0.0\n'
               if 'addpath' in cfg:
                  addpath = cfg['addpath']
                  if addpath['tx_all_paths']['value']:
                      lines += f' neighbor {g} addpath-tx-all-paths\n'
                  if addpath['tx_bestpath_per_AS']['value']:
                      lines += f' neighbor {g} addpath-tx-bestpath-per-AS\n'
                  if addpath['disable_rx']['value']:
                      lines += f' neighbor {g} disable-addpath-rx\n'

             for n,ns in (cfg['neighbors'].items() if 'neighbors' in cfg else []):
               if ns['admin_state'][12:] == "enable":
                  lines += f' neighbor {n} peer-group {ns["peer_group"]["value"]}\n'
               # Else simply don't add it

             # TODO activate ipv4/ipv6 under address-family

             cfg["bgp_neighbor_lines"] = lines
             logging.info( f"About to (re)start FRR in {ni} to add {i}" )
             script_update_frr( **cfg )
             ni['frr'] = 'running' if cfg['admin_state']=='enable' else 'stopped'

        self.todo = list( self.interfaces.keys() ) # Initial list
        while True: # Keep waiting for interfaces to be added/removed
          while self.todo!=[]:
           for _i in self.todo:
            add_interface_to_config(_i)
            _get_peer = f'show bgp neighbors {_i} json'
            json_data = run_vtysh( ns=self.net_inst, show=[_get_peer] )
            if json_data:
                _js = json.loads( json_data )
                if _i in _js:
                   i = _js[ _i ]
                   neighbor = i['bgpNeighborAddr'] # ipv6 link-local
                   localId = i['localRouterId']
                   peerId = i['remoteRouterId']
                   if neighbor!="none" and peerId!="0.0.0.0":
                      logging.info( f"Peer {peerId} UP - data from FRR:\n{i}" )
                      localV6 = i['hostLocal']
                      logging.info( f"localAs={i['localAs']} remoteAs={i['remoteAs']}" )
                      logging.info( f"id={peerId} name={i['hostname'] if 'hostname' in i else '?'}" )
                      if cfg['assign_static_ipv6'] or not cfg['use_ipv6_nexthops_for_ipv4']:
                          # dont have the MAC address, but can derive it from ipv6 link local
                          mac = ipv6_2_mac(neighbor) # XXX not ideal, may differ
                          logging.info( f"{neighbor} MAC={mac}" )
                          peer_nhs = self.ConfigurePeerIPMAC( _i, localId, peerId, mac, localV6, cfg )
                      else:
                          peer_nhs = (None,neighbor) # /64 link-local ipv6 address

                      if hasattr(self,'prefix_mgr'):
                         self.prefix_mgr.onInterfaceBGPv6Connected( _i, peer_nhs, peerId, i['remoteAs'] )
                      self.todo.remove( _i )
                      logging.info( f"MonitoringThread done with {_i}, left={self.todo}" )
                      continue

                logging.info( f"MonitoringThread {_i} not in output or not up yet, wait 5s" )
                time.sleep(5)
                logging.info( f"MonitoringThread wakes up left={self.todo}" )
          logging.info( "MonitoringThread done processing TODO list, waiting for events..." )
          if ni['frr']=='restart':
             add_interface_to_config( "update_trigger" )
          self.event.wait(timeout=None)
          logging.info( f"MonitoringThread received event, TODO={self.todo}" )
          self.event.clear() # Reset for next iteration

      except Exception as e:
         traceback_str = ''.join(traceback.format_tb(e.__traceback__))
         logging.error( f"MonitoringThread error: {e} trace={traceback_str}" )

      logging.info( f"MonitoringThread exit: {self.net_inst}" )
      del ni['monitor_thread']

#
# Adds or removes given interface using vtysh
# Not currently used
# peer_as := internal | external | None (->remove)
def UpdateBGPInterface(ni,intf,peer_as):
    cfg = ni['config']
    net_inst = cfg['network_instance']
    if peer_as is not None:
       ni['bgp_interfaces'][ intf ] = peer_as
       cmd = [ f"neighbor {intf} interface v6only remote-as {peer_as}",
               f"neighbor {intf} port {cfg['frr_bgpd_port']}" ]
    else:
       # TODO remove NHG
       ni['bgp_interfaces'].pop( intf, None )
       cmd = [ f"no neighbor {intf}" ]

    # If FRR daemons are running, update this interface
    if 'frr' in ni and ni['frr']=='running':
       if 'bgp' in cfg and cfg['bgp']=='enable':
          ctxt = f"router bgp {cfg['autonomous_system']}"
          res = run_vtysh( ns=net_inst, context=ctxt, config=cmd )
          logging.info( f"UpdateBGPInterface: {res}" )
          # TODO return true/false for success

    return False

##################################################################
## Updates configuration state based on 'config' notifications
## May calls vtysh to update an interface
##
## Return: network instance that was updated
##################################################################
def Handle_Notification(obj, state):
    if obj.HasField('config'):
        logging.info(f"GOT CONFIG :: {obj.config.key.js_path}")

        # Tested on main thread
        # ConfigurePeerIPMAC( "e1-1.0", "1.2.3.4", "00:11:22:33:44:55" )

        net_inst = obj.config.key.keys[0] # e.g. "default"
        if net_inst == "mgmt":
            return None

        def get_data_as_json():
          if obj.config.op == 2: # Skip deletes, TODO process them?
             return {}
          json_acceptable_string = obj.config.data.json.replace("'", "\"")
          return json.loads(json_acceptable_string)

        ni = state.network_instances[ net_inst ] if net_inst in state.network_instances else {}

        def update_conf(category,key,value,restart_frr=False):
           if 'config' not in ni:
               ni['config'] = {}
           cfg = ni['config']
           if category in cfg:
               cfg[category].update( { key: value } )
           else:
               cfg[category] = { key: value }
           if restart_frr and 'frr' in ni:
               ni.update( { 'frr' : 'restart' } )

        base_path = ".network_instance.protocols.experimental_frr"
        if obj.config.key.js_path == base_path:
            logging.info(f"Got config for agent, now will handle it :: \n{obj.config}\
                            Operation :: {obj.config.op}\nData :: {obj.config.data.json}")
            # Could define NETNS here: "NETNS" : f'srbase-{net_inst}'
            params = { "network_instance" : net_inst }
            restartFRR = False

            def updateParam(p,v):
                params[ p ] = v
                cfg = ni['config'] if 'config' in ni else {}
                needRestart = True if (p not in cfg or cfg[p]!=v) else restartFRR
                logging.info(f"updateParam {p}='{v}' -> requires restart={needRestart} pending={restartFRR}")
                return needRestart

            if obj.config.op == 2:
                logging.info(f"Delete config scenario")
                # TODO if this is the last namespace, unregister?
                # response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
                # logging.info( f'Handle_Config: Unregister response:: {response}' )
                # state = State() # Reset state, works?
                restartFRR = updateParam( "admin_state", "disable" )
                # state.network_instances.pop( net_inst, None )
            else:
                data = get_data_as_json()
                enabled_daemons = []
                if 'admin_state' in data:
                    restartFRR = updateParam( "admin_state", data['admin_state'][12:] )
                if 'autonomous_system' in data:
                    restartFRR = updateParam( "autonomous_system", data['autonomous_system']['value'] )
                if 'router_id' in data:
                    restartFRR = updateParam( "router_id", data['router_id']['value'] )

                if 'bgp' in data:
                    bgp = data['bgp']
                    if 'admin_state' in bgp:
                      params[ "bgp" ] = bgp['admin_state'][12:]
                      if params[ "bgp" ] == "enable":
                        enabled_daemons.append( "bgpd" )

                    params[ "frr_bgpd_port" ] = bgp['port']['value'] if 'port' in bgp else "1179"
                    params[ "bgp_preference" ] = bgp['preference']['value']
                    params[ "route_import" ] = bgp['route_import'][13:]
                    params[ "assign_static_ipv6" ] = bgp['assign_static_ipv6']['value']
                    params[ "use_ipv6_nexthops_for_ipv4" ] = bgp['use_ipv6_nexthops_for_ipv4']['value']

                    params[ "bgp_link_local_range" ] = "192.0.0.0/24" # bgp['link_local_range']['value']
                    if 'use_ipv4_link_local_range' in bgp:
                        if bgp['use_ipv4_link_local_range']['value']:
                           params[ "bgp_link_local_range" ] = "169.254.0.0/24"

                    if 'anycast_nexthop' in bgp:
                       params[ "anycast_nexthop" ] = bgp['anycast_nexthop']['value']

                    if 'addpath' in bgp:
                       params[ "addpath" ] = bgp['addpath']

                if 'eigrp' in data:
                    eigrp = data['eigrp']
                    if 'admin_state' in eigrp:
                      params[ "eigrp" ] = eigrp['admin_state'][12:]
                      if params[ "eigrp" ] == "enable":
                         enabled_daemons.append( "eigrpd" )
                    if 'create_veth_multicast_bypass' in eigrp:
                        yes = eigrp['create_veth_multicast_bypass']['value']
                        params[ "eigrp_create_veth_pair" ] = "yes" if yes else "no"
                if 'openfabric' in data:
                   openfabric = data['openfabric']
                   params[ "openfabric" ] = openfabric['admin_state'][12:]
                   if params[ "openfabric" ] == "enable":
                      enabled_daemons.append( "fabricd" )
                   params[ "openfabric_name" ] = openfabric['name']['value']
                   params[ "openfabric_net" ] = openfabric['net']['value']
                   params[ "openfabric_domain_password" ] = openfabric['domain_password']['value']

                   # Support 'auto' net value: 49.area 0001.<6-byte MAC>.00
                   if params[ "openfabric_net" ] == "auto":
                       mac = GetSystemMAC()
                       params[ "openfabric_net" ] = f"49.0001.{ mac }.00"
                else:
                   params[ "openfabric" ] = "disable"

                # Could dynamically create CPM filter for IP proto 88
                if ni!={}:
                    if 'openfabric_name' in params:
                      _of = params['openfabric_name' ]
                      lines2 = ""
                      for _if in ni['openfabric_interfaces']:
                        # Add single indent space for each sub line
                        lines2 += f'\ninterface {_if}\n ip router openfabric {_of}'
                        if _if[0:2] == "lo":
                           lines2 += '\n openfabric passive'
                        lines2 += "\n!"
                      params[ "openfabric_interface_lines" ] = lines2
                      # TODO should move this logic to monitor thread, like bgp
                else:
                    ni = { "bgp_interfaces" : {}, "openfabric_interfaces" : {}, "config" : {} }

            if updateParam( "enabled_daemons"," ".join( enabled_daemons ) ):
               ni.update( { 'frr' : 'restart' } ) # something other than 'running' or 'stopped'
            if 'config' in ni:
                ni['config'].update( **params )
            else:
                ni['config'] = params

        # Tends to come first (always?) when full blob is configured
        elif obj.config.key.js_path == ".network_instance.interface.bgp_unnumbered":
          if obj.config.op != 2: # Skip deletes, TODO process them
            data = get_data_as_json()

            peer_as = None
            if 'peer_as_enum' in data:
              # 'external' or 'internal', remove 'PEER_AS_ENUM_'
              peer_as = data['peer_as_enum'][13:]
            elif 'peer_as_uint32' in data:
              peer_as = data['peer_as_uint32']['value']

            intf = obj.config.key.keys[1].replace("ethernet-","e").replace("/","-")

            if peer_as is not None:

              # If daemon is running, it gets updated upon 'commit'
              mapping = { intf : peer_as }
              if 'bgp_interfaces' in ni:
                ni['bgp_interfaces'].update( mapping )
              else:
                ni['bgp_interfaces'] = mapping

        elif obj.config.key.js_path == ".network_instance.interface.openfabric":
            logging.info("Process openfabric interface config")
            data = get_data_as_json()

            # Given the key, this should be present
            activate = data['activate']['value']
            intf = obj.config.key.keys[1].replace("ethernet-","e").replace("/","-")
            if 'config' in ni:
                cfg = ni['config']
                cfg['openfabric_interfaces'][ intf ] = True

                if 'frr' in ni and ni['frr']=='running':
                  if 'openfabric' in cfg and cfg['openfabric']=='enable':
                     name = cfg['openfabric_name']
                     no_ = "" if activate else "no "
                     cmds = [ f"{no_}ip router openfabric {name}" ]
                     if intf[0:2] == "lo" and activate:
                        cmds += "openfabric passive"
                     run_vtysh( ns=net_inst,context=f"interface {intf}",config=cmds )
            elif activate:
                ni['config'] = { "openfabric_interfaces" : { intf : True } }

        elif obj.config.key.js_path == base_path + ".group":
           group_name = obj.config.key.keys[1]
           update_conf( 'groups', group_name, get_data_as_json()['group'], True )
        elif obj.config.key.js_path == base_path + ".neighbor":
           neighbor_ip = obj.config.key.keys[1]
           update_conf( 'neighbors', neighbor_ip, get_data_as_json()['neighbor'], True )
        else:
            logging.warning( f"Ignoring: {obj.config.key.js_path}" )

        logging.info( f"Updated config for {net_inst}: {ni}" )
        state.network_instances[ net_inst ] = ni
        return net_inst
    else:
        logging.info(f"Unexpected notification : {obj}")

    # No network namespaces modified
    logging.info("No network instances modified...")
    return None

###########################
# Invokes gnmic client to update router configuration, via bash script
###########################
def script_update_frr(**kwargs):
    logging.info(f'Calling manage-frr script: params={kwargs}' )

    try:
       my_env = {**os.environ, **{ k:str(v) for (k,v) in kwargs.items() } }
       script_proc = subprocess.Popen(['scripts/manage-frr.sh'],
                                       # preexec_fn=demote(frr_uid, frr_gid),
                                       env=my_env, # shell=False
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       stdoutput, stderroutput = script_proc.communicate()
       logging.info(f'manage-frr result: {stdoutput} err={stderroutput}')
       # Add_Telemetry( '.network_instance{.name=="default"}.protocols.experimental_frr',
       #              { 'oper_state': 'up' } )
       Add_Telemetry( '.network_instance{.name=="default"}.protocols.experimental_frr',
                      { 'oper_state' : { 'value': 'up' }} )

    except Exception as e:
       logging.error(f'Exception caught in script_update_frr :: {e}')

# router statement: e.g. "router bgp <as>" or "router openfabric NAME"
def run_vtysh(ns,context='',show=[],config=[]):
    logging.info(f'Calling vtysh: ns={ns} context={context} show={show} config={config}' )
    try:
       args = ['/usr/bin/sudo', '/usr/bin/vtysh',
               '--vty_socket', f'/var/run/frr/srbase-{ns}/']
       if config!=[]:
          args += [ '-c', 'configure terminal', '-c', context ]
       args += sum( [ [ "-c", x ] for x in config ], [] )
       args += sum( [ [ "-c", x ] for x in show   ], [] )
       vtysh_proc = subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
       stdoutput, stderroutput = vtysh_proc.communicate()
       logging.info(f'vtysh result: {stdoutput} err={stderroutput}')
       return stdoutput
    except Exception as e:
       logging.error(f'Exception caught in run_vtysh :: {e}')

class State(object):
    def __init__(self):
        self.network_instances = {}   # Indexed by name
        # TODO more properties

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

def UpdateDaemons( state, modified_netinstances ):
    for n in modified_netinstances:
       ni = state.network_instances[ n ]
       # Shouldn't run more than one monitoringthread
       if 'config' in ni:
         interfaces = ni['bgp_interfaces'] if 'bgp_interfaces' in ni else {}
         if 'monitor_thread' not in ni:
            ni['monitor_thread'] = MonitoringThread( state, n, interfaces )
            ni['monitor_thread'].start()
         else:
            logging.info( f"MonitorThread already running, sending updated(?) list: {interfaces}" )
            ni['monitor_thread'].CheckForUpdatedInterfaces()
       else:
           logging.warning( "Incomplete config, not starting MonitoringThread" )

##################################################################################################
## This is the main proc where all processing for FRR agent starts.
## Agent registration, notification registration, Subscrition to notifications.
## Waits on the subscribed Notifications and once any config is received, handles that config
## If there are critical errors, unregisters the agent gracefully.
##################################################################################################
def Run():
    sub_stub = sdk_service_pb2_grpc.SdkNotificationServiceStub(channel)

    # optional agent_liveliness=<seconds> to have system kill unresponsive agents
    response = stub.AgentRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
    logging.info(f"Registration response : {response.status}")

    request=sdk_service_pb2.NotificationRegisterRequest(op=sdk_service_pb2.NotificationRegisterRequest.Create)
    create_subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    stream_id = create_subscription_response.stream_id
    logging.info(f"Create subscription response received. stream_id : {stream_id}")

    Subscribe_Notifications(stream_id)

    stream_request = sdk_service_pb2.NotificationStreamRequest(stream_id=stream_id)
    stream_response = sub_stub.NotificationStream(stream_request, metadata=metadata)

    state = State()
    count = 1
    modified = {} # Dict of modified network instances, no duplicates
    try:
        for r in stream_response:
            logging.info(f"Count :: {count}  NOTIFICATION:: \n{r.notification}")
            count += 1
            for obj in r.notification:
                if obj.HasField('config') and obj.config.key.js_path == ".commit.end":
                    logging.info(f'Processing commit.end, updating daemons...{modified}')
                    UpdateDaemons( state, modified )
                    modified = {} # Restart dict
                else:
                    netns = Handle_Notification(obj, state)
                    logging.info(f'Updated state after {netns}: {state}')
                    if netns in state.network_instances: # filter mgmt and other irrelevant ones
                        modified[ netns ] = True

    except grpc._channel._Rendezvous as err:
        logging.error(f'_Rendezvous error: {err}')

    except Exception as e:
        logging.error( "General exception in Run -> exitting" )
        logging.exception(e)
        #if file_name != None:
        #    Update_Result(file_name, action='delete')
    # for n in state.ipdbs:
    #   state.ipdbs[n].release()
    Exit_Gracefully(0,0)

############################################################
## Gracefully handle SIGTERM signal
## When called, will unregister Agent and gracefully exit
############################################################
def Exit_Gracefully(signum, frame):
    logging.info("Caught signal :: {}\n will unregister frr_agent".format(signum))
    try:
        response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
        logging.error('try: Unregister response:: {}'.format(response))
    except grpc._channel._Rendezvous as err:
        logging.error('GOING TO EXIT NOW: {}'.format(err))
    finally:
        sys.exit(signum)

##################################################################################################
## Main from where the Agent starts
## Log file is written to: /var/log/srlinux/stdout/<dutName>_fibagent.log
## Signals handled for graceful exit: SIGTERM
##################################################################################################
if __name__ == '__main__':
    # hostname = socket.gethostname()
    stdout_dir = '/var/log/srlinux/stdout' # PyTEnv.SRL_STDOUT_DIR
    signal.signal(signal.SIGTERM, Exit_Gracefully)
    if not os.path.exists(stdout_dir):
        os.makedirs(stdout_dir, exist_ok=True)
    log_filename = f'{stdout_dir}/{agent_name}.log'
    logging.basicConfig(
      handlers=[RotatingFileHandler(log_filename, maxBytes=3000000,backupCount=5)],
      format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
      datefmt='%H:%M:%S', level=logging.INFO)
    logging.info("START TIME :: {}".format(datetime.datetime.now()))
    Run()
