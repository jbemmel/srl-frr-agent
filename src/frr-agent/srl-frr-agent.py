#!/usr/bin/env python
# coding=utf-8

import grpc
import datetime
import time
import sys
import logging
import socket
import os
import re
import ipaddress
import json
import signal
import queue
import traceback
import subprocess
import pwd

# sys.path.append('/usr/lib/python3.6/site-packages/sdk_protos')
import sdk_service_pb2
import sdk_service_pb2_grpc
import lldp_service_pb2
import config_service_pb2
import route_service_pb2
import route_service_pb2_grpc
import nexthop_group_service_pb2
import nexthop_group_service_pb2_grpc

import sdk_common_pb2

# To report state back, TODO
import telemetry_service_pb2
import telemetry_service_pb2_grpc

from pygnmi.client import gNMIclient

# pygnmi does not support multithreading, so we need to build it
from pygnmi.spec.gnmi_pb2_grpc import gNMIStub
from pygnmi.spec.gnmi_pb2 import SetRequest, Update, TypedValue
from pygnmi.path_generator import gnmi_path_generator

# Needs yum install python3-pyroute2 -y
from pyroute2 import IPDB
from pyroute2 import NetNS

from logging.handlers import RotatingFileHandler

############################################################
## Agent will start with this name
############################################################
agent_name='srl_frr_agent'

# Global IPDB
ipdb = None

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
    elif option == 'nexthop_group':
        entry = nexthop_group_service_pb2.NextHopGroupSubscriptionRequest()
        request = sdk_service_pb2.NotificationRegisterRequest(op=op, stream_id=stream_id, nhg=entry)

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

def ConfigurePeerIPMAC( intf, local_ip, peer_ip, mac, gnmi_stub ):
   logging.info( f"ConfigurePeerIPMAC on {intf}: ip={peer_ip} mac={mac} local_ip={local_ip}" )
   phys_sub = intf.split('.') # e.g. e1-1.0 => ethernet-1/1.0
   base_if = phys_sub[0].replace('-','/').replace('e',"ethernet-")
   subnet = ipaddress.ip_network(peer_ip+'/31',strict=False)
   ips = list( map( str, subnet.hosts() ) )

   # For IPv6, build a /127 based on mapped ipv4 of lowest ID
   lowest_id = min(local_ip,peer_ip)
   mapped_v4 = '::ffff:' + lowest_id # Or 'regular' v6: '2001::ffff:'
   v6_subnet = ipaddress.ip_network( mapped_v4 + '/127', strict=False )
   v6_ips = list( map( str, v6_subnet.hosts() ) )
   _i = v6_ips.index( str(ipaddress.ip_address(mapped_v4)) )
   local_v6 = v6_ips[ _i if local_ip == lowest_id else (1-_i) ]
   peer_v6  = v6_ips[ (1-_i) if local_ip == lowest_id else _i ]
   logging.info( f"ConfigurePeerIPMAC v6={v6_ips} local={local_v6} peer={peer_v6}" )

   path = f'/interface[name={base_if}]/subinterface[index={phys_sub[1]}]'
   config = {
     "admin-state" : "enable",
     "ipv4" : {
        "address" : [
           { "ip-prefix" : ips[ 0 if peer_ip == ips[1] else 1 ] + "/31",
             "primary": '[null]'  # type 'empty'
           }
        ],
        "arp" : {
           "neighbor": [
             {
               "ipv4-address": peer_ip,
               "link-layer-address": mac,
               "_annotate_link-layer-address": "managed by SRL FRR agent"
             }
           ]
        }
     },
     "ipv6" : {
        "address" : [
           # Use ipv4 mapped address, /127 around lowest of router IDs
           { "ip-prefix" : local_v6 + "/127",
             "primary": '[null]'  # type 'empty'
           }
        ]
     }
   }
   gNMI_Set( gnmi_stub, path, config )
   return peer_v6

# Works, but no longer used
def ConfigureNextHopGroup( net_inst, intf, peer_ip, gnmi_stub ):
    path = f'/network-instance[name={net_inst}]/next-hop-groups'
    config = {
     "group": [
      {
        "name": intf, # Full interface.sub
        "nexthop": [
          {
            "index": 0,
            "ip-address": peer_ip,
            "_annotate_ip-address" : "managed by SRL FRR agent",
            "admin-state": "enable"
          }
        ]
      }
     ]
    }
    return gNMI_Set( gnmi_stub, path, config )

def gNMI_Set( gnmi_stub, path, data ):
   #with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
   #                       username="admin",password="admin",
   #                       insecure=True, debug=True) as gnmic:
   #  logging.info( f"Sending gNMI SET: {path} {config} {gnmic}" )
   update_msg = []
   u_path = gnmi_path_generator( path )
   u_val = bytes( json.dumps(data), 'utf-8' )
   update_msg.append(Update(path=u_path, val=TypedValue(json_ietf_val=u_val)))
   update_request = SetRequest( update=update_msg )
   try:
         # Leaving out 'metadata' does return an error, so the call goes through
         # It just doesn't show up in CLI (cached), logout+login fixes it
         res = gnmi_stub.Set( update_request, metadata=gnmi_options )
         logging.info( f"After gnmi.Set {path}: {res}" )
         return res
   except grpc._channel._InactiveRpcError as err:
         logging.error(err)
         # May happen during system startup, retry once
         if err.code() == grpc.StatusCode.FAILED_PRECONDITION:
             logging.info("Exception during startup? Retry in 5s...")
             time.sleep( 5 )
             res = gnmi_stub.Set( update_request, metadata=gnmi_options )
             logging.info(f"OK, success? {res}")
             return res
         raise err

def SDK_AddNHG(network_instance,ip_nexthop,ipv6_link_local,ipv6_nexthop):
    nhg_stub = nexthop_group_service_pb2_grpc.SdkMgrNextHopGroupServiceStub(channel)
    nh_request = nexthop_group_service_pb2.NextHopGroupRequest()

    # IPv4
    nhg_info = nh_request.group_info.add()
    nhg_info.key.network_instance_name = network_instance
    nhg_info.key.name = ipv6_link_local + '_v4_frr_sdk' # Must end with '_sdk'
    nh = nhg_info.data.next_hop.add()
    nh.resolve_to = nexthop_group_service_pb2.NextHop.INDIRECT  # DIRECT? LOCAL?
    nh.type = nexthop_group_service_pb2.NextHop.REGULAR
    nh.ip_nexthop.addr = ipaddress.ip_address(ip_nexthop).packed

    # IPv6
    nhg_info = nh_request.group_info.add()
    nhg_info.key.network_instance_name = network_instance
    nhg_info.key.name = ipv6_link_local + '_v6_frr_sdk' # Must end with '_sdk'
    nh = nhg_info.data.next_hop.add()
    nh.resolve_to = nexthop_group_service_pb2.NextHop.INDIRECT  # DIRECT
    nh.type = nexthop_group_service_pb2.NextHop.REGULAR

    # SRL does not allow link local address to be used as NH, use mapped ipv4
    nh.ip_nexthop.addr = ipaddress.ip_address(ipv6_nexthop).packed
    # nh.ip_nexthop.addr = ipaddress.ip_address(ipv6_link_local).packed # FAILS

    logging.info(f"NextHopGroupAddOrUpdate :: {nh_request}")
    nhg_response = nhg_stub.NextHopGroupAddOrUpdate(request=nh_request,metadata=metadata)
    logging.info(f"NextHopGroupAddOrUpdate :: {nhg_response.status} {nhg_response.error_str}")
    return nhg_response.status != 0

def SDK_AddRoute(network_instance,ip_addr,prefix_len,via_v6,preference):
    route_stub = route_service_pb2_grpc.SdkMgrRouteServiceStub(channel)
    route_request = route_service_pb2.RouteAddRequest()
    route_info = route_request.routes.add()
    route_info.data.preference = preference

    # Could configure defaults for these in the agent Yang params
    # route_info.data.metric = ip['metric']

    route_info.key.net_inst_name = network_instance
    ip = ipaddress.ip_address(ip_addr)
    route_info.key.ip_prefix.ip_addr.addr = ip.packed
    route_info.key.ip_prefix.prefix_length = int(prefix_len)
    route_info.data.nexthop_group_name = via_v6 + f'_v{ip.version}_frr_sdk' # Must end with '_sdk'

    logging.info(f"RouteAddOrUpdate REQUEST :: {route_request}")
    route_response = route_stub.RouteAddOrUpdate(request=route_request,metadata=metadata)
    logging.info(f"RouteAddOrUpdate RESPONSE:: {route_response.status} {route_response.error_str}")
    return route_response.status != 0

def SDK_DelRoute(network_instance,ip_addr,prefix_len):
    route_stub = route_service_pb2_grpc.SdkMgrRouteServiceStub(channel)
    route_request = route_service_pb2.RouteDeleteRequest()
    route_info = route_request.routes.add()
    route_info.net_inst_name = network_instance
    ip = ipaddress.ip_address(ip_addr)
    route_info.ip_prefix.ip_addr.addr = ip.packed
    route_info.ip_prefix.prefix_length = int(prefix_len)
    # route_info.data.nexthop_group_name = no need to set this

    logging.info(f"RouteDeleteRequest REQUEST :: {route_request}")
    route_response = route_stub.RouteDelete(request=route_request,metadata=metadata)
    logging.info(f"RouteDeleteRequest RESPONSE:: {route_response.status} {route_response.error_str}")
    return route_response.status != 0

def Add_Route(network_instance, netlink_msg, peer_2_pref):
    prefix = netlink_msg['attrs'][1][1] # RTA_DST
    length = netlink_msg['dst_len']
    # metric = netlink_msg['attrs'][2][1] # RTA_priority -> metric ?
    att4 = netlink_msg['attrs'][4]
    if att4[0] == "RTA_VIA":
       via_v6 = att4[1]['addr'] # RTA_VIA, ipv4
    else:
       via_v6 = att4[1] # RTA_GATEWAY, ipv6
    preference = peer_2_pref[ via_v6 ]
    logging.info( f"Add_Route {prefix}/{length} pref={preference}" )
    return SDK_AddRoute(network_instance,prefix,length,via_v6,preference)

def Del_Route(network_instance, netlink_msg):
    prefix = netlink_msg['attrs'][1][1] # RTA_DST
    length = netlink_msg['dst_len']
    logging.info( f"Del_Route {prefix}/{length}" )
    return SDK_DelRoute(network_instance,prefix,length)

#
# Runs as a separate thread
#
from threading import Thread
class MonitoringThread(Thread):
   def __init__(self, state, net_inst, interfaces):
       Thread.__init__(self)
       self.state = state
       self.net_inst = net_inst
       self.interfaces = interfaces

       # Check that gNMI is connected now
       grpc.channel_ready_future(gnmi_channel).result(timeout=5)

   def run(self):

      # Create per-thread gNMI stub, using a global channel
      gnmi_stub = gNMIStub( gnmi_channel )

      logging.info( f"MonitoringThread: {self.net_inst} {self.interfaces}")

      # Need to register callback before connecting FRR, but postpone processing
      # of route add/del events by queuing them
      work_queue = queue.Queue()
      try:
         global ipdb
         ipdb = IPDB(nl=NetNS(f'srbase-{self.net_inst}'))
         # Register our callback to the IPDB
         def netlink_callback(ipdb, msg, action):
             logging.info(f"IPDB callback msg={msg} action={action}")
             if action=="RTM_NEWROUTE" and msg['proto'] == 186: # BGP route
                logging.info( "Queue: Add_Route" )
                work_queue.put( (action,msg) ) # Could enqueue method ptr here
             elif action=="RTM_DELROUTE" and msg['proto'] == 186: # BGP route
                logging.info( "Queue: Del_Route" )
                work_queue.put( (action,msg) )
             else:
                logging.info( f"Ignoring: {action}" )

         ipdb.register_callback(netlink_callback)
      except Exception as ex:
         logging.error( f"Exception while starting IPDB callback: {ex}" )

      # Map of peer ipv6 link_local -> route preference (ibgp or ebgp)
      peer_2_pref = {}
      params = self.state.network_instances[ self.net_inst ]
      ibgp_pref = int( params[ 'ibgp_preference' ] )
      ebgp_pref = int( params[ 'ebgp_preference' ] )
      try:
        todo = self.interfaces
        while todo != []:
          for _i in todo:
            _get_peer = f'show bgp neighbors {_i} json'
            json_data = run_vtysh( ns=self.net_inst, show=[_get_peer] )
            if json_data:
                _js = json.loads( json_data )
                if _i in _js:
                   i = _js[ _i ]
                   neighbor = i['bgpNeighborAddr'] #ipv6 link-local
                   localId = i['localRouterId']
                   peerId = i['remoteRouterId']
                   if neighbor!="none" and peerId!="0.0.0.0":
                      # dont have the MAC address, but can derive it from ipv6 link local
                      mac = ipv6_2_mac(neighbor) # XXX not ideal, may differ
                      logging.info( f"{neighbor} MAC={mac}" )
                      logging.info( f"localAs={i['localAs']} remoteAs={i['remoteAs']}" )
                      logging.info( f"id={peerId} name={i['hostname'] if 'hostname' in i else '?'}" )
                      peer_v6 = ConfigurePeerIPMAC( _i, localId, peerId, mac, gnmi_stub )
                      # ConfigureNextHopGroup( self.net_inst, _i, peerId, gnmi_stub )
                      SDK_AddNHG( self.net_inst, peerId, neighbor, peer_v6 )
                      peer_2_pref[ neighbor ] = ibgp_pref if i['localAs'] == i['remoteAs'] else ebgp_pref
                      todo.remove( _i )
                      logging.info( f"MonitoringThread done with {_i}, left={todo}" )

          time.sleep(10)
          logging.info( f"MonitoringThread wakes up left={todo}" )
      except Exception as e:
         logging.error(e)

      # After setting up the BGP peering, process route events
      logging.info( f"MonitoringThread {self.net_inst} starts processing events...queue={work_queue.qsize()}" )
      # self.daemon = True
      while True:
         try:
            action, msg = work_queue.get()
            logging.info( f"MonitoringThread {self.net_inst} got event: {action}" )
            if action == "RTM_NEWROUTE":
               Add_Route( self.net_inst, msg, peer_2_pref )
            elif action == "RTM_DELROUTE":
               Del_Route( self.net_inst, msg )
            work_queue.task_done()
         except Exception as ex:
           traceback_str = ''.join(traceback.format_tb(ex.__traceback__))
           logging.error( f"Exception while processing {action}: {ex} {traceback_str}" )

      logging.info( f"MonitoringThread exit: {self.net_inst}" )


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
        ni = state.network_instances[ net_inst ] if net_inst in state.network_instances else {}
        if obj.config.key.js_path == ".network_instance.protocols.experimental_frr":
            logging.info(f"Got config for agent, now will handle it :: \n{obj.config}\
                            Operation :: {obj.config.op}\nData :: {obj.config.data.json}")
            # Could define NETNS here: "NETNS" : f'srbase-{net_inst}'
            params = { "network_instance" : net_inst }
            restartFRR = False

            def updateParam(p,v):
                params[ p ] = v
                needRestart = True if (p not in ni or ni[p]!=v) else restartFRR
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
                json_acceptable_string = obj.config.data.json.replace("'", "\"")
                data = json.loads(json_acceptable_string)
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
                    if 'preference' in bgp:
                      # Keep these as strings, to pass to script
                      params[ "ebgp_preference" ] = bgp['preference']['ebgp']['value']
                      params[ "ibgp_preference" ] = bgp['preference']['ibgp']['value']
                    else:
                      params[ "ebgp_preference" ] = params[ "ibgp_preference" ] = "170"
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
                if ni != {}:
                    if "bgpd" in enabled_daemons:
                      lines = ""
                      routemap = ""
                      entry = 10
                      for name,peer_as in ni['bgp_interfaces'].items():
                        # Add single indent space at end
                        lines += f'neighbor {name} interface remote-as {peer_as}\n '
                        # Use configured BGP port, custom patch
                        lines += f'neighbor {name} port {params[ "frr_bgpd_port" ]}\n '

                        # Add a route-map entry to drop local routes on this interface
                        routemap += f'route-map drop_interface_routes deny {entry}\n'
                        routemap += f' match interface {name}\n'
                        entry += 10

                      routemap += f'route-map drop_interface_routes permit {entry}'
                      params[ "bgp_neighbor_lines" ] = lines
                      params[ "bgp_routemap_lines" ] = routemap

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
                else:
                    state.network_instances[ net_inst ] = { "bgp_interfaces" : {}, "openfabric_interfaces" : {} }

            if updateParam( "enabled_daemons"," ".join( enabled_daemons ) ):
                params['frr'] = 'restart' # something other than 'running' or 'stopped'
            state.network_instances[ net_inst ].update( **params )

        # Tends to come first (always?) when full blob is configured
        elif obj.config.key.js_path == ".network_instance.interface":
            json_acceptable_string = obj.config.data.json.replace("'", "\"")
            data = json.loads(json_acceptable_string)

            # 'interface' only present when bgp-unnumbered param is set
            peer_as = None
            if 'interface' in data:
               _i = data['interface']
               if 'bgp_unnumbered_peer_as_enum' in _i:
                  # 'external' or 'internal', remove 'BGP_UNNUMBERED_PEER_AS_ENUM_'
                  peer_as = _i['bgp_unnumbered_peer_as_enum'][28:]
               elif 'bgp_unnumbered_peer_as_uint32' in _i:
                  peer_as = _i['bgp_unnumbered_peer_as_uint32']['value']

               # Can show up here, but also below in .openfabric (duplicate?)
               if 'openfabric' in _i:
                  logging.info(f"TODO: process openfabric interface config : {_i['openfabric']}")

            intf = obj.config.key.keys[1].replace("ethernet-","e").replace("/","-")
            # lookup AS for this ns, check if enabled (i.e. daemon running)
            if ni != {}:
                ni = state.network_instances[ net_inst ]
                if peer_as is not None:
                   ni['bgp_interfaces'][ intf ] = peer_as
                   cmd = f"neighbor {intf} interface remote-as {peer_as}"
                else:
                   ni['bgp_interfaces'].pop( intf, None )
                   cmd = f"no neighbor {intf}"

                # If FRR daemons are running, update this interface
                if 'frr' in ni and ni['frr']=='running':
                   if 'bgp' in ni and ni['bgp']=='enable':
                      ctxt = f"router bgp {ni['autonomous_system']}"
                      run_vtysh( ns=net_inst, context=ctxt, config=[cmd] )

            elif peer_as is not None:
                state.network_instances[ net_inst ] = {
                  "bgp_interfaces" : { intf : peer_as }
                }

        elif obj.config.key.js_path == ".network_instance.interface.openfabric":
            logging.info("Process openfabric interface config")
            json_acceptable_string = obj.config.data.json.replace("'", "\"")
            data = json.loads(json_acceptable_string)

            # Given the key, this should be present
            activate = data['activate']['value']
            intf = obj.config.key.keys[1].replace("ethernet-","e").replace("/","-")
            if net_inst in state.network_instances:
                ni = state.network_instances[ net_inst ]
                ni['openfabric_interfaces'][ intf ] = True

                if 'frr' in ni and ni['frr']=='running':
                  if 'openfabric' in ni and ni['openfabric']=='enable':
                     name = ni['openfabric_name']
                     no_ = "" if activate else "no "
                     cmds = [ f"{no_}ip router openfabric {name}" ]
                     if intf[0:2] == "lo" and activate:
                        cmds += "openfabric passive"
                     run_vtysh( ns=net_inst,context=f"interface {intf}",config=cmds )
            elif activate:
                state.network_instances[ net_inst ].update( {
                    "openfabric_interfaces" : { intf : True },
                } )

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
       my_env = {**os.environ, **kwargs}
       script_proc = subprocess.Popen(['scripts/manage-frr.sh'],
                                       # preexec_fn=demote(frr_uid, frr_gid),
                                       env=my_env, # shell=False
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       stdoutput, stderroutput = script_proc.communicate()
       logging.info(f'manage-frr result: {stdoutput} err={stderroutput}')
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
        self.admin_state = None       # May not be set in config
        self.network_instances = {}   # Indexed by name
        # TODO more properties

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

def UpdateDaemons( state, modified_netinstances ):
    for n in modified_netinstances:
       ni = state.network_instances[ n ]

       # First, (re)start or stop FRR daemons
       if 'frr' not in ni or ni['frr'] not in ['running','stopped']:
          params = { **ni, "bgp_interfaces" : "" } # Override dict
          script_update_frr( **params )
          ni['frr'] = 'running' if ni['admin_state']=='enable' else 'stopped'

       if 'bgp' in ni and ni['bgp']=='enable' and ni['bgp_interfaces']!=[]:

           # TODO run any update commands when interfaces are added/removed
           # run_vtysh( ns=net_inst,
           #  context=f"router bgp {ni['autonomous_system']}",
           #  config=[cmd] )
           MonitoringThread( state, n, ni['bgp_interfaces'] ).start()

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

    # TestAddLinkLocal_Nexthop_Group('link_local','169.254.0.1')
    # TestAddLinkLocal_Nexthop_Group('regular','69.254.0.1')

    request=sdk_service_pb2.NotificationRegisterRequest(op=sdk_service_pb2.NotificationRegisterRequest.Create)
    create_subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    stream_id = create_subscription_response.stream_id
    logging.info(f"Create subscription response received. stream_id : {stream_id}")

    Subscribe_Notifications(stream_id)

    stream_request = sdk_service_pb2.NotificationStreamRequest(stream_id=stream_id)
    stream_response = sub_stub.NotificationStream(stream_request, metadata=metadata)

    state = State()
    count = 1
    modified = [] # List of modified network instances
    try:
        for r in stream_response:
            logging.info(f"Count :: {count}  NOTIFICATION:: \n{r.notification}")
            count += 1
            for obj in r.notification:
                if obj.HasField('config') and obj.config.key.js_path == ".commit.end":
                    logging.info(f'Processing commit.end, updating daemons...{modified}')
                    UpdateDaemons( state, modified )
                    modified = [] # Restart list
                else:
                    netns = Handle_Notification(obj, state)
                    logging.info(f'Updated state after {netns}: {state}')
                    if netns is not None:
                        modified.append( netns )

    except grpc._channel._Rendezvous as err:
        logging.info(f'_Rendezvous error: {err}')

    except Exception as e:
        logging.error(f'Exception caught :: {e}')
        #if file_name != None:
        #    Update_Result(file_name, action='delete')

    Exit_Gracefully(0,0)

############################################################
## Gracefully handle SIGTERM signal
## When called, will unregister Agent and gracefully exit
############################################################
def Exit_Gracefully(signum, frame):
    logging.info("Caught signal :: {}\n will unregister frr_agent".format(signum))
    global ipdb
    if ipdb is not None:
        ipdb.release()
        ipdb = None
    try:
        response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
        logging.error('try: Unregister response:: {}'.format(response))
        sys.exit()
    except grpc._channel._Rendezvous as err:
        logging.info('GOING TO EXIT NOW: {}'.format(err))
        sys.exit()

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
