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

#
# Calculate pair of /31 IPs for given interface (e.g. e1-1 => peerlinks[0])
#
def GetLinkLocalIPs( phys_intf, link_local_range ):
   peerlinks = list(ipaddress.ip_network(link_local_range).subnets(new_prefix=31))
   peer_link = peerlinks[ int(phys_intf.split('-')[1]) - 1 ]
   return list( map( str, peer_link.hosts() ) )

def ConfigurePeerIPMAC( intf, local_ip, peer_ip, mac, link_local_range, gnmi_stub ):
   logging.info( f"ConfigurePeerIPMAC on {intf}: ip={peer_ip} mac={mac} local_ip={local_ip}" )
   phys_sub = intf.split('.') # e.g. e1-1.0 => ethernet-1/1.0
   base_if = phys_sub[0].replace('-','/').replace('e',"ethernet-")

   # Tried using /31 around router ID, but interferes with loopback peering
   # subnet = ipaddress.ip_network(peer_ip+'/31',strict=False)
   # ips = list( map( str, subnet.hosts() ) )
   ips = GetLinkLocalIPs( phys_sub[0], link_local_range )

   # For IPv6, build a /127 based on mapped ipv4 of highest ID
   # (assuming leaves have higher IDs than spines)
   highest_id = max(local_ip,peer_ip)
   mapped_v4 = '::ffff:' + highest_id # Or 'regular' v6: '2001::ffff:'
   v6_subnet = ipaddress.ip_network( mapped_v4 + '/127', strict=False )
   v6_ips = list( map( str, v6_subnet.hosts() ) )
   _i = v6_ips.index( str(ipaddress.ip_address(mapped_v4)) )
   local_v6 = v6_ips[ _i if local_ip == highest_id else (1-_i) ]
   peer_v6  = v6_ips[ (1-_i) if local_ip == highest_id else _i ]
   logging.info( f"ConfigurePeerIPMAC v6={v6_ips} local={local_v6} peer={peer_v6}" )

   path = f'/interface[name={base_if}]/subinterface[index={phys_sub[1]}]'
   desc = f"auto-configured by SRL FRR agent peer={peer_ip}"
   config = {
     "admin-state" : "enable",
     "description" : desc,
     "ipv4" : {
        "address" : [
           { "ip-prefix" : ips[ 0 ] + "/31",
             "primary": '[null]'  # type 'empty'
           }
        ],
        "arp" : {
           "neighbor": [
             {
               "ipv4-address": ips[ 1 ],
               "link-layer-address": mac,
               "_annotate_link-layer-address": desc
             }
           ]
        }
     },
     "ipv6" : {
        "address" : [
           # Use ipv4 mapped address, /127 around highest of router IDs
           { "ip-prefix" : local_v6 + "/127",
             "primary": '[null]'  # type 'empty'
           }
        ]
     }
   }
   gNMI_Set( gnmi_stub, path, config )
   return ( ips[1], peer_v6 )

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

#
# Creates a next hop group using the SDK
# @param ip_nexthops: Optional list of next hop IPs (should be same version)
#
def SDK_AddNHG( network_instance, name, ip_nexthops=[] ):
    logging.info(f"SDK_AddNHG :: name={name} ip_nexthops={ip_nexthops}")
    nhg_stub = nexthop_group_service_pb2_grpc.SdkMgrNextHopGroupServiceStub(channel)
    nh_request = nexthop_group_service_pb2.NextHopGroupRequest()

    # IPv4
    nhg_info = nh_request.group_info.add()
    nhg_info.key.network_instance_name = network_instance
    nhg_info.key.name = name + '_sdk' # Must end with '_sdk'

    for ip in ip_nexthops:
      nh = nhg_info.data.next_hop.add()
      nh.resolve_to = nexthop_group_service_pb2.NextHop.DIRECT  # INDIRECT? LOCAL?
      nh.type = nexthop_group_service_pb2.NextHop.REGULAR
      nh.ip_nexthop.addr = ipaddress.ip_address(ip).packed

    logging.info(f"NextHopGroupAddOrUpdate :: {nh_request}")
    nhg_response = nhg_stub.NextHopGroupAddOrUpdate(request=nh_request,metadata=metadata)
    logging.info(f"NextHopGroupAddOrUpdate :: status={nhg_response.status} err={nhg_response.error_str}")
    return nhg_response.status != 0

def SDK_AddRoute(network_instance,nhg_name,ip_addr,prefix_len,preference):
    route_stub = route_service_pb2_grpc.SdkMgrRouteServiceStub(channel)
    route_request = route_service_pb2.RouteAddRequest()
    route_info = route_request.routes.add() # Could add multiple
    route_info.data.preference = preference

    # Could configure defaults for these in the agent Yang params
    # route_info.data.metric = ip['metric']

    route_info.key.net_inst_name = network_instance
    ip = ipaddress.ip_address(ip_addr)
    route_info.key.ip_prefix.ip_addr.addr = ip.packed
    route_info.key.ip_prefix.prefix_length = int(prefix_len)

    #
    # SDK allows to either specify a NHG name, or a list of nexthop IPs
    #
    route_info.data.nexthop_group_name = nhg_name + '_sdk' # Must end with '_sdk'
    # for _i in nexthop_ips:
    #    nexthop = route_info.nexthop.add()
    #    nh.resolve_to = route_service_pb2.NextHop.DIRECT  # INDIRECT?
    #    nh.type = route_service_pb2.NextHop.REGULAR
        # SRL does not allow link local address to be used as NH, use mapped ipv4
    #    nh.ip_nexthop.addr = ipaddress.ip_address(ipv6_nexthop).packed

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

def Add_Route(network_instance, netlink_msg, preference):
    # logging.info( f"Add_Route {network_instance} pref={preference} m={netlink_msg}" )
    prefix = netlink_msg['attrs'][1][1] # RTA_DST
    length = netlink_msg['dst_len']
    # metric = netlink_msg['attrs'][2][1] # RTA_priority -> metric ?
    version = "v6" if netlink_msg['family'] == 10 else "v4"

    def get_ipv6_nh(attrs):
        if attrs[0] == "RTA_VIA":
            return attrs[1]['addr']
        elif attrs[0] == "RTA_GATEWAY":
            return attrs[1]
        else:
            logging.error( f"Unable to find IPv6 nexthop: {attrs[0]}" )
            return None

    att4 = netlink_msg['attrs'][4]
    if att4[0] == "RTA_MULTIPATH":
      # for v in att4[1]:
         # via_v6 = get_ipv6_nh( v['attrs'][0] )
      #     oif = v['oif']
      #     logging.info( f"multipath[oif={oif}] Add_Route {prefix}/{length}" )
      #     SDK_AddRoute(network_instance,oif,prefix,length,preference)

      # For now, assume *all* interfaces are listed
      SDK_AddRoute(network_instance,version,prefix,length,preference)
    else:
      # via_v6 = get_ipv6_nh( att4 )
      oif = netlink_msg['attrs'][5][1] # RTA_OIF
      logging.info( f"Add_Route {prefix}/{length} oif={oif}" )
      SDK_AddRoute(network_instance,f"{version}_{oif}",prefix,length,preference)

def Del_Route(network_instance, netlink_msg):
    prefix = netlink_msg['attrs'][1][1] # RTA_DST
    length = netlink_msg['dst_len']
    logging.info( f"Del_Route {prefix}/{length}" )
    return SDK_DelRoute(network_instance,prefix,length)

#
# Registers an IPDB callback handler for route events in the given VRF instance
# optional initial set of interfaces to create placeholder NHGs for
#
def RegisterRouteHandler(net_inst,preference,interfaces):
  logging.info( f"RegisterRouteHandler({net_inst},preference={preference})" )
  ipdb = IPDB(nl=NetNS(f'srbase-{net_inst}'))

  # Create placeholders for NextHop groups
  SDK_AddNHG(net_inst,'v4') # "all" interfaces, ipv4
  SDK_AddNHG(net_inst,'v6') # "all" interfaces, ipv6
  for i in interfaces:
      logging.info( f"RegisterRouteHandler: Pre-creating NHGs for {i}" )
      SDK_AddNHG(net_inst,f"v4_{ipdb.interfaces[i]['index']}")
      SDK_AddNHG(net_inst,f"v6_{ipdb.interfaces[i]['index']}")

  # Register our callback to the IPDB
  def netlink_callback(ipdb, msg, action):
      # logging.info(f"IPDB callback msg={msg} action={action}")
      if action=="RTM_NEWROUTE" and msg['proto'] == 186: # BGP route
         logging.info( f"Routehandler {net_inst}: Add_Route {msg}" )
         Add_Route( net_inst, msg, preference )
      elif action=="RTM_DELROUTE" and msg['proto'] == 186: # BGP route
         logging.info( f"Routehandler {net_inst}: Del_Route {msg}" )
         Del_Route( net_inst, msg )
      else:
         logging.info( f"netlink_callback: Ignoring {action}" )

  ipdb.register_callback(netlink_callback)
  return ipdb


#
# Runs as a separate thread
#
from threading import Thread
class MonitoringThread(Thread):
   def __init__(self, state, net_inst, interfaces):
       Thread.__init__(self)
       self.state = state
       self.net_inst = net_inst
       self.interfaces = interfaces # dict of intf->as

       # Check that gNMI is connected now
       grpc.channel_ready_future(gnmi_channel).result(timeout=5)

   def run(self):

      # Create per-thread gNMI stub, using a global channel
      gnmi_stub = gNMIStub( gnmi_channel )

      logging.info( f"MonitoringThread: {self.net_inst} {self.interfaces}")

      params = self.state.network_instances[ self.net_inst ]
      ipdb_interfaces = self.state.ipdbs[self.net_inst].interfaces
      try:
        todo = list( self.interfaces.keys() )
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
                      peer_v4, peer_v6 = ConfigurePeerIPMAC( _i, localId, peerId, mac, params['config']['bgp_link_local_range'], gnmi_stub )
                      # ConfigureNextHopGroup( self.net_inst, _i, peerId, gnmi_stub )
                      intf_index = ipdb_interfaces[_i]['index'] # Matches 'oif' in netlink

                      # Update NHGs with ipv4/v6 addresses for peer
                      # SDK_AddNHG( self.net_inst, intf_index, peer_v4, peer_v6 )
                      params[ 'v4' ][ peer_v4 ] = True
                      params[ 'v6' ][ peer_v6 ] = True
                      SDK_AddNHG(self.net_inst,"v4",params[ 'v4' ])
                      SDK_AddNHG(self.net_inst,f"v4_{intf_index}",[peer_v4])
                      SDK_AddNHG(self.net_inst,"v6",params[ 'v6' ])
                      SDK_AddNHG(self.net_inst,f"v6_{intf_index}",[peer_v6])

                      todo.remove( _i )
                      logging.info( f"MonitoringThread done with {_i}, left={todo}" )

          time.sleep(10)
          logging.info( f"MonitoringThread wakes up left={todo}" )
      except Exception as e:
         logging.error(e)

      logging.info( f"MonitoringThread exit: {self.net_inst}" )

#
# Adds or removes NHG for given interface
# peer_as := internal | external | None (->remove)
def UpdateBGPInterface(ni,intf,peer_as):
    cfg = ni['config']
    net_inst = cfg['network_instance']
    if peer_as is not None:
       ni['bgp_interfaces'][ intf ] = peer_as
       cmd = [ f"neighbor {intf} interface remote-as {peer_as}",
               f"neighbor {intf} port {cfg['frr_bgpd_port']}" ]
    else:
       # TODO remove NHG
       ni['bgp_interfaces'].pop( intf, None )
       cmd = [ f"no neighbor {intf}" ]

    # If FRR daemons are running, update this interface
    if 'frr' in ni and ni['frr']=='running':
       if 'bgp' in cfg and cfg['bgp']=='enable':
          ctxt = f"router bgp {cfg['autonomous_system']}"
          run_vtysh( ns=net_inst, context=ctxt, config=cmd )

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

        ni = state.network_instances[ net_inst ] if net_inst in state.network_instances else {}
        if obj.config.key.js_path == ".network_instance.protocols.experimental_frr":
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
                    params[ "bgp_link_local_range" ] = bgp['link_local_range']['value']
                    params[ "bgp_preference" ] = bgp['preference']['value']

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
                if 'config' in ni:
                    cfg = ni['config']
                    if "bgpd" in enabled_daemons:
                      lines = ""
                      for name,peer_as in ni['bgp_interfaces'].items():
                        # Add single indent space at end
                        lines += f'neighbor {name} interface remote-as {peer_as}\n '
                        # Use configured BGP port, custom patch
                        lines += f'neighbor {name} port {params[ "frr_bgpd_port" ]}\n '

                      params[ "bgp_neighbor_lines" ] = lines

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
                    state.network_instances[ net_inst ] = { "bgp_interfaces" : {}, "openfabric_interfaces" : {}, "config" : {} }

            if updateParam( "enabled_daemons"," ".join( enabled_daemons ) ):
               state.network_instances[ net_inst ]['frr'] = 'restart' # something other than 'running' or 'stopped'
            state.network_instances[ net_inst ]['config'].update( **params )

        # Tends to come first (always?) when full blob is configured
        elif (obj.config.key.js_path == ".network_instance.interface"
          and obj.config.op != 2): # Skip deletes, TODO process them?
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

            # Make sure NHGs exists, update with IPs later
            if peer_as is not None and net_inst in state.ipdbs:
              logging.info( f"Pre-creating NHG for {intf}" )
              ipdb_interfaces = state.ipdbs[net_inst].interfaces
              intf_index = ipdb_interfaces[intf]['index']
              SDK_AddNHG(net_inst,f"v4_{intf_index}")
              SDK_AddNHG(net_inst,f"v6_{intf_index}")

            # lookup AS for this ns, check if enabled (i.e. daemon running)
            if 'bgp_interfaces' in ni:
                UpdateBGPInterface(ni,intf,peer_as)
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
            if 'config' in ni:
                cfg = ni['config']
                ni['openfabric_interfaces'][ intf ] = True

                if 'frr' in ni and ni['frr']=='running':
                  if 'openfabric' in cfg and cfg['openfabric']=='enable':
                     name = cfg['openfabric_name']
                     no_ = "" if activate else "no "
                     cmds = [ f"{no_}ip router openfabric {name}" ]
                     if intf[0:2] == "lo" and activate:
                        cmds += "openfabric passive"
                     run_vtysh( ns=net_inst,context=f"interface {intf}",config=cmds )
            elif activate:
                state.network_instances[ net_inst ].update( {
                    "config" : { "openfabric_interfaces" : { intf : True } },
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
        self.ipdbs = {}               # Indexed by name
        # TODO more properties

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

def UpdateDaemons( state, modified_netinstances ):
    for n in modified_netinstances:
       ni = state.network_instances[ n ]
       cfg = ni['config'] if 'config' in ni else {}
       # Register route handler before starting daemons / adding interfaces
       if 'bgp' in cfg and cfg['bgp']=='enable':
          if n not in state.ipdbs:
            logging.info( f"About to start route handler; interfaces={ni['bgp_interfaces']}")
            ni['v4'] = {} # Start list of IPv4 nexthops
            ni['v6'] = {}
            state.ipdbs[n] = RegisterRouteHandler(n,
                               int(cfg['bgp_preference']), ni['bgp_interfaces'] )

       # First, (re)start or stop FRR daemons
       if 'frr' not in ni or ni['frr'] not in ['running','stopped']:
          script_update_frr( **cfg )
          ni['frr'] = 'running' if cfg['admin_state']=='enable' else 'stopped'

       if 'bgp' in cfg and cfg['bgp']=='enable' and ni['bgp_interfaces']!={}:
          # TODO shouldn't run monitoringthread more than once per interface
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

    # Test: create dummy ECMP route pair
    SDK_AddNHG( "default", "dummy", [ "192.0.0.1", "192.0.0.3" ] )
    SDK_AddRoute( "default", "dummy", "66.66.66.66", 32, preference=99 )

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
        logging.info(f'_Rendezvous error: {err}')

    except Exception as e:
        logging.error(f'Exception caught :: {e}')
        #if file_name != None:
        #    Update_Result(file_name, action='delete')
    for n in state.ipdbs:
       state.ipdbs[n].release()
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
