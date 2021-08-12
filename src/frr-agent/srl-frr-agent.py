#!/usr/bin/env python
# coding=utf-8

#
# TODO: Add CLI command to open vtysh: /usr/bin/sudo /usr/bin/vtysh --vty_socket /var/run/frr/srbase-default/
# or simply alias:
# environment alias vtysh "bash /usr/bin/sudo /usr/bin/vtysh --vty_socket /var/run/frr/srbase-default/"
#

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
import traceback
import subprocess
# from concurrent.futures import ThreadPoolExecutor
import pwd

# sys.path.append('/usr/lib/python3.6/site-packages/sdk_protos')
import sdk_service_pb2
import sdk_service_pb2_grpc
import lldp_service_pb2
import config_service_pb2
import route_service_pb2
import nexthop_group_service_pb2
import sdk_common_pb2

# To report state back
import telemetry_service_pb2
import telemetry_service_pb2_grpc

from pygnmi.client import gNMIclient

# pygnmi does not support multithreading, so we need to build it
from pygnmi.spec.gnmi_pb2_grpc import gNMIStub
from pygnmi.spec.gnmi_pb2 import SetRequest, Update, TypedValue
from pygnmi.path_generator import gnmi_path_generator

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

#
# Uses gNMI to get /platform/chassis/mac-address
#
def GetSystemMAC():
   path = '/platform/chassis/mac-address'
   with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                            username="admin",password="admin",
                            insecure=True, debug=False) as gnmi:
      result = gnmi.get( encoding='json_ietf', path=[path] )
      for e in result['notification']:
         if 'update' in e:
           logging.info(f"GOT Update :: {e['update']}")
           for u in e['update']:
               for j in u['val']['entry']:
                  return j # XX probably incorrect

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

def ConfigurePeerIPMAC( intf, peer_ip, mac, gnmi_stub ):
   logging.info( f"ConfigurePeerIPMAC on {intf}: ip={peer_ip} mac={mac}" )
   phys_sub = intf.split('.') # e.g. e1-1.0 => ethernet-1/1.0
   base_if = phys_sub[0].replace('-','/').replace('e',"ethernet-")
   subnet = ipaddress.ip_network(peer_ip+'/31',strict=False)
   ips = list( map( str, subnet.hosts() ) )

   path = f'/interface[name={base_if}]/subinterface[index={phys_sub[1]}]'
   config = {
     "admin-state" : "enable",
     "ipv4" : {
        "address" : [
           { "ip-prefix" : ips[ 0 if peer_ip == ips[1] else 1 ] + "/31",
             "primary": '[null]'  # type 'empty'
           },
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
     }
   }
   return gNMI_Set( gnmi_stub, path, config )

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
# Runs as a separate thread
#
from threading import Thread
class MonitoringThread(Thread):
   def __init__(self, net_inst, interfaces):
       Thread.__init__(self)
       self.net_inst = net_inst
       self.interfaces = interfaces

       # Check that gNMI is connected now
       grpc.channel_ready_future(gnmi_channel).result(timeout=5)

   def run(self):

      # Create per-thread gNMI stub, using a global channel
      gnmi_stub = gNMIStub( gnmi_channel )

      logging.info( f"MonitoringThread: {self.net_inst} {self.interfaces}")
      try:
        while self.interfaces != []:
         for _i in self.interfaces:
            _get_peer = f'show bgp neighbors {_i} json'
            json_data = run_vtysh( ns=self.net_inst, show=[_get_peer] )
            if json_data:
                _js = json.loads( json_data )
                if _i in _js:
                   i = _js[ _i ]
                   neighbor = i['bgpNeighborAddr'] #ipv6 link-local
                   peerId = i['remoteRouterId']
                   if neighbor!="none" and peerId!="0.0.0.0":
                      # dont have the MAC address, but can derive it from ipv6 link local
                      mac = ipv6_2_mac(neighbor) # XXX not ideal, may differ
                      logging.info( f"{neighbor} MAC={mac}" )
                      logging.info( f"localAs={i['localAs']} remoteAs={i['remoteAs']}" )
                      logging.info( f"id={peerId} name={i['hostname'] if 'hostname' in i else '?'}" )
                      ConfigurePeerIPMAC( _i, peerId, mac, gnmi_stub )
                      ConfigureNextHopGroup( self.net_inst, _i, peerId, gnmi_stub )
                      self.interfaces.remove( _i )

         time.sleep(10)
      except Exception as e:
         logging.error(e)
      logging.info( f"MonitoringThread exit: {self.net_inst}" )


##################################################################
## Proc to process the config Notifications received by auto_config_agent
## At present processing config from js_path containing agent_name
##################################################################
def Handle_Notification(obj, state):
    if obj.HasField('config') and obj.config.key.js_path != ".commit.end":
        logging.info(f"GOT CONFIG :: {obj.config.key.js_path}")

        # Tested on main thread
        # ConfigurePeerIPMAC( "e1-1.0", "1.2.3.4", "00:11:22:33:44:55" )

        net_inst = obj.config.key.keys[0] # e.g. "default"
        if obj.config.key.js_path == ".network_instance.protocols.experimental_frr":
            logging.info(f"Got config for agent, now will handle it :: \n{obj.config}\
                            Operation :: {obj.config.op}\nData :: {obj.config.data.json}")
            params = { "network_instance" : net_inst, "NETNS" : f'srbase-{net_inst}' }
            interfaces = []
            if obj.config.op == 2:
                logging.info(f"Delete config scenario")
                # TODO if this is the last namespace, unregister?
                # response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
                # logging.info( f'Handle_Config: Unregister response:: {response}' )
                # state = State() # Reset state, works?
                params[ "admin_state" ] = "disable" # Only stop service for this namespace
                state.network_instances.pop( net_inst, None )
            else:
                json_acceptable_string = obj.config.data.json.replace("'", "\"")
                data = json.loads(json_acceptable_string)
                enabled_daemons = []
                if 'admin_state' in data:
                    params[ "admin_state" ] = data['admin_state'][12:]
                if 'autonomous_system' in data:
                    params[ "autonomous_system" ] = data['autonomous_system']['value']
                if 'router_id' in data:
                    params[ "router_id" ] = data['router_id']['value']
                if 'bgp' in data:
                    params[ "bgp" ] = data['bgp'][4:]
                    if params[ "bgp" ] == "enable":
                       enabled_daemons.append( "bgpd" )
                if 'eigrp' in data:
                    params[ "eigrp" ] = data['eigrp'][6:]
                    if params[ "eigrp" ] == "enable":
                       # Multicast only works in 'srbase' namespace
                       params[ "NETNS" ] = "srbase"
                       enabled_daemons.append( "eigrpd" )
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
                       params[ "openfabric_net" ] = f"49.0001.{ mac.replace(':','.') }.00"

                # Could dynamically create CPM filter for IP proto 88

                if net_inst in state.network_instances:
                    ni = state.network_instances[ net_inst ]
                    lines = ""
                    for name,peer_as in ni['interfaces'].items():
                        # Add single indent space at end
                        lines += f'neighbor {name} interface remote-as {peer_as}\n '
                        interfaces.append( name )
                    params[ "bgp_neighbor_lines"] = lines

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

                    ni.update( params )
                else:
                    state.network_instances[ net_inst ] = { **params, "interfaces" : {}, "openfabric_interfaces" : {} }

            params[ "enabled_daemons" ] = " ".join( enabled_daemons )
            script_update_frr(**params)
            if interfaces!=[] and params[ "bgp" ] == "enable":
               MonitoringThread( net_inst, interfaces ).start()
            else:
               logging.info( "interfaces==[] or FRR BGP disabled, not starting monitor thread yet" )
            return True

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
            if net_inst in state.network_instances:
                ni = state.network_instances[ net_inst ]
                if peer_as is not None:
                   ni['interfaces'][ intf ] = peer_as
                   cmd = f"neighbor {intf} interface remote-as {peer_as}"
                else:
                   ni['interfaces'].pop( intf, None )
                   cmd = f"no neighbor {intf}"
                if ni['admin_state']=='enable':
                   # TODO add 'interface {intf} ipv6 nd suppress-ra'? doesn't work
                   # TODO support AS changes?
                   run_vtysh( ns=net_inst,
                              context=f"router bgp {ni['autonomous_system']}",
                              config=[cmd] )

                   # Wait a few seconds, then retrieve the peer's router-id and AS
                   if peer_as is not None:
                       # XXX Should start 1 thread per network-instance, or even
                       # 1 thread for all instances. This is polling
                       MonitoringThread(net_inst,[intf]).start()

            elif peer_as is not None:
                state.network_instances[ net_inst ] = {
                  "interfaces" : { intf : peer_as },
                  "admin_state" : "disable",
                  "openfabric_interfaces" : {},
                  "openfabric" : "disable"
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
                if ni['openfabric']=='enable':
                   name = ni['openfabric_name']
                   no_ = "" if activate else "no "
                   cmds = [ f"{no_}ip router openfabric {name}" ]
                   if intf[0:2] == "lo" and activate:
                      cmds += "openfabric passive"
                   run_vtysh( ns=net_inst,context=f"interface {intf}",config=cmds )
                else:
                   ni['openfabric_interfaces'][ intf ] = True

            elif activate:
                state.network_instances[ net_inst ] = {
                  "openfabric_interfaces" : { intf : True },
                  "openfabric" : "disable",
                  "interfaces" : {},
                  "admin_state" : "disable",
                }

    else:
        logging.info(f"Unexpected notification : {obj}")

    # dont subscribe to LLDP now
    return False

#
# Test: adding a link local nexthop 169.254.0.1 via the NDK
#
def TestAddLinkLocal_Nexthop_Group(name,nh_ip,net_inst='default'):

    import nexthop_group_service_pb2
    import nexthop_group_service_pb2_grpc

    nhg_stub = nexthop_group_service_pb2_grpc.SdkMgrNextHopGroupServiceStub(channel)
    #if action =='replace':
    #    nhg_stub.SyncStart(request=sdk_common_pb2.SyncRequest(),metadata=metadata)
    nh_request = nexthop_group_service_pb2.NextHopGroupRequest()
    nhg_info = nh_request.group_info.add()
    nhg_info.key.network_instance_name = net_inst
    nhg_info.key.name = name + '_sdk' # Must end with '_sdk'
    nh = nhg_info.data.next_hop.add()
    ip = ipaddress.ip_address(nh_ip) # Like Zebra creates
    nh.resolve_to = nexthop_group_service_pb2.NextHop.DIRECT # or INDIRECT or LOCAL
    nh.ip_nexthop.addr = ip.packed

    logging.info(f"NH_REQUEST :: {nh_request}")
    nhg_response = nhg_stub.NextHopGroupAddOrUpdate(request=nh_request,metadata=metadata)
    logging.info(f"NH RESPONSE:: {nhg_response}")
    logging.info(f"NHG status:{nhg_response.status}")
    logging.info(f"NHG error:{nhg_response.error_str}")

    return nhg_response.status == 0

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

##################################################################################################
## This is the main proc where all processing for auto_config_agent starts.
## Agent registration, notification registration, Subscrition to notifications.
## Waits on the subscribed Notifications and once any config is received, handles that config
## If there are critical errors, Unregisters the fib_agent gracefully.
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
    try:
        for r in stream_response:
            logging.info(f"Count :: {count}  NOTIFICATION:: \n{r.notification}")
            count += 1
            for obj in r.notification:
                if obj.HasField('config') and obj.config.key.js_path == ".commit.end":
                    logging.info('TO DO -commit.end config')
                else:
                    Handle_Notification(obj, state)

                    # Program router_id only when changed
                    # if state.router_id != old_router_id:
                    #   gnmic(path='/network-instance[name=default]/protocols/bgp/router-id',value=state.router_id)
                    logging.info(f'Updated state: {state}')

    except grpc._channel._Rendezvous as err:
        logging.info(f'GOING TO EXIT NOW: {err}')

    except Exception as e:
        logging.error(f'Exception caught :: {e}')
        #if file_name != None:
        #    Update_Result(file_name, action='delete')
        try:
            response = stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
            logging.error(f'Run try: Unregister response:: {response}')
        except grpc._channel._Rendezvous as err:
            logging.info(f'GOING TO EXIT NOW: {err}')
            sys.exit()
        return True
    sys.exit()
    return True
############################################################
## Gracefully handle SIGTERM signal
## When called, will unregister Agent and gracefully exit
############################################################
def Exit_Gracefully(signum, frame):
    logging.info("Caught signal :: {}\n will unregister fib_agent".format(signum))
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
    if Run():
        logging.info('Agent unregistered and agent routes withdrawed from dut')
    else:
        logging.info('Should not happen')
