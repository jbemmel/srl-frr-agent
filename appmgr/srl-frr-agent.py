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
import traceback
import subprocess
from concurrent.futures import ThreadPoolExecutor
import pwd

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

from pygnmi.client import gNMIclient, telemetryParser

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

############################################################
## Subscribe to required event
## This proc handles subscription of: Interface, LLDP,
##                      Route, Network Instance, Config
############################################################
def Subscribe(stream_id, option):
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

def ConfigurePeerIPMAC( intf, peer_ip, mac ):
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
   with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                           username="admin",password="admin",
                           insecure=True, debug=True) as c:
      logging.info( f"Sending gNMI SET: {path} {config}" )
      c.set( encoding='json_ietf', update=[(path,config)] )

#
# Runs as a separate thread
#
def MonitorInterfaces( peer ):
   logging.info( f"MonitorInterfaces: {peer}")
   try:
     while peer['ifs'] != []:
      for _i in peer['ifs']:
         _get_peer = f'show bgp neighbors {_i} json'
         json_data = run_vtysh( ns=peer['net_inst'], show=[_get_peer] )
         if json_data:
             _js = json.loads( json_data )
             if _i in _js:
                i = _js[ _i ]
                neighbor = i['bgpNeighborAddr']
                if neighbor!="none":
                   # dont have the MAC address, but can derive it from ipv6 link local
                   mac = ipv6_2_mac(neighbor) if neighbor != 'none' else '?'
                   logging.info( f"{neighbor} MAC={mac}" )
                   logging.info( f"localAs={i['localAs']} remoteAs={i['remoteAs']}" )
                   logging.info( f"id={i['remoteRouterId']} name={i['hostname'] if 'hostname' in i else '?'}" )
                   ConfigurePeerIPMAC( _i, i['remoteRouterId'], mac )
                   peer['ifs'].remove( _i )

      time.sleep(10)
   except Exception as e:
      logging.error(e)
   logging.info( "Done monitoring interfaces" )


##################################################################
## Proc to process the config Notifications received by auto_config_agent
## At present processing config from js_path containing agent_name
##################################################################
def Handle_Notification(obj, state):
    if obj.HasField('config') and obj.config.key.js_path != ".commit.end":
        logging.info(f"GOT CONFIG :: {obj.config.key.js_path}")
        net_inst = obj.config.key.keys[0] # e.g. "default"
        if obj.config.key.js_path == ".network_instance.protocols.experimental_frr":
            logging.info(f"Got config for agent, now will handle it :: \n{obj.config}\
                            Operation :: {obj.config.op}\nData :: {obj.config.data.json}")
            params = { "network_instance" : net_inst }
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
                if 'admin_state' in data:
                    params[ "admin_state" ] = data['admin_state'][12:]
                if 'autonomous_system' in data:
                    params[ "autonomous_system" ] = data['autonomous_system']['value']
                if 'router_id' in data:
                    params[ "router_id" ] = data['router_id']['value']

                if net_inst in state.network_instances:
                    lines = ""
                    for name,peer_as in state.network_instances[ net_inst ]['interfaces'].items():
                        # Add single indent space at end
                        lines += f'neighbor {name} interface remote-as {peer_as}\n '
                        interfaces.append( name )
                    params[ "bgp_neighbor_lines"] = lines
                else:
                    state.network_instances[ net_inst ] = { **params, "interfaces" : {} }

            script_update_frr(**params)
            if interfaces!=[] and params[ "admin_state" ] == "enable":
               executor = ThreadPoolExecutor(max_workers=1)
               executor.submit( MonitorInterfaces, { "ifs" : interfaces, "net_inst" : net_inst } )
            else:
               logging.info( "interfaces==[] or disabled, not starting monitor thread yet" )
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
                   run_vtysh( ns=net_inst, asn=ni['autonomous_system'], config=[cmd] )

                   # Wait a few seconds, then retrieve the peer's router-id and AS
                   if peer_as is not None:
                       # XXX Should start 1 thread per network-instance, or even
                       # 1 thread for all instances. This is polling
                       executor = ThreadPoolExecutor(max_workers=1)
                       executor.submit( MonitorInterfaces, { "ifs" : [intf], "net_inst" : net_inst } )

            elif peer_as is not None:
                state.network_instances[ net_inst ] = { "interfaces" : { intf : peer_as } }
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
       script_proc = subprocess.Popen(['/etc/opt/srlinux/appmgr/manage-frr.sh'],
                                       # preexec_fn=demote(frr_uid, frr_gid),
                                       env=my_env, # shell=False
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       stdoutput, stderroutput = script_proc.communicate()
       logging.info(f'manage-frr result: {stdoutput} err={stderroutput}')
    except Exception as e:
       logging.error(f'Exception caught in script_update_frr :: {e}')

def run_vtysh(ns,asn=0,show=[],config=[]):
    logging.info(f'Calling vtysh: ns={ns} show={show} config={config}' )
    try:
       args = ['/usr/bin/sudo', '/usr/bin/vtysh',
               '--vty_socket', f'/var/run/frr/srbase-{ns}/']
       if config!=[]:
          args += [ '-c', 'configure terminal', '-c', f'router bgp {asn}' ]
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
