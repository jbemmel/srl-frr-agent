#!/usr/bin/env python
# coding=utf-8

import grpc
import datetime
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

# See opt/rh/rh-python36/root/usr/lib/python3.6/site-packages/sdk_protos/bfd_service_pb2.py
import bfd_service_pb2

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

##################################################################
## Proc to process the config Notifications received by auto_config_agent
## At present processing config from js_path containing agent_name
##################################################################
def Handle_Notification(obj, state):
    if obj.HasField('config') and obj.config.key.js_path != ".commit.end":
        logging.info(f"GOT CONFIG :: {obj.config.key.js_path}")
        if obj.config.key.js_path == ".network_instance.protocols.experimental_frr":
            logging.info(f"Got config for agent, now will handle it :: \n{obj.config}\
                            Operation :: {obj.config.op}\nData :: {obj.config.data.json}")
            if obj.config.op == 2:
                logging.info(f"Delete config scenario")
                # if file_name != None:
                #    Update_Result(file_name, action='delete')
                response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
                logging.info( f'Handle_Config: Unregister response:: {response}' )
                state = State() # Reset state, works?
            else:
                params = { "network_instance" : obj.config.key.keys[0] } # e.g. "default"

                json_acceptable_string = obj.config.data.json.replace("'", "\"")
                data = json.loads(json_acceptable_string)
                if 'admin_state' in data:
                    params[ "admin_state" ] = data['admin_state'][12:]
                if 'autonomous_system' in data:
                    params[ "autonomous_system" ] = data['autonomous_system']['value']
                if 'router_id' in data:
                    params[ "router_id" ] = data['router_id']['value']
                params[ "peer_as" ] = "external" # TODO change logic
                script_update_frr(**params)
                return True

        # Tends to come first (always?) when full blob is configured
        elif obj.config.key.js_path == ".network_instance.interface":
            json_acceptable_string = obj.config.data.json.replace("'", "\"")
            data = json.loads(json_acceptable_string)

            # 'interface' can be missing
            if 'interface' in data:
               intf = data['interface']
               # TODO handle deletion events too
               if 'bgp_unnumbered_peer_as_enum' in intf:
                  # 'external' or 'internal'
                  peer_as = intf['bgp_unnumbered_peer_as_enum'][13:]
               elif 'bgp_unnumbered_peer_as_uint32' in intf:
                  peer_as = intf['bgp_unnumbered_peer_as_uint32']['value']
               else:
                  peer_as = '?'
               logging.info( f"TODO: Configure peer-as={peer_as}" )
               # TODO lookup AS for this ns, check if enabled
               asn = 65000
               ns = obj.config.key.keys[0]
               intf = obj.config.key.keys[1].replace("ethernet-","e").replace("/","-")
               # TODO multiple commands and/or set peer-as here too?
               cmd = f"{'no ' if not val else ''}neighbor {intf} interface peer-group V4"
               # XXX assumes daemon is running
               run_vtysh( ns=ns, asn=asn, cmd=cmd )

        # TODO process
    else:
        logging.info(f"Unexpected notification : {obj}")

    # dont subscribe to LLDP now
    return False

##
# Update agent state flapcounts for BFD
##
def Update_BFDFlapcounts(state,peer_ip,status=0):
    if peer_ip not in state.bfd_flaps:
       logging.info(f"BFD : initializing flap state for {peer_ip}")
       state.bfd_flaps[peer_ip] = {}
    now = datetime.datetime.now()
    flaps_this_period, history = Update_Flapcounts(state, now, peer_ip, status,
                                                   state.bfd_flaps,
                                                   state.flap_period_mins)
    state_update = {
      "status" : { "value" : "red" if flaps_this_period > state.flap_threshold or status!=4 else "green" },
      "flaps_last_period" : flaps_this_period,
      "flaps_history" : { "value" : history },
      "last_flap_timestamp" : { "value" : now.strftime("%Y-%m-%d %H:%M:%S") }
    }
    Update_Peer_State( peer_ip, 'bfd', state_update )
    Update_Global_State( state, "total_bfd_flaps_last_period", # Works??
      sum( [len(f) for f in state.bfd_flaps.values()] ) )

##
# Update agent state flapcounts for Route entry
##
def Update_RouteFlapcounts(state,peer_ip,prefix):
    if peer_ip not in state.route_flaps:
       logging.info(f"ROUTE : initializing flap state for {peer_ip}")
       state.route_flaps[peer_ip] = {}
    now = datetime.datetime.now()
    flaps_this_period, history = Update_Flapcounts(state, now, peer_ip, prefix,
                                                   state.route_flaps,
                                                   state.flap_period_mins)
    state_update = {
      "status" : { "value" : "red" if flaps_this_period > state.flap_threshold else "green" },
      "flaps_last_period" : flaps_this_period,
      "flaps_history" : { "value" : history },
      "last_flap_timestamp" : { "value" : now.strftime("%Y-%m-%d %H:%M:%S") }
    }
    Update_Peer_State( peer_ip, 'routes', state_update )
    # Update_Global_State( state )

##
# Update agent state flapcounts
##
def Update_Flapcounts(state,now,peer_ip,status,flapmap,period_mins):
    flaps = flapmap[peer_ip]
    if status != 0:
       flaps[now] = status
    keep_flaps = {}
    keep_history = ""
    start_of_period = now - datetime.timedelta(minutes=period_mins)
    _max = state.max_flaps_history
    for i in sorted(flaps.keys(), reverse=True):
       logging.info(f"BFD : check if {i} is within the last period {start_of_period}")
       if ( i > start_of_period and (_max==0 or _max>len(keep_flaps)) ):
           keep_flaps[i] = flaps[i]
           keep_history += f'{ i.strftime("[%H:%M:%S.%f]") } ~ {flaps[i]},'
       else:
           logging.info(f"flap happened outside monitoring period/max: {i}")
           break
    logging.info(f"BFD : keeping last period of flaps for {peer_ip}:{keep_flaps}")
    flapmap[peer_ip] = keep_flaps
    return len( keep_flaps ), keep_history

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

def run_vtysh(ns,asn,cmd):
    logging.info(f'Calling vtysh: ns={ns} cmd={cmd}' )
    try:
       vtysh_proc = subprocess.Popen(
         ['/usr/bin/sudo', '/usr/bin/vtysh',
          '--vty_socket', f'/var/run/frr/srbase-{ns}/',
          '-c', 'configure terminal',
          '-c', f'router bgp {asn}', '-c', cmd ],
         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       stdoutput, stderroutput = vtysh_proc.communicate()
       logging.info(f'vtysh result: {stdoutput} err={stderroutput}')
    except Exception as e:
       logging.error(f'Exception caught in run_vtysh :: {e}')

class State(object):
    def __init__(self):
        self.admin_state = None       # May not be set in config

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
