import logging, ipaddress, json
from datetime import datetime

from sdk_protos import route_service_pb2,route_service_pb2_grpc
from sdk_protos import nexthop_group_service_pb2 as ndk_nhg_pb2
from sdk_protos import nexthop_group_service_pb2_grpc as ndk_nhg_grpc
from sdk_protos import telemetry_service_pb2,telemetry_service_pb2_grpc

def NHG_name(interface,v4=False):
    return f"bgpu_{'v4_' if v4 else ''}{interface}_sdk" # Must end with _sdk

class PrefixManager:
    """
    Manages route prefixes received through netlink, and forwards them to the NDK.

    Originally, I thought that in 21.6.4 (at least) the NDK did not like NHGs
    without IP next hops provisioned,so this class holds on to those prefixes
    until the nexthop is resolved (by FRR BGP unnumbered session coming online)

    Later I learned that the issue is bgpd not liking ipv4 routes with ipv6 nexthops
    """
    def __init__(self,net_inst,sdk_channel,metadata,config):
        self.network_instance = net_inst
        self.channel = sdk_channel
        self.metadata = metadata  # Credentials for API access
        self.config = config      # Settings for this network instance
        self.oif_2_interface = {} # Map of oif to resolved interface name
        self.nhg_2_peer_nh_ips = {} # NHG name to (v4,v6) nexthop address(es)
        self.interface_state = {} # Dynamic interface state
        self.unresolved_ecmp_groups = {} # ECMP routes, key=oif bitmask
        self.pending_routes = {} # Map of unresolved routes, per interface index
        self.stats = { 'ipv4': { 'value' : 0 }, 'ipv6': { 'value': 0 } }

        # connect to ipdb to receive netlink messages
        self.RegisterRouteHandler(net_inst)

    def Add_Telemetry(self,js_path,js_data):
        telemetry_stub = telemetry_service_pb2_grpc.SdkMgrTelemetryServiceStub(self.channel)
        telemetry_update_request = telemetry_service_pb2.TelemetryUpdateRequest()
        telemetry_info = telemetry_update_request.state.add()
        telemetry_info.key.js_path = f'.network_instance{{.name=="{self.network_instance}"}}' + js_path
        telemetry_info.data.json_content = json.dumps(js_data)
        logging.info(f"Telemetry_Update_Request :: {telemetry_update_request}")
        telemetry_response = telemetry_stub.TelemetryAddOrUpdate(request=telemetry_update_request, metadata=self.metadata)
        return telemetry_response

    def Set_Interface_State(self,interface,oper_state):
        ifstate = {
         'last_updated': { 'value': datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ") },
         'oper_state': { 'value': oper_state },
        }
        if oper_state=='up' and interface in self.interface_state:
          ifstate.update( self.interface_state[interface] )

        ifname = interface.replace('-','/').replace('e','ethernet-')
        self.Add_Telemetry( f'.interface{{.name=="{ifname}"}}.bgp_unnumbered.status', ifstate )

    #
    # Registers an IPDB callback handler for route events in the given VRF instance
    #
    def RegisterRouteHandler(self,net_inst):
      logging.info( f"RegisterRouteHandler({net_inst})" )

      # During system startup, wait for netns to be created
      import os
      while not os.path.exists( f'/var/run/netns/srbase-{net_inst}' ):
         logging.info( f"Waiting for srbase-{net_inst} netns to be created...")
         import time
         time.sleep(1)

      # Need to do this in a separate thread, not same as processing config
      # Needs yum install python3-pyroute2 -y
      from pyroute2 import IPDB  # pylint: disable=no-name-in-module
      from pyroute2 import NetNS # pylint: disable=no-name-in-module
      self.ipdb = IPDB(nl=NetNS(f'srbase-{net_inst}'))
      for i in self.ipdb.interfaces:
          index = self.ipdb.interfaces[i]['index']
          logging.info( f"IPDB found interface: {i} index(oif)={index}" )

      # Register our callback to the IPDB, to listen for BGP routes from FRR
      def netlink_callback(ipdb, msg, action):
         # logging.info(f"IPDB callback msg={msg} action={action}")
         if 'proto' in msg and msg['proto'] == 186: # BGP route
           if action=="RTM_NEWROUTE":
              logging.debug( f"Routehandler {net_inst}: add_Route {msg}" )
              self.add_Route( msg )
           elif action=="RTM_DELROUTE":
              logging.debug( f"Routehandler {net_inst}: del_Route {msg}" )
              self.del_Route( msg )
           else:
              logging.info( f"netlink_callback: Ignoring BGP action {action}" )
         elif action=='RTM_NEWLINK':
           logging.debug( f"Link change event: {msg}" )
           status = msg['attrs'][2][1] # IFLA_OPERSTATE
           self.Set_Interface_State( msg['attrs'][0][1], 'up' if status=='UP' else 'down' )
         else:
           logging.debug( f"netlink_callback: Ignoring {action}" )

      self.ipdb.register_callback(netlink_callback)

    def add_Route( self, netlink_msg ):
       prefix = netlink_msg['attrs'][1][1] # RTA_DST
       length = netlink_msg['dst_len']
       route = [ (prefix, length) ]

       # metric = netlink_msg['attrs'][2][1] # RTA_priority -> metric ?
       # version = "v6" if netlink_msg['family'] == 10 else "v4"

       # DEBUG: Ignore v4 routes
       # if version=="v6":
       #   logging.info( f"JvB: ignoring v6 route: {prefix}/{length}" )
       #   return

       att4 = netlink_msg['attrs'][4]
       resolved_nhg = None
       if att4[0] == "RTA_MULTIPATH": # Handle ECMP routes

           # logging.info( f"JvB: ignoring v4 ecmp route: {prefix}/{length}" )
           # return

           # Calculate bitmasked OR of interface indices
           oif_mask = 0
           unresolved_oifs = []
           oifs = [ v['oif'] for v in att4[1] ]
           for oif in oifs:
               oif_mask |= (1<<oif)
               if oif not in self.oif_2_interface:
                   unresolved_oifs.append( oif )
           nhg_name = f"ecmp-{oif_mask:x}"
           if unresolved_oifs==[]:
               resolved_nhg = nhg_name
               if nhg_name not in self.nhg_2_peer_nh_ips:
                   self.create_ecmp_nhg( nhg_name, oifs )
               else:
                   logging.info( f"ECMP NHG: {self.nhg_2_peer_nh_ips[nhg_name]}")

               # Test: remove any individual routes before installing ECMP route
               # Should not be needed, addorupdate can update NHG
               # logging.info( f"add_Route {prefix}/{length} removing any single routes before adding ECMP route" )
               # self.NDK_DeleteRoutes( route )
           else:
               oif = nhg_name # Used as key in pending_routes
               self.unresolved_ecmp_groups[nhg_name] = (oifs, unresolved_oifs)
       else: # if version=="v6":
           oif = netlink_msg['attrs'][5][1] # RTA_OIF
           if oif in self.oif_2_interface:
               resolved_nhg = self.oif_2_interface[oif]
       # else:
       #   logging.info( "Workaround: Don't install single link ipv4 route {prefix}/{length}" )
       #   return

       logging.info( f"add_Route {prefix}/{length} oif={oif} resolved_nhg={resolved_nhg}")

       # Check if the interface has been resolved, if not add to pending list
       if resolved_nhg:
           self.NDK_AddRoutes(resolved_nhg,routes=route)
       else:
           if oif in self.pending_routes:
               self.pending_routes[oif] += route
           else:
               self.pending_routes[oif] = route
           logging.info( f"add_Route added to pending routes: {self.pending_routes}" )

    def NDK_AddRoutes(self,interface,routes):
        """
        Registers a list of routes with the NDK;
        NHG (named after interface) is assumed to exist
        """
        route_request = route_service_pb2.RouteAddRequest()
        for prefix,prefix_length in routes:
            route_info = route_request.routes.add()
            route_info.data.preference = int( self.config['bgp_preference'] )

            # Could configure defaults for these in the agent Yang params
            # route_info.data.metric = ip['metric']

            route_info.key.net_inst_name = self.network_instance
            ip = ipaddress.ip_address(prefix) # IPv4 or IPv6
            route_info.key.ip_prefix.ip_addr.addr = ip.packed
            route_info.key.ip_prefix.prefix_length = int(prefix_length)

            use_v6 = self.config['use_ipv6_nexthops_for_ipv4'] or ip.version==6
            route_info.data.nexthop_group_name = NHG_name( interface, not use_v6 )

            self.stats[ f'ipv{ip.version}' ]['value'] += 1

        logging.info(f"RouteAddOrUpdate REQUEST :: {route_request}")
        route_stub = route_service_pb2_grpc.SdkMgrRouteServiceStub(self.channel)
        route_response = route_stub.RouteAddOrUpdate(request=route_request,
                                                     metadata=self.metadata)
        logging.info(f"RouteAddOrUpdate RESPONSE:: {route_response.status} " +
                                                 f"{route_response.error_str}" )

        self.Add_Telemetry( '.protocols.experimental_frr.stats.routes', self.stats )
        return route_response.status == 0

    def del_Route( self, netlink_msg ):
        prefix = netlink_msg['attrs'][1][1] # RTA_DST
        length = netlink_msg['dst_len']
        if netlink_msg['attrs'][5][0] == 'RTA_OIF':
          oif = netlink_msg['attrs'][5][1] # RTA_OIF, not correct upon link down
        elif netlink_msg['attrs'][4][0] == 'RTA_MULTIPATH':
          oif = netlink_msg['attrs'][4][1][0]['oif']
        else:
          logging.warning( f"Unable to determine 'oif': {netlink_msg}" )
          oif = None
        logging.info( f"del_Route {prefix}/{length} oif={oif} pending={self.pending_routes} msg={netlink_msg}" )
        if oif in self.pending_routes:
            self.pending_routes[oif] = [ (p,l) for p,l in self.pending_routes[oif] if p!=prefix and l!=length ]
            logging.info( f"del_Route {prefix}/{length} pending_routes[{oif}]={self.pending_routes[oif]}" )
        return self.NDK_DeleteRoutes( routes=[(prefix,length)] )

    def NDK_DeleteRoutes( self, routes ):
        route_del_request = route_service_pb2.RouteDeleteRequest()
        for prefix,prefix_length in routes:
            route_info = route_del_request.routes.add()
            route_info.net_inst_name = self.network_instance
            ip = ipaddress.ip_address(prefix)
            route_info.ip_prefix.ip_addr.addr = ip.packed
            route_info.ip_prefix.prefix_length = int(prefix_length)
            # route_info.data.nexthop_group_name = no need to set this

        logging.info(f"RouteDelete REQUEST :: {route_del_request}")
        route_stub = route_service_pb2_grpc.SdkMgrRouteServiceStub(self.channel)
        route_del_response = route_stub.RouteDelete(request=route_del_request,
                                                    metadata=self.metadata)
        logging.info(f"RouteDelete RESPONSE:: {route_del_response.status} " +
                                              f"{route_del_response.error_str}")
        return route_del_response.status == 0
        # TODO after last route is removed, cleanup NHG too

    def resolve_pending_routes(self,key,nhg_name):
        if key in self.pending_routes:
            self.NDK_AddRoutes( nhg_name, self.pending_routes[key] )
            del self.pending_routes[key]
            logging.info( f"resolve_pending_routes routes added, remaining={self.pending_routes}" )
        else:
            logging.info( f"resolve_pending_routes no routes pending for {key} nhg={nhg_name}" )

    def create_ecmp_nhg(self,nhg_name,oifs):
        """
        Creates a new ECMP NHG, and resolves any pending routes
        """
        assert( nhg_name not in self.nhg_2_peer_nh_ips )
        logging.info( f"create_ecmp_nhg {nhg_name} oifs={oifs}" )
        nhg_ips = {}
        for oif in oifs:
           ifname = self.oif_2_interface[oif]
           v4_v6_nh = list(self.nhg_2_peer_nh_ips[ifname].keys())[0]
           nhg_ips[v4_v6_nh] = oif
        self.nhg_2_peer_nh_ips[nhg_name] = nhg_ips
        self.NDK_AddOrUpdateNextHopGroup( nhg_name )
        self.resolve_pending_routes( nhg_name, nhg_name )

    def onInterfaceBGPv6Connected(self,interface,peer_nhs,peer_id,peer_as):
        """
        Called when FRR BGP unnumbered ipv6 session comes up
        """
        logging.info( f"onInterfaceBGPv6Connected {interface} {peer_nhs}" )
        intf_index = self.ipdb.interfaces[interface]['index'] # == netlink 'oif'
        self.oif_2_interface[intf_index] = interface
        self.nhg_2_peer_nh_ips[interface] = { peer_nhs: intf_index }  # (v4,v6)
        self.NDK_AddOrUpdateNextHopGroup( interface )
        peer_data = {
          'last_updated': { 'value': datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ") },
          'peer_as': { 'value': peer_as },
        }
        self.Add_Telemetry( f'.protocols.experimental_frr.peer{{.router_id=="{peer_id}"}}', peer_data )
        self.interface_state[interface] = {
          'discovered_peer_as': { 'value': peer_as },
          'router_id': { 'value': peer_id },
        }
        self.Set_Interface_State( interface, 'up' )

        # Also update any ECMP groups that this interface belongs to
        for nhg_name in list(self.unresolved_ecmp_groups.keys()):
            oifs, unresolved_oifs = self.unresolved_ecmp_groups[nhg_name]
            if intf_index in unresolved_oifs:
               if len(unresolved_oifs)==1:
                   del self.unresolved_ecmp_groups[nhg_name]
                   self.create_ecmp_nhg( nhg_name, oifs )
               else:
                   unresolved_oifs.remove( intf_index )
                   self.unresolved_ecmp_groups[nhg_name] = (oifs, unresolved_oifs)

        self.resolve_pending_routes( intf_index, nhg_name=interface )
        logging.info( f"onInterfaceBGPv6Connected unresolved ECMP left={self.unresolved_ecmp_groups}" )
    #
    # Creates or updates next hop group for a given (resolved) interface,
    # using the NDK
    #
    def NDK_AddOrUpdateNextHopGroup( self, groupname, do_v4=False ):
        logging.info(f"NDK_AddOrUpdateNextHopGroup :: name={groupname} v4={do_v4}")
        nh_request = ndk_nhg_pb2.NextHopGroupRequest()

        nhg_info = nh_request.group_info.add()
        nhg_info.key.network_instance_name = self.network_instance
        nhg_info.key.name = NHG_name( groupname, do_v4 )

        assert( groupname in self.nhg_2_peer_nh_ips )
        v4_valid = False
        for (v4_nh,v6_nh) in sorted(self.nhg_2_peer_nh_ips[groupname].keys()):
          if v4_nh:
              v4_valid = True
          nh = nhg_info.data.next_hop.add()
          # 'linux' mgr uses 'DIRECT' resolution for ipv6 link locals
          nh.resolve_to = ndk_nhg_pb2.NextHop.INDIRECT # LOCAL, DIRECT
          nh.type = ndk_nhg_pb2.NextHop.REGULAR # INVALID, MPLS, REGULAR
          nh.ip_nexthop.addr = ipaddress.ip_address(v4_nh if do_v4 else v6_nh).packed
          logging.info(f"NextHopGroupAddOrUpdate :: added {v4_nh if do_v4 else v6_nh} (INDIRECT)" )

        logging.info(f"NextHopGroupAddOrUpdate :: {nh_request}")
        nhg_stub = ndk_nhg_grpc.SdkMgrNextHopGroupServiceStub(self.channel)
        nhg_response = nhg_stub.NextHopGroupAddOrUpdate(request=nh_request,
                                                        metadata=self.metadata)
        logging.info(f"NextHopGroupAddOrUpdate :: status={nhg_response.status}"+
                                                f"err={nhg_response.error_str}")

        # Also create ipv4 variant, if valid
        if v4_valid and not do_v4:
            return self.NDK_AddOrUpdateNextHopGroup(groupname,do_v4=True)

        return nhg_response.status == 0
