import logging
import ipaddress

from sdk_protos import route_service_pb2,route_service_pb2_grpc
from sdk_protos import nexthop_group_service_pb2 as ndk_nhg_pb2
from sdk_protos import nexthop_group_service_pb2_grpc as ndk_nhg_grpc

NHG_ALL = "all_bgp_unnumbered_peers"

class PrefixManager:
    """
    Manages route prefixes received through netlink, and forwards them to the NDK.

    In 21.6.4 (at least) the NDK does not like NHGs without IP next hops provisioned,
    so this class holds on to those prefixes until the nexthop is resolved
    (by FRR BGP unnumbered session coming online)
    """
    def __init__(self,net_inst,gnmi_channel,metadata,pref):
        self.network_instance = net_inst
        self.channel = gnmi_channel
        self.metadata = metadata  # Credentials for API access
        self.preference = pref    # Route preference from config
        self.oif_2_interface = { 0: [] } # Map of oif to resolved interface name
        self.interface_2_peer_ipv6s = { NHG_ALL: {} } # name to ipv6 nexth addrs
        self.pending_routes = {} # Map of unresolved routes, per interface index

        # connect to ipdb to receive netlink messages
        self.RegisterRouteHandler(net_inst)

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
      from pyroute2 import IPDB
      from pyroute2 import NetNS
      self.ipdb = IPDB(nl=NetNS(f'srbase-{net_inst}'))
      for i in self.ipdb.interfaces:
          index = self.ipdb.interfaces[i]['index']
          logging.info( f"IPDB found interface: {i} index(oif)={index}" )

      # Register our callback to the IPDB, to listen for BGP routes from FRR
      def netlink_callback(ipdb, msg, action):
         # logging.info(f"IPDB callback msg={msg} action={action}")
         if 'proto' in msg and msg['proto'] == 186: # BGP route
           if action=="RTM_NEWROUTE":
              logging.info( f"Routehandler {net_inst}: add_Route {msg}" )
              self.add_Route( msg )
           elif action=="RTM_DELROUTE":
              logging.info( f"Routehandler {net_inst}: del_Route {msg}" )
              self.del_Route( msg )
           else:
              logging.info( f"netlink_callback: Ignoring BGP action {action}" )
         else:
            logging.info( f"netlink_callback: Ignoring {action}" )

      self.ipdb.register_callback(netlink_callback)

    def add_Route( self, netlink_msg ):
       prefix = netlink_msg['attrs'][1][1] # RTA_DST
       length = netlink_msg['dst_len']
       # metric = netlink_msg['attrs'][2][1] # RTA_priority -> metric ?
       # version = "v6" # if netlink_msg['family'] == 10 or not use_v4 else "v4"

       # def get_ipv6_nh(attrs):
       #     if attrs[0] == "RTA_VIA":
       #         return attrs[1]['addr']
       #     elif attrs[0] == "RTA_GATEWAY":
       #         return attrs[1]
       #     else:
       #         logging.error( f"Unable to find IPv6 nexthop: {attrs[0]}" )
       #         return None

       att4 = netlink_msg['attrs'][4]
       if att4[0] == "RTA_MULTIPATH":
           # for v in att4[1]:
           # via_v6 = get_ipv6_nh( v['attrs'][0] )
           #     oif = v['oif']
           #     logging.info( f"multipath[oif={oif}] Add_Route {prefix}/{length}" )
           #     SDK_AddRoute(network_instance,oif,prefix,length,preference)

           # For now, assume *all* interfaces are listed
           logging.info( f"add_Route {prefix}/{length} oif=MULTIPATH assuming *({att4[1]})" )
           oif = 0
       else:
           # via_v6 = get_ipv6_nh( att4 )
           oif = netlink_msg['attrs'][5][1] # RTA_OIF
       logging.info( f"add_Route {prefix}/{length} oif={oif}" )

       # Check if the interface has been resolved, if not add to pending list
       route = [ (prefix, length) ]
       if oif in self.oif_2_interface:
           self.NDK_AddRoutes(self.oif_2_interface[oif],routes=route)
       else:
           if oif in self.pending_routes:
               self.pending_routes[oif] += route
           else:
               self.pending_routes[oif] = route
           logging.info( f"Route added to pending routes: {self.pending_routes}" )

    def NDK_AddRoutes(self,interface,routes):
        """
        Registers a list of routes with the NDK;
        NHG (named after interface) is assumed to exist
        """
        route_request = route_service_pb2.RouteAddRequest()
        for prefix,prefix_length in routes:
            route_info = route_request.routes.add()
            route_info.data.preference = self.preference

            # Could configure defaults for these in the agent Yang params
            # route_info.data.metric = ip['metric']

            route_info.key.net_inst_name = self.network_instance
            ip = ipaddress.ip_address(prefix) # IPv4 or IPv6
            route_info.key.ip_prefix.ip_addr.addr = ip.packed
            route_info.key.ip_prefix.prefix_length = int(prefix_length)

            #
            # SDK allows to either specify a NHG name, or a list of nexthop IPs
            # nexthop = route_info.nexthop.add()
            #
            nhg_name = f"{interface}_sdk" # Must end with '_sdk'
            route_info.data.nexthop_group_name = nhg_name

        logging.info(f"RouteAddOrUpdate REQUEST :: {route_request}")
        route_stub = route_service_pb2_grpc.SdkMgrRouteServiceStub(self.channel)
        route_response = route_stub.RouteAddOrUpdate(request=route_request,
                                                     metadata=self.metadata)
        logging.info(f"RouteAddOrUpdate RESPONSE:: {route_response.status} " +
                                                 f"{route_response.error_str}" )
        return route_response.status == 0

    def del_Route( self, netlink_msg ):
        prefix = netlink_msg['attrs'][1][1] # RTA_DST
        length = netlink_msg['dst_len']
        logging.info( f"Del_Route {prefix}/{length}" )
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

    def onInterfaceBGPv6Connected(self,interface,peer_ipv6):
        """
        Called when FRR BGP unnumbered ipv6 session comes up
        """
        logging.info( f"onInterfaceBGPv6Connected {interface} {peer_ipv6}" )
        intf_index = self.ipdb.interfaces[interface]['index'] # == netlink 'oif'
        self.oif_2_interface[intf_index] = interface
        self.oif_2_interface[0].append( interface ) # Add to list of all ifs
        self.interface_2_peer_ipv6s[NHG_ALL].update( { peer_ipv6: intf_index } )
        self.NDK_AddOrUpdateNextHopGroup( NHG_ALL )
        self.interface_2_peer_ipv6s[interface] = { peer_ipv6: intf_index }
        self.NDK_AddOrUpdateNextHopGroup( interface )

        if intf_index in self.pending_routes:
            self.NDK_AddRoutes( interface, self.pending_routes[intf_index] )
            del self.pending_routes[intf_index]

    #
    # Creates or updates next hop group for a given (resolved) interface,
    # using the NDK
    #
    def NDK_AddOrUpdateNextHopGroup( self, interface ):
        logging.info(f"NDK_AddOrUpdateNextHopGroup :: interface={interface}")
        nh_request = ndk_nhg_pb2.NextHopGroupRequest()

        nhg_info = nh_request.group_info.add()
        nhg_info.key.network_instance_name = self.network_instance
        nhg_info.key.name = interface + '_sdk' # Must end with '_sdk'

        assert( interface in self.interface_2_peer_ipv6s )
        for ipv6_nexthop in self.interface_2_peer_ipv6s[interface].keys():
          nh = nhg_info.data.next_hop.add()
          nh.resolve_to = ndk_nhg_pb2.NextHop.INDIRECT
          nh.type = ndk_nhg_pb2.NextHop.REGULAR
          nh.ip_nexthop.addr = ipaddress.ip_address(ipv6_nexthop).packed

        logging.info(f"NextHopGroupAddOrUpdate :: {nh_request}")
        nhg_stub = ndk_nhg_grpc.SdkMgrNextHopGroupServiceStub(self.channel)
        nhg_response = nhg_stub.NextHopGroupAddOrUpdate(request=nh_request,
                                                        metadata=self.metadata)
        logging.info(f"NextHopGroupAddOrUpdate :: status={nhg_response.status}"+
                                                f"err={nhg_response.error_str}")
        return nhg_response.status == 0
