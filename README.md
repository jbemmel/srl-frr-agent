# Extending SR Linux with open source functionality - exploring 🚀 the 'adjacent possible'
![plot](./images/Adjacent_Possible2.png)

The [adjacent possible](https://understandinginnovation.blog/2019/01/03/exploring-the-adjacent-possible-the-origin-of-good-ideas/) is the set of innovations that are available from a given starting point. Given a truly open platform based on Linux, there is a whole internet full of open source software that can now be integrated, enabling new ways to do things differently. By definition, such extensions are not 'mainstream' and hence not a good match for productization as official product features (with associated roadmap, support, QA, etc. ). However, it opens up a whole new area of networking solutions; this demo is but one small example.

## Experimenting with running FRR on top of SR Linux: BGP unnumbered

FRR supports BGP unnumbered ([RFC5549](https://datatracker.ietf.org/doc/html/rfc5549)). The idea is to limit the use of statically assigned addresses to just an IPv4 router ID on a loopback interface, combined with auto-assigned (SLAAC) link-local IPv6 addresses on interfaces. Peer AS numbers are automatically discovered, and BGP extended next-hop encoding is used to advertise IPv4 routes with an IPv6 next hop.

FRR by default puts its routes in the Linux kernel, and it is possible to listen for Netlink events to receive changes (see [Python code](https://github.com/jbemmel/srl-frr-agent/blob/main/src/frr-agent/srl-frr-agent.py#L346)).
Using the 'zebra' protocol, 'ip neighbor' shows how a custom static ARP entry for '169.254.0.1' gets inserted to resolve the (dummy) IPv4 next hop:
```
[root@leaf1 frr]# ip neig
...
169.254.0.1 dev e1-1.0 lladdr 02:7d:f7:ff:00:01 PERMANENT proto zebra  <= this one
fe80::7d:f7ff:feff:1 dev e1-1.0 lladdr 02:7d:f7:ff:00:01 router REACHABLE
...
```
On the peer, the _exact same address_ is used:
```
[root@spine1 ~]# ip neig
...
169.254.0.1 dev e1-1.0 lladdr 02:9f:7f:ff:00:01 PERMANENT proto zebra <= this one
fe80::9f:7fff:feff:1 dev e1-1.0 lladdr 02:9f:7f:ff:00:01 router REACHABLE
...
```
SR Linux does not allow configuration of link-local addresses on interfaces, and next hops with such addresses (ipv4/v6) are currently ignored. Therefore, this demo agent instead assigns a /31 IPv4 address based on a configured range, and assigns that to the interface after the automatic IPv6 BGP peering session is established.
Similarly, a mapped IPv4 local /127 peer link is provisioned for IPv6, using the lowest router ID as a base (+1 or -1 for the peer IP).

The IPv4 addresses are asymmetrical, as they are only used to lookup the MAC address of the next hop. It may happen that the same address is used on both sides of the link:
```
spine e1-1.0: 192.0.0.0/31 -> leaf ARP entry for 192.0.0.1
leaf  e1-1.0: 192.0.0.0/31 -> spine ARP entry for 192.0.0.1
```

These addresses are automatically managed by the agent:
```
A:spine1# info /interface ethernet-1/1                                                                                                                                                                             
    interface ethernet-1/1 {
        admin-state enable
        subinterface 0 {
            description "auto-configured by SRL FRR agent peer=1.1.1.1"
            admin-state enable
            ipv4 {
                address 192.0.0.0/31 {
                    primary
                }
                arp {
                    duplicate-address-detection false
                    neighbor 192.0.0.1 {
                        link-layer-address 02:CF:5B:FF:00:01 !!! auto-configured by SRL FRR agent peer=1.1.1.1
                    }
                }
            }
            ipv6 {
                address fc00:101:101:101:1::/127 {
                    primary
                }
                router-advertisement {
                    router-role {
                        admin-state disable
                    }
                }
            }
        }
    }
```
Note how duplicate address detection needs to be disabled, in case the same address is used on both sides. Also note how SR Linux IPv6 RA are disabled (as FRR is sending these as well, and they may conflict)

## Populating the data path: adding routes using the SR Linux NDK

By default, FRR integrates with the Linux kernel and populates a network namespace with the routes it learns. Using a Netlink socket, applications can connect to a namespace and receive events about routes being added or removed.

### Other options to listen for route events

It may also be possible to listen to Zebra's netlink socket directly, see https://zstas.github.io/jekyll/update/2020/02/25/bgp.html - however, the Linux kernel events are more generic, and better documented.

```
sudo /usr/lib/frr/zebra -f /etc/frr/zebra.conf -u frr -M fpm:protobuf -t
2021/08/04 23:38:17 ZEBRA: [NNACN-54BDA][EC 4043309110] Disabling MPLS support (no kernel support)
2021/08/04 23:38:17 ZEBRA: [YGG9Y-F45YY][EC 4043309078] FPM protobuf message format is not available
```
Unfortunately FPM protobuf support requires a custom FRR build

At /var/run/frr/zserv.api there is a socket to connect to

# SR Linux config snippets

To configure this new experimental extension on SR Linux, a sample spine-leaf topology lab is included. Here are some minimal config snippets to copy:

## BGP unnumbered (eBGP)
Spine:
```
enter candidate
/interface ethernet-1/1
admin-state enable
subinterface 0
admin-state enable
ipv4 { }
ipv6 { }
/interface lo0 subinterface 0 ipv4 address 100.1.0.1/32
/network-instance default
interface ethernet-1/1.0 bgp-unnumbered peer-as external
protocols experimental-frr
admin-state enable
router-id 1.1.0.1
autonomous-system 65000
bgp {
  admin-state enable
  port 1179
}
commit stay
```
Leaf:
```
enter candidate
/interface ethernet-1/1
admin-state enable
subinterface 0
admin-state enable
ipv4 { }
ipv6 { }
/interface lo0 subinterface 0 ipv4 address 100.1.1.1/32
/network-instance default
interface ethernet-1/1.0 bgp-unnumbered peer-as external
protocols experimental-frr
admin-state enable
router-id 1.1.1.1
autonomous-system 65001
bgp {
  admin-state enable
  port 1179
}
commit stay
```

Note how the FRR BGP process listens on a (configurable) non-default port 1179, instead of 179; this allows FRR and the native SR Linux BGP process to coexist in the same namespace, if needed. A [patch](https://github.com/FRRouting/frr/pull/9513) to enable this configuration for FRR was submitted.

For vtysh access, a shell alias gets configured:
```
environment alias vtysh "bash /usr/bin/sudo /usr/bin/vtysh --vty_socket /var/run/frr/srbase-default/"
```
(this is hardcoded to use the 'default' network-instance, a more generic CLI extension command could be built to support 'the current' namespace as well - see /opt/srlinux/python/virtual-env/lib/python3.6/site-packages/srlinux/mgmt/cli/plugins/deploy_agent.py for an example)

After establishing the alias, the BGP peering status and routing table can be examined:
```
show bgp summary
show ip route
```
Which should look something like this:
```
spine1# show bgp sum

IPv4 Unicast Summary:
BGP router identifier 1.1.0.1, local AS number 65000 vrf-id 0
BGP table version 2
RIB entries 3, using 552 bytes of memory
Peers 1, using 723 KiB of memory

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
leaf1(e1-1.0)   4      65001       581       581        0    0    0 00:28:42            1        2 N/A

Total number of neighbors 1

IPv6 Unicast Summary:
BGP router identifier 1.1.0.1, local AS number 65000 vrf-id 0
BGP table version 2
RIB entries 3, using 552 bytes of memory
Peers 1, using 723 KiB of memory

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
leaf1(e1-1.0)   4      65001       581       581        0    0    0 00:28:42            1        2 N/A

Total number of neighbors 1

spine1# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, A - Babel, F - PBR, f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

C>* 100.1.0.1/32 is directly connected, lo0.0, 00:27:50
B>* 100.1.1.1/32 [20/0] via fe80::cf:5bff:feff:1, e1-1.0, weight 1, 00:27:44
C>* 169.254.1.0/24 is directly connected, gateway, 00:27:50
C>* 192.0.0.0/31 is directly connected, e1-1.0, 00:27:38
```

On SR Linux side, the routes get instantiated:
```
A:leaf1# show network-instance default route-table all                                                                                                                                                             
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
IPv4 Unicast route table of network instance default
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
+-------------------------------------+-------+------------+----------------------+----------------------+----------+---------+-----------------------+-----------------------+
|               Prefix                |  ID   | Route Type |     Route Owner      |      Best/Fib-       |  Metric  |  Pref   |    Next-hop (Type)    |  Next-hop Interface   |
|                                     |       |            |                      |     status(slot)     |          |         |                       |                       |
+=====================================+=======+============+======================+======================+==========+=========+=======================+=======================+
| 1.1.0.0/31                          | 1     | local      | net_inst_mgr         | True/success         | 0        | 0       | 1.1.0.0 (direct)      | ethernet-1/1.0        |
| 1.1.0.0/32                          | 1     | host       | net_inst_mgr         | True/success         | 0        | 0       | None (extract)        | None                  |
| 100.1.0.1/32                        | 10    | ndk1       | srl_frr_agent        | True/success         | 0        | 170     | 1.1.0.1 (indirect)    | None                  |
| 100.1.1.1/32                        | 2     | host       | net_inst_mgr         | True/success         | 0        | 0       | None (extract)        | None                  |
+-------------------------------------+-------+------------+----------------------+----------------------+----------+---------+-----------------------+-----------------------+
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
4 IPv4 routes total
4 IPv4 prefixes with active routes
0 IPv4 prefixes with active ECMP routes
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
IPv6 Unicast route table of network instance default
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
+-------------------------------------+-------+------------+----------------------+----------------------+----------+---------+-----------------------+-----------------------+
|               Prefix                |  ID   | Route Type |     Route Owner      |      Best/Fib-       |  Metric  |  Pref   |    Next-hop (Type)    |  Next-hop Interface   |
|                                     |       |            |                      |     status(slot)     |          |         |                       |                       |
+=====================================+=======+============+======================+======================+==========+=========+=======================+=======================+
| ::ffff:1.1.0.0/127                  | 1     | local      | net_inst_mgr         | True/success         | 0        | 0       | ::ffff:1.1.0.0        | ethernet-1/1.0        |
|                                     |       |            |                      |                      |          |         | (direct)              |                       |
| ::ffff:1.1.0.0/128                  | 1     | host       | net_inst_mgr         | True/success         | 0        | 0       | None (extract)        | None                  |
| 2001::6401:1/128                    | 10    | ndk1       | srl_frr_agent        | True/success         | 0        | 170     | ::ffff:1.1.0.1        | None                  |
|                                     |       |            |                      |                      |          |         | (indirect)            |                       |
| 2001::6401:101/128                  | 2     | host       | net_inst_mgr         | True/success         | 0        | 0       | None (extract)        | None                  |
+-------------------------------------+-------+------------+----------------------+----------------------+----------+---------+-----------------------+-----------------------+
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
4 IPv6 routes total
4 IPv6 prefixes with active routes
0 IPv6 prefixes with active ECMP routes
```

Routes from BGP unnumbered peers are distinguished as coming from the "srl_frr_agent", via the NDK. Local interface routes like 1.1.0.0/31 are filtered out by a route-map in FRR (as would happen if a link local 169.254.x.y address were used instead)

Preference values are configurable for IBGP or EBGP, both default 170. Multiple BGP unnumbered interfaces (to different peers) can be supported per network instance

## The benefits of numbered BGP unnumbered

In the current 21.11.2 version, this agent configures a static IPv6 address on each interface in addition to the auto-assigned link-local one. While this may seem redundant and "inefficient", consider the following:

```
leaf2$ ping6 2001::1:1:0:1 -I 2001::1:1:0:2

PING 2001::1:1:0:1(2001::1:1:0:1) from 2001::1:1:0:2 : 56 data bytes

64 bytes from 2001::1:1:0:1: icmp_seq=1 ttl=63 time=19.1 ms
64 bytes from 2001::1:1:0:1: icmp_seq=2 ttl=63 time=15.1 ms
64 bytes from 2001::1:1:0:1: icmp_seq=3 ttl=63 time=17.6 ms
^C

--- 2001::1:1:0:1 ping statistics ---

3 packets transmitted, 3 received, 0% packet loss, time 2002ms

rtt min/avg/max/mdev = 15.101/17.279/19.105/1.653 ms

leaf2$ traceroute6 2001::1:1:0:1 -s 2001::1:1:0:2 -n

traceroute to 2001::1:1:0:1 (2001::1:1:0:1), 30 hops max, 80 byte packets

 1  fd00:101:102:101:2::5 (fd00:101:102:101:2::5)  9.262 ms fd00:101:101:101:2::3 (fd00:101:101:101:2::3)  9.219 ms *
 2  2001::1:1:0:1 (2001::1:1:0:1)  13.281 ms  13.322 ms  13.294 ms
 ```
 
 In a fabric with "pure" IPv6 unnumbered, traceroutes are impossible to trace. While assigning random IP addresses automatically is easy, it has clear drawbacks in other areas.
 One could argue it solves one problem, but creates another.

## Enhanced Interior Gateway Routing Protocol (EIGRP) - RFC7868 (same AS)
Spine + Leaf:
```
enter candidate
/system !!! ${//system/name/host-name|'0' if _=='spine1' else '1'}
/interface ethernet-1/1
admin-state enable
delete subinterface 0
/network-instance default
protocols experimental-frr
admin-state enable
router-id 1.1.${/system!!!}.1
autonomous-system 65000
bgp disable
eigrp admin-state enable
commit stay
```

Non-native multicast on subinterfaces is not supported by SR Linux, so the agent builds and manages its own subinterfaces behind the scenes.
We can manage the IP interfaces through FRR:

Spine:
```
A:spine1# vtysh network-instance default

spine1# conf t
spine1(config)# int eigrp-e1
spine1(config-if)# ip address 10.0.0.0/31
spine1(config-if)# end
spine1# show ip eigrp neighbors

EIGRP neighbors for AS(65000)

H   Address           Interface            Hold   Uptime   SRTT   RTO   Q     Seq  
                                           (sec)           (ms)        Cnt    Num   
```

Leaf:
```
A:leaf1# vtysh network-instance default

leaf1# conf t
leaf1(config)# int eigrp-e1
leaf1(config-if)# ip address 10.0.0.1/31
leaf1(config-if)# end
leaf1# ping 10.0.0.0
  <cr>  
leaf1# ping 10.0.0.0
PING 10.0.0.0 (10.0.0.0) 56(84) bytes of data.
64 bytes from 10.0.0.0: icmp_seq=1 ttl=64 time=0.074 ms
64 bytes from 10.0.0.0: icmp_seq=2 ttl=64 time=0.083 ms
64 bytes from 10.0.0.0: icmp_seq=3 ttl=64 time=0.081 ms
64 bytes from 10.0.0.0: icmp_seq=4 ttl=64 time=0.062 ms
64 bytes from 10.0.0.0: icmp_seq=5 ttl=64 time=0.056 ms
^C
--- 10.0.0.0 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4094ms
rtt min/avg/max/mdev = 0.056/0.071/0.083/0.011 ms
leaf1# show ip eigrp neighbors

EIGRP neighbors for AS(65000)

H   Address           Interface            Hold   Uptime   SRTT   RTO   Q     Seq  
                                           (sec)           (ms)        Cnt    Num   
0   10.0.0.0          eigrp-e1             11     0        0      2    0      4
```

Q.E.D.

## OpenFabric

Using CLI extensions to script the config for 'spine1' and some other node. The snippet below first annotates the system as '0' or '1' based on its hostname,
then references this annotation to generate things like IP addresses and other identities
```
enter candidate
/system !!! ${//system/name/host-name|'0' if _=='spine1' else '1'}
/interface ethernet-1/1
admin-state enable
subinterface 0
admin-state enable
ipv4
  address 10.0.0.${/system!!!}/31
  exit
exit
ipv6 { }
/interface lo0 subinterface 0 ipv4 address 100.1.${/system!!!}.1/32
/network-instance default
interface ethernet-1/1.0 openfabric activate true
interface lo0.0 openfabric activate true
protocols experimental-frr
admin-state enable
bgp disable
router-id 1.1.${/system!!!}.1
autonomous-system 65000
openfabric {
  name SRLinux
  net auto # This uses 49.0001.<system-MAC>.00 as network entity title (NET)
}
commit stay
```

## Other thoughts
It is also possible to dynamically assign /31 IPv4 addresses to the interfaces that participate in BGP unnumbered. If we discover the router ID of the peer and allow for a configurable IP range to use, then:
* Calculate the difference between the router IDs, and use this as an index into the IP range. The lower ID gets .0 and the higher one gets .1 (out of a /31 pair)
For example, if a spine is 1.1.0.0 and a leaf is 1.1.1.0, the difference is 256. 1.1.0.1 and 1.1.1.1 would have the same difference, so the index to use could be calculated as the difference between router-ids plus the last octet of the lowest one.
* It may be easier to use locally unique private addresses, disabling duplicate address detection
* Alternatively, the /31 corresponding to the neighbor's router ID can be used ( if router ID is 1.1.1.1, assign 1.1.1.0/31 ). This can work if different tiers differ in higher octets ( e.g. spine=1.1.0.x, leaf=1.1.1.x ) such that the local router's ID is not "close" to its peer
