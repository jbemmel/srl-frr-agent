# Extending SR Linux with open source functionality - exploring the 'adjacent possible'
The [adjacent possible](https://understandinginnovation.blog/2019/01/03/exploring-the-adjacent-possible-the-origin-of-good-ideas/) is the set of innovations that are available from a given starting point. Given a truly open platform based on Linux, there is a whole internet full of open source software that can now be integrated, enabling new ways to do things differently. By definition, such extensions are not 'mainstream' and hence not a good match for productization as official product features (with associated roadmap, support, QA, etc. ). However, it opens up a whole new area of networking solutions. This demo is but one example.

## Experimenting with running FRR on top of SR Linux: BGP unnumbered

FRR supports BGP unnumbered ([RFC5549](https://datatracker.ietf.org/doc/html/rfc5549)). The idea is to limit the use of statically assigned addresses to just an IPv4 router ID on a loopback interface, combined with auto-assigned (SLAAC) link-local IPv6 addresses on interfaces. Peer AS numbers are automatically discovered, and BGP extended next-hop encoding is used to advertise IPv4 routes with an IPv6 next hop.

FRR by default puts its routes in the Linux kernel, and it is possible to listen for Netlink events to receive changes (see sample Python code).
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
SR Linux does not allow configuration of link-local addresses on interfaces, and next hops with such addresses are currently ignored. Therefore, this demo agent instead creates a pair of /31 IPv4 addresses based on the peer's IPv4 router ID, and assigns that to the interface after the automatic IPv6 BGP peering session is established.

## Populating the data path: adding routes using the SR Linux NDK

By default, FRR integrates with the Linux kernel and populates a network namespace with the routes it learns. Using a Netlink socket, applications can connect to a namespace and receive events about routes being added or removed.

It may also be possible to listen to Zebra's netlink socket directly, see https://zstas.github.io/jekyll/update/2020/02/25/bgp.html - however, the Linux kernel events are more generic, and better documented.

```
sudo /usr/lib/frr/zebra -f /etc/frr/zebra.conf -u frr -M fpm:protobuf -t
2021/08/04 23:38:17 ZEBRA: [NNACN-54BDA][EC 4043309110] Disabling MPLS support (no kernel support)
2021/08/04 23:38:17 ZEBRA: [YGG9Y-F45YY][EC 4043309078] FPM protobuf message format is not available
```
Unfortunately FPM protobuf support requires a custom FRR build

At /var/run/frr/zserv.api there is a socket to connect to

## Other thoughts
It is also possible to dynamically assign /31 IPv4 addresses to the interfaces that participate in BGP unnumbered. If we discover the router ID of the peer and allow for a configurable IP range to use, then:
* Calculate the difference between the router IDs, and use this as an index into the IP range. The lower ID gets .0 and the higher one gets .1 (out of a /31 pair)
For example, if a spine is 1.1.0.0 and a leaf is 1.1.1.0, the difference is 256. 1.1.0.1 and 1.1.1.1 would have the same difference, so the index to use could be calculated as the difference between router-ids plus the last octet of the lowest one.
* It may be easier to use locally unique private addresses, disabling duplicate address detection
* Alternatively, the /31 corresponding to the neighbor's router ID can be used ( if router ID is 1.1.1.1, assign 1.1.1.0/31 ). This can work if different tiers differ in higher octets ( e.g. spine=1.1.0.x, leaf=1.1.1.x ) such that the local router's ID is not "close" to its peer

