# srl-unnumbered
Experimenting with running FRR on top of SR Linux

FRR supports BGP unnumbered ([RFC5549](https://datatracker.ietf.org/doc/html/rfc5549)), including support for advertising IPv4 next hops over an IPv6 BGP peering session (using auto-assigned link-local addresses ). The next hop that is advertised, is the IPv4 router ID of each node

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
This works because link local addresses are not tested for duplicate IPs. However, it looks like SRL refuses to use them as a next hop address when configured statically.

It is also possible to listen to Zebra's netlink socket directly, see https://zstas.github.io/jekyll/update/2020/02/25/bgp.html

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

