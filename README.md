# srl-unnumbered
Experimenting with running FRR on top of SR Linux

FRR supports BGP unnumbered ([RFC5549](https://datatracker.ietf.org/doc/html/rfc5549)), including support for advertising IPv4 next hops over an IPv6 BGP peering session (using auto-assigned link-local addresses ). The next hop that is advertised, is the IPv4 router ID of each node

FRR by default puts its routes in the Linux kernel, and it is possible to listen for Netlink events to receive changes (see sample Python code).
It is also possible to listen to Zebra's netlink socket directly, see https://zstas.github.io/jekyll/update/2020/02/25/bgp.html

```
sudo /usr/lib/frr/zebra -f /etc/frr/zebra.conf -u frr -M fpm:protobuf -t
2021/08/04 23:38:17 ZEBRA: [NNACN-54BDA][EC 4043309110] Disabling MPLS support (no kernel support)
2021/08/04 23:38:17 ZEBRA: [YGG9Y-F45YY][EC 4043309078] FPM protobuf message format is not available
```
Unfortunately this would require a custom FRR build
