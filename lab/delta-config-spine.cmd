set /system gnmi-server unix-socket admin-state enable

/acl cpm-filter ipv6-filter entry 225 match next-header tcp destination-port value 1179 operator eq
/acl cpm-filter ipv6-filter entry 225 action accept
/acl cpm-filter ipv6-filter entry 235 match next-header tcp source-port value 1179 operator eq
/acl cpm-filter ipv6-filter entry 235 action accept

/interface ethernet-1/1 subinterface 0 ipv6
/interface ethernet-1/2 subinterface 0 ipv6

/interface system0 {
        admin-state enable
        subinterface 0 {
            admin-state enable
            ipv4 {
                address 100.1.0.1/32 {
                }
            }
            ipv6 {
                address 2001::6401:1/128 {
                }
            }
        }
    }


/network-instance default {
        admin-state enable
        interface ethernet-1/1.0 {
            bgp-unnumbered-peer-as external
        }
        interface ethernet-1/2.0 {
            bgp-unnumbered-peer-as external
        }
        interface system0.0 {
        }
        protocols {
            experimental-frr {
                admin-state enable
                autonomous-system 65000
                router-id 1.1.0.1
                bgp {
                    admin-state enable
                    use-ipv6-nexthops-for-ipv4 true
                    assign-static-ipv6 false
                }
            }
            bgp {
             admin-state enable
             autonomous-system 65123
             router-id 1.1.0.1
             group ibgp {
                 peer-as 65123
             }
             ipv4-unicast {
                 admin-state enable
             }
             neighbor 100.1.1.1 {
                 admin-state enable
                 peer-group ibgp
             }
            }
        }
    }
