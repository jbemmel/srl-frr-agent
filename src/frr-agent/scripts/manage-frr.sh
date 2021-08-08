#!/bin/bash

#
# Minimalistic configuration script for Proof-of-Concept purposes.
# Aims to configure the simplest possible FRR config that works
#

# set -x # debug

# Always set
echo "enabled_daemons='${enabled_daemons}' network_instance=${network_instance}"
echo $admin_state

# May not be set if $admin_state=="disable"
echo $autonomous_system
echo $router_id
echo $bgp_neighbor_lines
echo $eigrp

NETNS="srbase-${network_instance}"
DIR="/etc/frr/${NETNS}"

/usr/bin/sudo -E bash << EOFSUDO
if [[ "${admin_state}" == "enable" ]]; then
mkdir -p "${DIR}" && cp -f /etc/frr/daemons ${DIR} && \
 echo "watchfrr_options=\"--netns=${NETNS}\"" >> "${DIR}/daemons"

for daemon in ${enabled_daemons}; do
 echo "Enabling daemon '\${daemon}' in network-instance ${network_instance}..."
 sed -i "s/^\${daemon}=no/\${daemon}=yes/g" "${DIR}/daemons"
done

if [[ "eigrp" == "enable" ]]; then
EIGRP="router eigrp $autonomous_system"
fi

cat > $DIR/frr.conf << EOF
frr defaults datacenter
log syslog informational
ipv6 forwarding
service integrated-vtysh-config
!
!
router bgp $autonomous_system
 bgp router-id $router_id
 # Disable RFC8212 compliance, turned off by default for datacenter case
 no bgp ebgp-requires-policy
 ! Avoid having to activate ipv6 for each neighbor/group separately
 bgp default ipv6-unicast
 ! Only applies when there are 'networks' statements
 ! no bgp network import-check

 ! It's possible to define peer groups for scaling, not currently used
 ! neighbor V4 peer-group

 ! Blob of configured interfaces for this network-instance, provided by Python
 ! Each line looks like this:
 ! neighbor e1-1.0 interface remote-as [peer-as]
 ${bgp_neighbor_lines}

 !
 address-family ipv4 unicast
  redistribute connected
 exit-address-family
 !
 address-family ipv6 unicast
  redistribute connected
 exit-address-family
 !
\${EIGRP}
line vty
!
EOF
chown -R frr:frr "${DIR}"
/usr/lib/frr/frrinit.sh restart ${NETNS}
else
/usr/lib/frr/frrinit.sh stop ${NETNS}
rm -rf "$DIR"
fi

EOFSUDO

exit $?
