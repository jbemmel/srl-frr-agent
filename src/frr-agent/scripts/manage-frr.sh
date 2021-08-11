#!/bin/bash

#
# Minimalistic configuration script for Proof-of-Concept purposes.
# Aims to configure the simplest possible FRR config that works
#

# set -x # debug

# Always set
echo "enabled_daemons='${enabled_daemons}' network_instance=${network_instance}"
echo "Linux NETNS=${NETNS}"
echo $admin_state

# May not be set if $admin_state=="disable"
echo $autonomous_system
echo $router_id
echo $bgp_neighbor_lines
echo $eigrp

# NETNS="srbase-${network_instance}" # now set in Python
DIR="/etc/frr/${NETNS}"

/usr/bin/sudo -E bash << EOFSUDO
if [[ "${admin_state}" == "enable" ]]; then
mkdir -p "${DIR}" && cp -f /etc/frr/daemons ${DIR} && \
 echo "watchfrr_options=\"--netns=${NETNS}\"" >> "${DIR}/daemons" && \
 echo "frr_profile=\"datacenter\"" >> "${DIR}/daemons"

for daemon in ${enabled_daemons}; do
 echo "Enabling daemon '\${daemon}' in network-instance ${network_instance}..."
 sed -i "s/^\${daemon}=no/\${daemon}=yes/g" "${DIR}/daemons"
done

if [[ "$openfabric" == "enable" ]]; then

if [[ "$openfabric_domain_password" != "" ]]; then
DOMAIN_PASSWORD=" domain-password md5 $openfabric_domain_password"
fi
if [[ "$openfabric_fabric_tier" != "" ]]; then
FABRIC_TIER=" fabric-tier $openfabric_fabric_tier"
fi
IFS='' read -r -d '' OPENFABRIC_CONFIG << EOF
${openfabric_interface_lines}
!
router openfabric $openfabric_name
 net $openfabric_net
\$DOMAIN_PASSWORD
\$FABRIC_TIER
EOF
fi

if [[ "$eigrp" == "enable" ]]; then
IFS='' read -r -d '' EIGRP_CONFIG << EOF
router eigrp $autonomous_system
 eigrp router-id $router_id
 # Enable on all interfaces
 network 0.0.0.0/0
 maximum-paths 4
 # Exclude internal SR Linux interface
 passive-interface gateway

 # TODO: add static neighbor statements through Yang?
EOF
else
EIGRP_CONFIG="no router eigrp $autonomous_system"
fi

if [[ "$bgp" == "enable" ]]; then
IFS='' read -r -d '' BGP_CONFIG << EOF
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
EOF
else
BGP_CONFIG="no router bgp $autonomous_system"
fi

cat > "$DIR/frr.conf" << EOF
frr defaults datacenter
log syslog informational
ipv6 forwarding
service integrated-vtysh-config
!
!
\${EIGRP_CONFIG}
!
\${BGP_CONFIG}
!
\${OPENFABRIC_CONFIG}
!
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
