ARG SR_BASEIMG
ARG SR_LINUX_RELEASE

# FROM srl/custombase:$SR_LINUX_RELEASE AS target
FROM $SR_BASEIMG:$SR_LINUX_RELEASE AS target

# Create a Python virtual environment, note --upgrade is broken
RUN sudo python3 -m venv /opt/demo-agents/frr-agent/.venv --system-site-packages --without-pip
ENV VIRTUAL_ENV=/opt/demo-agents/frr-agent/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# RUN sudo yum update --best --allowerasing && sudo yum install -y python3-pyroute2.noarch
RUN sudo $VIRTUAL_ENV/bin/python3 -m pip install --upgrade pyroute2 pyroute2-ipdb grpcio
ENV AGENT_PYTHONPATH="$VIRTUAL_ENV/lib/python3.6/site-packages:$AGENT_PYTHONPATH"

# Install FRR stable, enable BGP daemon
# frr-stable or frr-8 or frr-7
#    sudo sed -i 's|el8/frr8|el8/frr8.freeze|g' /etc/yum.repos.d/frr-8.repo && \
#RUN curl https://rpm.frrouting.org/repo/frr-8-repo-1-0.el8.noarch.rpm -o /tmp/repo.rpm && \
#    sudo yum install -y /tmp/repo.rpm && \
#    sudo yum install -y frr frr-pythontools && \
#    sudo chmod 644 /etc/frr/daemons && \
#    rm -f /tmp/repo.rpm && sudo yum clean all -y

# Add custom FRR build
RUN sudo yum install -y https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-8-x86_64-Packages/libyang2-2.0.0.10.g2eb910e4-1.el8.x86_64.rpm \
    https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-110/CentOS-7-x86_64-Packages/librtr-0.7.0-1.el7.centos.x86_64.rpm

COPY frr/docker/centos-8/pkgs/x86_64/frr-8.*_git*.el8.x86_64.rpm /tmp/frr8.rpm

RUN sudo yum install -y /tmp/frr8.rpm \
    && sudo rm -rf /tmp/frr8.rpm

# Allow provisioning of link-local IPs on interfaces, exclude gateway subnet?
# Issue is that these addresses do not get installed as next hop in the RT
# RUN sudo sed -i.orig "s/'169.254.'/'169.254.1.'/g" /opt/srlinux/models/srl_nokia/models/interfaces/srl_nokia-if-ip.yang

# Define custom alias for accessing vtysh in some namespace
RUN sudo mkdir -p /home/admin && printf '%s\n' \
  '"vtysh {network-instance}" = "bash /usr/bin/sudo /usr/bin/vtysh --vty_socket /var/run/frr/srbase-{}/"' \
  \
 >> /home/admin/.srlinuxrc

RUN sudo mkdir --mode=0755 -p /etc/opt/srlinux/appmgr/ /opt/demo-agents/frr-agent
COPY --chown=srlinux:srlinux ./srl-frr-agent.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/demo-agents/

# Add in auto-config agent sources too
COPY --from=srl/auto-config-v2:latest /opt/demo-agents/auto-config-agent/ /opt/demo-agents/auto-config-agent/

# Stop BGP mgr from crashing (change jump location to ignore "bad" ipv4 prefix)
# Find offset: LANG=C grep -obUaP "\x75\x43\x48\x85\xc9\x0f\x84\xd2\x00\x00\x00" /opt/srlinux/bin/sr_bgp_mgr => 6751939 + 7 = 6751946
# Change jump to what looks like a 4-byte ipv4 case? nope
# RUN printf '\x6e' | sudo dd of=/opt/srlinux/bin/sr_bgp_mgr bs=1 seek=6751946 count=1 conv=notrunc
# Remove ipv4 processing, jump to v6 instead? nope
# RUN printf '\x90\x90\x90\x90\x90\x90' | sudo dd of=/opt/srlinux/bin/sr_bgp_mgr bs=1 seek=7565980 count=6 conv=notrunc

# Modify BGP mgr config to auto-restart when crashed, endless
# RUN sudo sed -i.orig -E '4 i \   failure-threshold: 20\n   failure-action: wait=5' /opt/srlinux/appmgr/sr_bgp_mgr_config.yml

# run pylint to catch any obvious errors
RUN PYTHONPATH=$AGENT_PYTHONPATH pylint --load-plugins=pylint_protobuf -E /opt/demo-agents/frr-agent

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_UNNUMBERED_RELEASE="[custom build]"
ENV SRL_UNNUMBERED_RELEASE=$SRL_UNNUMBERED_RELEASE
