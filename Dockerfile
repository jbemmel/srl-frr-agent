ARG SR_LINUX_RELEASE
FROM srl/custombase:$SR_LINUX_RELEASE

RUN sudo yum install -y python3-pyroute2

# Install FRR stable, enable BGP daemon
# frr-stable or frr-8 or frr-7
RUN curl https://rpm.frrouting.org/repo/frr-7-repo-1-0.el8.noarch.rpm -o /tmp/repo.rpm && \
    sudo yum install -y /tmp/repo.rpm && \
    sudo yum install -y frr frr-pythontools && \
    sudo sed -i 's/bgpd=no/bgpd=yes/g' /etc/frr/daemons && \
    sudo chmod 644 /etc/frr/daemons && \
    rm -f /tmp/repo.rpm && sudo yum clean all -y

# Allow provisioning of link-local IPs on interfaces, exclude gateway subnet?
# Issue is that these addresses do not get installed as next hop in the RT
# RUN sudo sed -i.orig "s/'169.254.'/'169.254.1.'/g" /opt/srlinux/models/srl_nokia/models/interfaces/srl_nokia-if-ip.yang

RUN sudo mkdir -p /etc/opt/srlinux/appmgr/ /opt/srlinux/agents/frr-agent
COPY ./srl-frr-agent.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/srlinux/agents/

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_UNNUMBERED_RELEASE="[custom build]"
ENV SRL_UNNUMBERED_RELEASE=$SRL_UNNUMBERED_RELEASE
