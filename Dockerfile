ARG SR_LINUX_RELEASE
FROM srl/custombase:$SR_LINUX_RELEASE AS target

RUN sudo yum install -y python3-pyroute2

# Build FRR with  support for non-default BGP ports for unnumbered interfaces
# Use separate build image and copy only resulting binaries, else 3.4GB
FROM centos:8 AS build-frr-with-flexible-ports

# Install build tools, frr-stable is for libyang2-devel
# TODO --enable-protobuf --enable-grpc protobuf-c-devel
RUN curl -O https://rpm.frrouting.org/repo/frr-stable-repo-1-0.el8.noarch.rpm && \
  yum localinstall -y frr-stable-repo-1-0.el8.noarch.rpm && \
  dnf -y group install "Development Tools" && \
  yum config-manager --set-enabled powertools && \
  dnf install -y --enablerepo=powertools git autoconf pcre-devel \
  automake libtool make readline-devel texinfo net-snmp-devel pkgconfig \
  groff pkgconfig json-c-devel pam-devel bison flex python2-pytest \
  c-ares-devel python2-devel libcap-devel libyang2-devel \
  elfutils-libelf-devel && \
    git clone --branch stable/8.0 https://github.com/exergy-connect/frr.git && \
    cd frr && \
    ./bootstrap.sh && \
    ./configure --disable-ripd --disable-ripngd --disable-ospfd --disable-ospf6d \
      --disable-ldpd --disable-nhrpd  --disable-babeld --disable-isisd \
      --disable-pimd --disable-pbrd --disable-staticd --disable-vrrpd --disable-pathd && \
    make -j && make install

FROM target AS final-image

# Install FRR stable, enable BGP daemon
# frr-stable or frr-8 or frr-7
#    sudo sed -i 's|el8/frr8|el8/frr8.freeze|g' /etc/yum.repos.d/frr-8.repo && \
#RUN curl https://rpm.frrouting.org/repo/frr-8-repo-1-0.el8.noarch.rpm -o /tmp/repo.rpm && \
#    sudo yum install -y /tmp/repo.rpm && \
#    sudo yum install -y frr frr-pythontools && \
#    sudo chmod 644 /etc/frr/daemons && \
#    rm -f /tmp/repo.rpm && sudo yum clean all -y

# Add custom FRR build
COPY --from=build-frr-with-flexible-ports /usr/local/ /usr/local/

# Allow provisioning of link-local IPs on interfaces, exclude gateway subnet?
# Issue is that these addresses do not get installed as next hop in the RT
# RUN sudo sed -i.orig "s/'169.254.'/'169.254.1.'/g" /opt/srlinux/models/srl_nokia/models/interfaces/srl_nokia-if-ip.yang

# Define custom alias for accessing vtysh in some namespace
RUN sudo mkdir -p /home/admin && printf '%s\n' \
  '"vtysh network-instance" = "bash /usr/bin/sudo /usr/bin/vtysh --vty_socket /var/run/frr/srbase-{}/"' \
  \
>> /home/admin/.srlinuxrc

RUN sudo mkdir -p /etc/opt/srlinux/appmgr/ /opt/srlinux/agents/frr-agent
COPY --chown=srlinux:srlinux ./srl-frr-agent.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/srlinux/agents/

# run pylint to catch any obvious errors
RUN PYTHONPATH=$AGENT_PYTHONPATH pylint --load-plugins=pylint_protobuf -E /opt/srlinux/agents/frr-agent

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_UNNUMBERED_RELEASE="[custom build]"
ENV SRL_UNNUMBERED_RELEASE=$SRL_UNNUMBERED_RELEASE
