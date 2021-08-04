ARG SR_LINUX_RELEASE
FROM srl/custombase:$SR_LINUX_RELEASE

RUN sudo yum install -y python3-pyroute2

# Install FRR stable, enable BGP daemon
RUN curl https://rpm.frrouting.org/repo/frr-stable-repo-1-0.el8.noarch.rpm -o /tmp/repo.rpm && \
    sudo yum install -y /tmp/repo.rpm && \
    sudo yum install -y frr frr-pythontools && \
    sudo sed -i 's/bgpd=no/bgpd=yes/g' /etc/frr/daemons && \
    rm -f /tmp/repo.rpm

RUN sudo mkdir -p /etc/opt/srlinux/appmgr/
COPY ./appmgr/ /etc/opt/srlinux/appmgr

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_UNNUMBERED_RELEASE="[custom build]"
ENV SRL_UNNUMBERED_RELEASE=$SRL_UNNUMBERED_RELEASE
