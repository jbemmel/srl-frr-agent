LAST_COMMIT := $(shell sh -c "git log -1 --pretty=%h")
TODAY       := $(shell sh -c "date +%Y%m%d_%H%M")
TAG         := ${TODAY}.${LAST_COMMIT}
# HTTP_PROXY  := "http://proxy.lbs.alcatel-lucent.com:8000"

ifndef SR_LINUX_RELEASE
override SR_LINUX_RELEASE="latest"
endif

.PHONY: build build-combined do-build frr build-srlinux

build: BASEIMG=srl/custombase
build: NAME=srl/bgp-unnumbered-using-frr
build: do-build

do-build:
	sudo DOCKER_BUILDKIT=1 docker build --build-arg SRL_UNNUMBERED_RELEASE=${TAG} \
	                  --build-arg http_proxy=${HTTP_PROXY} \
										--build-arg https_proxy=${HTTP_PROXY} \
										--build-arg SR_BASEIMG="${BASEIMG}" \
	                  --build-arg SR_LINUX_RELEASE="${SR_LINUX_RELEASE}" \
	                  -f ./Dockerfile -t ${NAME}:${TAG} .
	sudo docker tag ${NAME}:${TAG} ${NAME}:latest

# Build FRR with  support for non-default BGP ports for unnumbered interfaces
# Produces ./docker/centos-8/pkgs/x86_64/frr-8.0_git<xxx>.el8.x86_64.rpm
# TODO could disable daemons that are not used/needed
frr:
	git clone --branch stable/8.0 https://github.com/exergy-connect/frr.git && \
	cd frr && \
	sudo DOCKER_BUILDKIT=1 docker/centos-8/build.sh

build-srlinux: BASEIMG=ghcr.io/nokia/srlinux
build-srlinux: NAME=srl/bgp-unnumbered-using-frr
build-srlinux: do-build

#
# This works but is more cumbersome, it rebuilds image every time base changes
#
# build-auto-frr: BASEIMG=srl/auto-config-v2
# build-auto-frr:	NAME=srl/auto-frr-demo
# build-auto-frr: do-build
