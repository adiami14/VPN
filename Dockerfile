FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
    net-tools \
    nano \
    nmap \
    dnsutils \
    iputils-ping \
    tcpdump \
    iproute2 \
    openssh-client \
    iptables \
    gcc

CMD ["bash"]

