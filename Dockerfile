from build-essential:latest

run dnf install traceroute tcpdump nmap-ncat openssl-devel &&\
    dnf clean all
