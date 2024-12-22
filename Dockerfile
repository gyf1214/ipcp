from build-essential:latest

run dnf install -y oracle-epel-release-el8 &&\
    dnf install -y traceroute tcpdump nmap-ncat libsodium libsodium-devel libsodium-static &&\
    dnf clean all
