from gyf1214/el-build-essential:8

run dnf install -y oracle-epel-release-el8 &&\
    dnf install -y traceroute tcpdump nmap-ncat iproute iputils libsodium libsodium-devel libsodium-static &&\
    dnf clean all
