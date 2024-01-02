from build-essential:latest

run apt-get update && apt-get install -yq \
    iproute2 uml-utilities tcpdump iputils-ping netcat inetutils-traceroute &&\
    apt-get clean &&\
    rm -fr /var/lib/apt/lists/*
