from gyf1214/el-build-essential:8

ARG CJSON_VERSION=1.7.18

run dnf install -y oracle-epel-release-el8 &&\
    dnf install -y traceroute tcpdump nmap-ncat iproute iputils libsodium libsodium-devel libsodium-static &&\
    dnf clean all && rm -rf /var/cache/dnf

run set -eux; \
    curl -fsSL -o /tmp/cjson.tar.gz \
      "https://github.com/DaveGamble/cJSON/archive/refs/tags/v${CJSON_VERSION}.tar.gz"; \
    tar -xzf /tmp/cjson.tar.gz -C /tmp; \
    cmake -S "/tmp/cJSON-${CJSON_VERSION}" -B /tmp/cjson-build \
      -DBUILD_SHARED_LIBS=OFF \
      -DBUILD_SHARED_AND_STATIC_LIBS=OFF \
      -DENABLE_CJSON_TEST=OFF \
      -DENABLE_CJSON_UTILS=OFF \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DCMAKE_INSTALL_LIBDIR=lib64; \
    cmake --build /tmp/cjson-build -j; \
    cmake --install /tmp/cjson-build; \
    test -f /usr/lib64/libcjson.a; \
    rm -rf /tmp/cjson.tar.gz /tmp/cJSON-* /tmp/cjson-build
