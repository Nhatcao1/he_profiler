FROM ubuntu:22.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        python3 \
        sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/server

CMD ["bash"]
