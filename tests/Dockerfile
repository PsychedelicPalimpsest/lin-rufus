FROM ubuntu:22.04

# Install all build and test dependencies (shared list with .github/workflows/linux.yml)
COPY install-deps.sh /tmp/install-deps.sh
RUN bash /tmp/install-deps.sh && rm -rf /var/lib/apt/lists/* /tmp/install-deps.sh

# configure.ac requires -Wbidi-chars=none, added in GCC 12
ENV CC=gcc-12

WORKDIR /src
