FROM ubuntu:22.04

# Install all build and test dependencies (shared list with .github/workflows/linux.yml).
# See tests/install-deps.sh for the full annotated list and DEPENDENCIES.md for details.
COPY install-deps.sh /tmp/install-deps.sh
RUN bash /tmp/install-deps.sh && rm -rf /var/lib/apt/lists/* /tmp/install-deps.sh

# configure.ac requires -Wbidi-chars=none, added in GCC 12.
# libasan6 (the ASAN runtime for GCC 12) is installed by install-deps.sh.
ENV CC=gcc-12

WORKDIR /src
