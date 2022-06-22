# This file is part of SymCC.
#
# SymCC is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# SymCC is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# SymCC. If not, see <https://www.gnu.org/licenses/>.

#
# The base image
#
FROM ubuntu:20.10 AS builder

# Install dependencies
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        cargo \
        clang-11 \
        cmake \
        g++ \
        git \
        libz3-dev \
        llvm-11-dev \
        llvm-11-tools \
        ninja-build \
        python2 \
        python3-pip \
        zlib1g-dev \
        libsystemd-dev \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install lit

# Download the LLVM sources already so that we don't need to get them again when
# SymCC changes
RUN git clone -b llvmorg-11.0.1 --depth 1 https://github.com/llvm/llvm-project.git /llvm_source

# Build a version of SymCC with the simple backend to compile libc++
COPY . /symcc_source

# Init submodules if they are not initialiazed yet
WORKDIR /symcc_source
RUN if git submodule status | grep "^-">/dev/null ; then \
    echo "Initializing submodules"; \
    git submodule init; \
    git submodule update; \
    fi


#
# Build SymCC with the simple backend
#
FROM builder AS builder_simple
WORKDIR /symcc_build
RUN cmake -G Ninja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DZ3_TRUST_SYSTEM_VERSION=on \
        /symcc_source \
    && ninja check

#
# Build libc++ with SymCC using the simple backend
#
FROM builder_simple AS builder_libcxx
WORKDIR /libcxx_symcc
RUN export SYMCC_REGULAR_LIBCXX=yes SYMCC_NO_SYMBOLIC_INPUT=yes \
  && mkdir /libcxx_symcc_build \
  && cd /libcxx_symcc_build \
  && cmake -G Ninja /llvm_source/llvm \
  -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi" \
  -DLLVM_TARGETS_TO_BUILD="X86" \
  -DLLVM_DISTRIBUTION_COMPONENTS="cxx;cxxabi;cxx-headers" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/libcxx_symcc_install \
  -DCMAKE_C_COMPILER=/symcc_build/symcc \
  -DCMAKE_CXX_COMPILER=/symcc_build/sym++ \
  && ninja distribution \
  && ninja install-distribution

#
# The final image
#
FROM ubuntu:20.10

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential \
        clang-11 \
        g++ \
        libllvm11 \
        zlib1g \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash ubuntu \
    && echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ubuntu

COPY --from=builder_simple /symcc_build /symcc_build
COPY --from=builder_simple /root/.cargo/bin/symcc_fuzzing_helper /symcc_build/
COPY util/pure_concolic_execution.sh /symcc_build/
COPY --from=builder_libcxx /libcxx_symcc_install /libcxx_symcc_install


ENV PATH /symcc_build:$PATH
ENV SYMCC_LIBCXX_PATH=/libcxx_symcc_install

USER ubuntu
WORKDIR /home/ubuntu
COPY sample.cpp /home/ubuntu/
RUN mkdir /tmp/output
