# x86-64 Linux container for dynamic analysis
# Runs on ARM Mac via QEMU emulation
FROM --platform=linux/amd64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install debugging and analysis tools
RUN apt-get update && apt-get install -y \
    # Core debugging
    gdb \
    gdbserver \
    strace \
    ltrace \
    # Binary analysis
    file \
    binutils \
    elfutils \
    patchelf \
    upx-ucl \
    # Development tools
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    cmake \
    # Networking
    curl \
    wget \
    netcat-openbsd \
    socat \
    # Utilities
    tmux \
    vim \
    jq \
    bc \
    # Multi-architecture support via QEMU userspace emulation
    qemu-user-static \
    qemu-user \
    # Cross-architecture libraries
    libc6-arm64-cross \
    libc6-armhf-cross \
    libc6-mips64el-cross \
    libc6-mipsel-cross \
    # Binary analysis tools
    binwalk \
    xxd \
    hexedit \
    # Additional tools for RE competitions
    nasm \
    radare2 \
    && rm -rf /var/lib/apt/lists/*

# Install GEF (GDB Enhanced Features) - do this BEFORE network isolation
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)" || true

# Install Python tools for exploit dev and reverse engineering
RUN pip3 install --no-cache-dir \
    flask \
    pwntools \
    capstone \
    keystone-engine \
    unicorn \
    # ELF/binary analysis
    pyelftools \
    lief \
    # Crypto libraries
    pycryptodome \
    # ROP gadget finding
    ropper \
    ROPGadget \
    # Frida instrumentation
    frida-tools \
    # Symbolic execution / constraint solving
    z3-solver \
    # Additional analysis
    angr \
    archinfo \
    # Hex/byte manipulation
    hexdump

# Create non-root user for safer execution
RUN useradd -m -s /bin/bash analyst && \
    mkdir -p /analysis/bins && \
    mkdir -p /analysis/logs && \
    mkdir -p /analysis/frida_scripts && \
    chown -R analyst:analyst /analysis

WORKDIR /analysis

# Copy the GDB API server
COPY gdb_server.py /analysis/gdb_server.py
RUN chown analyst:analyst /analysis/gdb_server.py

# Expose ports:
# 5000 - HTTP API for GDB commands
# 1234 - gdbserver remote debugging
# 27042 - Frida server
EXPOSE 5000 1234 27042

# Note: Running as root for now because GDB/strace need elevated privileges
# For maximum security, uncomment USER line and use sudo where needed
# USER analyst

# Default command - run the API server
CMD ["python3", "/analysis/gdb_server.py"]
