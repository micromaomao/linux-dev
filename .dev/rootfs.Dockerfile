FROM debian:stable

# echo ... | string replace -a ' ' \n | sort | string join ' '
RUN dpkg --add-architecture i386 && apt update && apt install -y \
    bash \
    binutils \
    bpftrace \
    curl \
    dhcpcd \
    fio \
    fish \
    g++ \
    gcc \
    gdb \
    git \
    htop \
    iproute2 \
    kitty-terminfo \
    libcap-dev \
    libcapstone-dev \
    libpfm4-dev \
    linux-perf \
    ltrace \
    make \
    net-tools \
    socat \
    ssh \
    strace \
    sysbench \
    sysstat \
    tcpdump \
    tmux \
    trace-cmd \
    vim \
    wget \
    libc6:i386 \
    libstdc++6:i386

RUN passwd -d root && chsh -s /usr/bin/fish root
# Does `usermod -d / root`, except don't complain that root is in use
RUN sed -ie 's/^\(root:x:0:0:root\):[^:]\+:\(.\+\)/\1:\/:\2/' /etc/passwd

COPY --chown=0:0 ./init.sh /init.sh
COPY --chown=0:0 ./sshd_config /etc/ssh/sshd_config
