FROM debian:stable

# echo ... | string replace -a ' ' \n | sort | string join ' '
RUN dpkg --add-architecture i386 && apt update && apt install -y \
    bash binutils clang curl dhcpcd fio fish gcc gdb git htop iproute2 kitty-terminfo ltrace make net-tools ssh strace sysbench tcpdump tmux trace-cmd vim wget \
    libc6:i386 libstdc++6:i386

RUN passwd -d root && chsh -s /usr/bin/fish root

COPY --chown=0:0 ./init.sh /init.sh
COPY --chown=0:0 ./sshd_config /etc/ssh/sshd_config
