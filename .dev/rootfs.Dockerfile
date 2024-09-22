FROM debian:sid

# echo ... | string replace -a ' ' \n | sort | string join ' '
RUN apt update && apt install -y \
    bash curl dhcpcd fish gdb git htop iproute2 kitty-terminfo ltrace make net-tools ssh strace tcpdump tmux trace-cmd vim wget

RUN passwd -d root && chsh -s /usr/bin/fish root

COPY --chown=0:0 ./init.sh /init.sh
COPY --chown=0:0 ./sshd_config /etc/ssh/sshd_config
