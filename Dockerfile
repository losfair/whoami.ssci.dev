FROM debian:bullseye

RUN apt-get update && apt-get install -y openssh-server net-tools htop curl && \
    useradd -p '*' -u 1000 user && mkdir -p /home/user/.ssh && chown -R user:user /home/user

COPY ./sshd_config /opt/sshd/sshd_config
COPY --chmod=755 ./enclave-rpc/enclave-rpc /
COPY --chmod=755 ./start.sh /
COPY --chmod=755 ./whoami.ssci.dev /

CMD ["/start.sh"]
