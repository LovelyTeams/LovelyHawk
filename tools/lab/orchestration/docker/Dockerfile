# An SSH-reachable host that runs its own Docker daemon.
#
# The daemon is the host's own, not the lab machine's: LovelyHawk gets a real
# `docker ps`, real images, networks and volumes, and — the point of this host
# — containers deliberately started the way an audit is supposed to complain
# about. Sharing the lab machine's socket instead would have worked for reading,
# but every mutation the tool later grows would then act on the lab itself.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update -qq; \
    apt-get install -y -qq --no-install-recommends \
      openssh-server \
      docker.io \
      docker-compose-v2 \
      iproute2 \
      procps \
      curl \
      ca-certificates \
      >/dev/null; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /var/run/sshd /run/sshd; \
    ssh-keygen -A; \
    printf 'root:LabRoot#2026\n' | chpasswd; \
    sed -i 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config; \
    grep -q '^PermitRootLogin yes' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config; \
    sed -i 's/^[#[:space:]]*UsePAM.*/UsePAM no/' /etc/ssh/sshd_config

# Docker Hub is not reachable from here, so the inner daemon is pointed at the
# same mirror the outer one uses. Without this every `docker run` below hangs
# until it times out and the host comes up with an empty daemon.
RUN mkdir -p /etc/docker && \
    printf '{"registry-mirrors":["https://docker.m.daocloud.io"]}\n' > /etc/docker/daemon.json

COPY plant.sh /opt/plant.sh
COPY compose/ /srv/incident/
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/plant.sh /opt/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/opt/entrypoint.sh"]
