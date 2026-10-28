# The "super" arena: one Ubuntu host wrong in every way the ordinary arena is,
# and then some. It exists so every LovelyHawk page has a rich, real finding to
# show on a single SSH target — host overview, the six system baselines, the
# middleware and database baselines, command audit, file integrity, log
# analysis, packet capture, accounts and persistence.
#
# It reuses the committed arena misconfigure.sh unchanged and adds one more
# layer (misconfigure-super.sh) on top. Nothing here is novel: each item is an
# everyday misconfiguration or the trace of someone who found the box that way
# first, and every "callback" points at TEST-NET (198.51.100.0/24), which does
# not route, so the box never actually reaches anything.
#
# Build context is tools/lab so this can COPY arena/misconfigure.sh.
#   docker build -f tools/lab/super/Dockerfile -t lovelyres-lab:super tools/lab
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update -qq; \
    apt-get install -y -qq --no-install-recommends \
      openssh-server \
      nginx \
      apache2 \
      mariadb-server \
      redis-server \
      postgresql \
      vsftpd \
      cron \
      at \
      rsyslog \
      curl \
      socat \
      libcap2-bin \
      acl \
      net-tools \
      iproute2 \
      procps \
      psmisc \
      sudo \
      vim-tiny \
      >/dev/null; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /var/run/sshd /run/sshd; \
    ssh-keygen -A; \
    printf 'root:LabRoot#2026\n' | chpasswd

COPY arena/misconfigure.sh /opt/misconfigure.sh
COPY super/misconfigure-super.sh /opt/misconfigure-super.sh
COPY super/entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/misconfigure.sh /opt/misconfigure-super.sh /opt/entrypoint.sh; \
    /opt/misconfigure.sh; \
    /opt/misconfigure-super.sh

EXPOSE 22 21 80 443 3306 5432 6379 8080
ENTRYPOINT ["/opt/entrypoint.sh"]
