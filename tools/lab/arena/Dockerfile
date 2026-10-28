# One Ubuntu server with several services on it, the way a competition box
# actually looks — rather than twelve containers each holding one product.
#
# Fewer moving parts to keep alive, and every LovelyHawk page has something to
# find on the same host: middleware, databases, the six baseline files, and a
# handful of intrusion artefacts.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update -qq; \
    apt-get install -y -qq --no-install-recommends \
      openssh-server \
      nginx \
      mariadb-server \
      redis-server \
      postgresql \
      cron \
      rsyslog \
      curl \
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

COPY misconfigure.sh /opt/misconfigure.sh
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/misconfigure.sh /opt/entrypoint.sh && /opt/misconfigure.sh

EXPOSE 22 80 3306 5432 6379
ENTRYPOINT ["/opt/entrypoint.sh"]
