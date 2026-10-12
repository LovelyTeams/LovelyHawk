# One SSH-reachable host running one service with a deliberately bad config.
#
# The service image itself is the base, so every path is the canonical one the
# real product ships with: LovelyHawk has to find /etc/nginx/nginx.conf where a
# real nginx keeps it, not where a lab decided to put it.
ARG BASE
FROM ${BASE}

ARG INSTALLER
ARG SERVICE

USER root

# sshd, and nothing else. The service is already in the base image.
RUN set -eux; \
    case "$INSTALLER" in \
      apt) \
        export DEBIAN_FRONTEND=noninteractive; \
        apt-get update -qq; \
        apt-get install -y -qq --no-install-recommends openssh-server procps sed grep >/dev/null; \
        rm -rf /var/lib/apt/lists/*; \
        ;; \
      dnf) \
        dnf install -y -q openssh-server procps-ng >/dev/null; \
        dnf clean all >/dev/null; \
        ;; \
      microdnf) \
        microdnf install -y openssh-server procps-ng >/dev/null; \
        microdnf clean all >/dev/null; \
        ;; \
      *) echo "unknown installer: $INSTALLER" >&2; exit 1;; \
    esac; \
    mkdir -p /var/run/sshd /run/sshd; \
    ssh-keygen -A; \
    printf 'root:LabRoot#2026\n' | chpasswd

# The lab exists to be logged into and inspected. This is not the baseline the
# tool checks for — the baseline files are rewritten per service below.
RUN set -eux; \
    sed -i 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config; \
    grep -q '^PermitRootLogin yes' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config; \
    sed -i 's/^[#[:space:]]*UsePAM.*/UsePAM no/' /etc/ssh/sshd_config

COPY misconfigure/${SERVICE}.sh /opt/misconfigure.sh
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/misconfigure.sh /opt/entrypoint.sh && /opt/misconfigure.sh

EXPOSE 22
ENTRYPOINT ["/opt/entrypoint.sh"]
