#!/bin/bash
# Builds and starts one compromised lab host per distribution.
#
# Each entry names the base image, the package manager incantation that installs
# an SSH server, and the port to publish. The compromise and entrypoint scripts
# are shared, so every host carries the same artefacts and any difference in
# what LovelyRes reports comes from the distribution, not the lab.
set -u
cd "$(dirname "$0")"

# name|image|port|install command
HOSTS='
ubuntu|ubuntu:22.04|2222|apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-server sudo cron netcat-openbsd curl iproute2 procps net-tools libcap2-bin python3
debian|debian:12|2224|apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-server sudo cron netcat-openbsd curl iproute2 procps net-tools libcap2-bin python3
rocky|rockylinux/rockylinux:9|2225|dnf install -y -q openssh-server sudo crontabs nmap-ncat iproute procps-ng net-tools libcap python3 && ssh-keygen -A
alma|almalinux:9|2226|dnf install -y -q openssh-server sudo crontabs nmap-ncat iproute procps-ng net-tools libcap python3 && ssh-keygen -A
openeuler|openeuler/openeuler:22.03-lts|2227|dnf install -y -q openssh-server sudo cronie nmap-ncat iproute procps-ng net-tools libcap python3 findutils && ssh-keygen -A
anolis|openanolis/anolisos:8.8|2228|dnf install -y -q openssh-server sudo crontabs nmap-ncat iproute procps-ng net-tools libcap python3 && ssh-keygen -A
deepin|linuxdeepin/deepin:beige|2229|apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-server sudo cron netcat-openbsd curl iproute2 procps net-tools libcap2-bin python3
suse|opensuse/leap:15.5|2230|zypper -q --non-interactive install openssh-server sudo cron netcat curl iproute2 procps net-tools libcap-progs python3 && ssh-keygen -A
alpine|alpine:3.20|2223|apk add --no-cache openssh-server openssh-sftp-server bash sudo busybox-extras procps net-tools iproute2 curl shadow libcap python3 && ssh-keygen -A
'

only="${1:-}"
printf '%s\n' "$HOSTS" | while IFS='|' read -r name image port install; do
  [ -z "$name" ] && continue
  [ -n "$only" ] && [ "$only" != "$name" ] && continue
  echo "=== $name ($image) on $port ==="
  cat > "Dockerfile.$name" <<EOF
FROM $image
ENV DEBIAN_FRONTEND=noninteractive
RUN $install
RUN mkdir -p /var/run/sshd /run/sshd /root/.ssh
COPY compromise.sh /opt/compromise.sh
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/compromise.sh /opt/entrypoint.sh && /opt/compromise.sh || true
EXPOSE 22
CMD ["/opt/entrypoint.sh"]
EOF
  if docker build -q -f "Dockerfile.$name" -t "lovelyres-lab:$name" . >/dev/null 2>&1; then
    docker rm -f "lab-$name" >/dev/null 2>&1
    docker run -d --restart unless-stopped --name "lab-$name" -p "$port:22" \
      "lovelyres-lab:$name" >/dev/null 2>&1
    sleep 3
    printf '  %s\n' "$(docker inspect -f '{{.State.Status}}' "lab-$name" 2>/dev/null || echo missing)"
  else
    echo '  BUILD FAILED'
    docker build -f "Dockerfile.$name" -t "lovelyres-lab:$name" . 2>&1 | tail -5
  fi
done
