# An SSH-reachable host that runs Podman and has no `docker` at all.
#
# This is the shape of most RHEL-family and domestic-distro machines —
# openEuler, Anolis, AlmaLinux, Rocky all ship Podman and none of them ship
# Docker. Every question the tool asked with `docker` came back empty on hosts
# like this, which looks like an answer and is not one.
#
# AlmaLinux rather than Ubuntu on purpose: Podman from apt is old and behaves
# differently, and the point of this host is to be the machine the tool will
# actually meet.
FROM almalinux:9

RUN set -eux; \
    dnf install -y -q openssh-server podman iproute procps-ng >/dev/null; \
    dnf clean all >/dev/null; \
    ssh-keygen -A; \
    printf 'root:LabRoot#2026\n' | chpasswd; \
    sed -i 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config; \
    grep -q '^PermitRootLogin yes' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config; \
    sed -i 's/^[#[:space:]]*UsePAM.*/UsePAM no/' /etc/ssh/sshd_config

# Docker Hub is not reachable from here, so Podman is pointed at the same
# mirror. Without this the plant script comes up with nothing.
RUN mkdir -p /etc/containers && \
    printf 'unqualified-search-registries = ["docker.m.daocloud.io"]\n\n[[registry]]\nprefix = "docker.io"\nlocation = "docker.m.daocloud.io"\n' \
      > /etc/containers/registries.conf

# There must be no `docker` on this host. A shim would make the lab prove the
# wrong thing: the point is that the tool finds Podman on its own.
RUN test ! -e /usr/bin/docker

COPY plant.sh /opt/plant.sh
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/plant.sh /opt/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/opt/entrypoint.sh"]
