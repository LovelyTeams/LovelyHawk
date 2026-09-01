# An SSH-reachable host with kubectl pointed at the lab's k3s cluster — the
# shape of a real competition box, where you log into a jump host rather than
# onto a control-plane node.
#
# kubectl comes out of the k3s image rather than off the network: the single
# k3s binary dispatches on argv[0], so a symlink named `kubectl` is the real
# client, at exactly the version the cluster runs, with nothing to download.
ARG K3S_IMAGE
FROM ${K3S_IMAGE} AS k3s

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update -qq; \
    apt-get install -y -qq --no-install-recommends \
      openssh-server \
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

COPY --from=k3s /bin/k3s /usr/local/bin/k3s
RUN ln -s /usr/local/bin/k3s /usr/local/bin/kubectl

COPY plant.sh /opt/plant.sh
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/plant.sh /opt/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/opt/entrypoint.sh"]
