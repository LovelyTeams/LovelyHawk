# One machine that runs Docker workloads and a Kubernetes cluster at once.
#
# This is what a real competition box looks like: nobody hands you a host that
# only does containers and a separate one that only does Kubernetes. Having
# both here means the Docker page and the Kubernetes page are looking at the
# same SSH target, which is the case the tool has to be good at and the case
# the separate single-purpose hosts never exercise.
#
# The k3s binary comes out of the k3s image rather than off the network: the
# same single binary answers to `k3s`, `kubectl` and `crictl` depending on the
# name it is invoked by, so one copy covers the server and the client.
ARG K3S_IMAGE
FROM ${K3S_IMAGE} AS k3s

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update -qq; \
    apt-get install -y -qq --no-install-recommends \
      openssh-server \
      docker.io \
      docker-compose-v2 \
      iproute2 \
      iptables \
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
COPY --from=k3s /bin/cni /opt/k3s-bin/cni
RUN set -eux; \
    ln -s /usr/local/bin/k3s /usr/local/bin/kubectl; \
    # k3s's own image ships these; a plain Ubuntu does not, and without them
    # the kubelet never registers a node — the server comes up, the API answers,
    # and `kubectl get nodes` says "No resources found" for ever. They are all
    # one binary that dispatches on the name it was called by.
    # Every name the k3s image links to `cni`, not a guessed subset. Guessing
    # cost three rebuilds: host-local, then flannel, then bandwidth, each one
    # only surfacing after the previous fix let the sandbox get one step
    # further. A missing plugin does not fail loudly — the kubelet registers,
    # the API answers, and every pod sits in ContainerCreating for ever.
    for plugin in bandwidth bridge firewall flannel host-local loopback portmap; do \
      ln -s /opt/k3s-bin/cni "/opt/k3s-bin/$plugin"; \
    done
# Scoped to this directory rather than replacing /bin: the k3s image's /bin is
# busybox, and putting that first would quietly swap out the host's own tools.
ENV PATH="/opt/k3s-bin:${PATH}"

# Docker Hub is not reachable from here. Both runtimes need telling separately:
# the Docker daemon reads its own config, and k3s's containerd reads another.
RUN set -eux; \
    mkdir -p /etc/docker /etc/rancher/k3s; \
    printf '{"registry-mirrors":["https://docker.m.daocloud.io"]}\n' > /etc/docker/daemon.json; \
    printf 'mirrors:\n  docker.io:\n    endpoint:\n      - "https://docker.m.daocloud.io"\n' \
      > /etc/rancher/k3s/registries.yaml

COPY plant-docker.sh /opt/plant-docker.sh
COPY plant-kubernetes.sh /opt/plant-kubernetes.sh
COPY compose/ /srv/incident/
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/plant-docker.sh /opt/plant-kubernetes.sh /opt/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/opt/entrypoint.sh"]
