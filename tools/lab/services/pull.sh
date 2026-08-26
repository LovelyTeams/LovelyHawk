#!/bin/sh
# Pulls the service base images the配置基线 labs are built from.
#
# Docker Hub is not reachable from this WSL install, so everything goes through
# a mirror by name. Nothing about the daemon configuration is changed: the
# mirror is part of the image reference, and `docker tag` gives each image the
# short name the Dockerfiles use.
set -u

MIRROR="${LAB_MIRROR:-docker.m.daocloud.io}"

# <mirror path>|<local tag>
IMAGES='
library/nginx:1.27|lab-base/nginx:1.27
library/httpd:2.4|lab-base/httpd:2.4
library/tomcat:10.1-jdk17|lab-base/tomcat:10.1
library/mysql:8.0|lab-base/mysql:8.0
library/mariadb:11|lab-base/mariadb:11
library/postgres:16|lab-base/postgres:16
library/redis:7|lab-base/redis:7
library/mongo:7|lab-base/mongo:7
enmotech/opengauss:5.0.0|lab-base/opengauss:5.0.0
pingcap/tidb:v7.5.0|lab-base/tidb:v7.5.0
'

ok=0
missing=''
for row in $IMAGES; do
  remote=$(printf '%s' "$row" | cut -d'|' -f1)
  local=$(printf '%s' "$row" | cut -d'|' -f2)
  if docker image inspect "$local" >/dev/null 2>&1; then
    echo "HAVE    $local"
    ok=$((ok + 1))
    continue
  fi
  if timeout 900 docker pull "$MIRROR/$remote" >/dev/null 2>&1; then
    docker tag "$MIRROR/$remote" "$local"
    echo "PULLED  $local"
    ok=$((ok + 1))
  else
    echo "MISSING $local   (mirror has no $remote)"
    missing="$missing $local"
  fi
done

echo
echo "$ok image(s) ready."
[ -n "$missing" ] && echo "not available:$missing"
exit 0
