#!/bin/sh
# Brings every lab host back after the WSL virtual machine restarted.
#
# A WSL restart stops all containers with exit 255 and gives the machine a new
# address, so the connections in LovelyHawk point at nowhere. This starts what
# already exists — no rebuild — and the caller re-imports the addresses.
set +e

started=$(docker start $(docker ps -aq --filter name=svc-) 2>/dev/null | wc -l)
intrusion=$(docker start $(docker ps -aq --filter name=lab-) 2>/dev/null | wc -l)

# sshd needs a moment before a connection will land.
sleep 5

# Compare against what exists rather than a number written here: this script
# gets a new host every time the lab grows, and a hardcoded total quietly turns
# into a lie that reads as "两台没起来".
echo "svc- 靶机 $(docker ps --filter name=svc- -q | wc -l)/$(docker ps -aq --filter name=svc- | wc -l) 在跑（本次启动 $started 台）"
echo "lab- 靶机 $(docker ps --filter name=lab- -q | wc -l)/$(docker ps -aq --filter name=lab- | wc -l) 在跑（本次启动 $intrusion 台）"
echo "地址 $(hostname -I | awk '{print $1}')"
echo
echo "pnpm lab:restart 会顺带刷新连接库；单独跑这个脚本的话，记得补一次 pnpm lab:import。"
exit 0
