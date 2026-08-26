#!/bin/sh
# Brings every lab host back after the WSL virtual machine restarted.
#
# A WSL restart stops all containers with exit 255 and gives the machine a new
# address, so the connections in LovelyRes point at nowhere. This starts what
# already exists — no rebuild — and the caller re-imports the addresses.
set +e

started=$(docker start $(docker ps -aq --filter name=svc-) 2>/dev/null | wc -l)
intrusion=$(docker start $(docker ps -aq --filter name=lab-) 2>/dev/null | wc -l)

# sshd needs a moment before a connection will land.
sleep 5

echo "配置靶机 $(docker ps --filter name=svc- -q | wc -l)/12 在跑（本次启动 $started 台）"
echo "入侵靶机 $(docker ps --filter name=lab- -q | wc -l)/9 在跑（本次启动 $intrusion 台）"
echo "地址 $(hostname -I | awk '{print $1}')"
echo
echo "记得再跑一次 pnpm lab:import，把新地址写回连接库。"
exit 0
