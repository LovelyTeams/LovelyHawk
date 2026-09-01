# arena/plant-docker.sh 不在这里

这台靶机的 Docker 种植脚本是 `../docker/plant.sh`，由 `../up.mjs` 在推进虚机后
复制成 `arena/plant-docker.sh` 再构建镜像——Docker 的构建上下文出不了自己的目录，
所以只能复制，不能引用。

原来这里放着一份逐字节相同的副本。改了其中一份之后另一份没跟上，综合靶机就悄悄少了
一个容器，而探针要找的正是它。要改种植内容，改 `docker/plant.sh` 那一份。
