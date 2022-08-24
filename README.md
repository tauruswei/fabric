# Hyperledger Fabric cross-compiled for X86

## 1、docker buildx 安装
（1）下载buildx二进制文件

[https://github.com/docker/buildx/releases/](https://github.com/docker/buildx/releases/)

（2）将下载的二进制文件拷贝到 ~/.docker/cli-plugins，并命名为 docker-buildx

（3）修改权限
```bash
chmod a+x ~/.docker/cli-plugins/docker-buildx
```
(4)安装
```bash
docker buildx install
```

##2、安装qemu(用来模拟arm64)
```bash
apt install qemu-user-static
```

##3、创建docker实例（编译fabric arm image 需要）
```bash
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
docker buildx create --name multiarch --driver docker-container --use
docker buildx inspect --bootstrap
```
##4、build fabric image
```bash
rm  -f vendor 
make peer-docker-clean
make peer-docker
make orderer-docker-clean
make orderer-docker
make ccenv-docker-clean
make ccenv-docker
make baseos-docker-clean
make baseos-docker
```
