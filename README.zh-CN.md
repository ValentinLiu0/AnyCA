# AnyCA

AnyCA 是一个用 C23 编写的证书颁发机构（CA）和 OCSP 响应服务。它使用存储在
PKCS #11 HSM 中的私钥签发 X.509 v3 证书，用 SQLite 保存 CA 配置、已签发证书和
吊销记录，并通过 HTTP 提供 OCSP 响应。

## 主要功能

- **创建或接管 CA**：可以新建自签名根 CA，由程序在 HSM 中生成 CA 密钥和 OCSP
  签名密钥；也可以导入已有 CA 证书和 HSM 私钥。
- **签发证书**：根据 PKCS #10 请求签发证书，支持 RSA、ECDSA 和 ML-DSA 密钥；RSA/ECDSA
  的签名摘要算法可选 SHA-1、SHA-256、SHA-384、SHA-512（默认 SHA-384），ML-DSA
  直接对消息签名。ML-DSA 需要 PKCS #11 3.2 provider。也可以生成独立的自签名根
  证书。
- **管理 OCSP 签名证书**：`ca create` 和 `ca import` 会自动生成 OCSP 签名证书，
  之后可随时使用 `ca ocsp-renew` 续签。
- **保存签发和吊销记录**：CA 配置、证书清单和吊销记录都存放在 SQLite 数据库中；
  吊销后 OCSP 响应立即随之变化。
- **支持多个 HSM**：一个进程可以加载多个 PKCS #11 模块，CA 密钥和 OCSP 签名密钥
  可以位于不同的模块或令牌中。
- **密钥位于 HSM**：CLI 只读取公钥并请求 HSM 签名，私钥不会离开令牌。
- **发布 CRL 和 CA 证书**：服务器启动时发布 CA 证书；CLI 按需发布 DER 编码的
  CRL，服务器也可以按配置的周期自动发布。
- **动态重载配置**：CLI 修改数据库后，服务器会在下一次 OCSP 响应或 CRL 调度时
  重新加载 CA 配置，因此 `ca create`、`ca update`、`ca delete`、
  `ca ocsp-renew`、`cert record` 和 `cert revoke` 无需重启即可生效。
- **提供 OCSP 服务**：服务器在 `/ocsp/<端点>` 路径上响应 OCSP 查询，支持 HTTP
  GET 和 POST。

程序包含两个可执行文件：

| 程序           | 用途                                                                                                        |
|----------------|-------------------------------------------------------------------------------------------------------------|
| `anyca_cli`    | 管理 CA、签发和吊销证书、查看 HSM 令牌与密钥、发布 CRL                                                      |
| `anyca_server` | 加载已登记的 CA，对外提供 OCSP 响应；启动时发布 CA 证书、按配置的周期发布 CRL，并在数据库变化时自动重载配置 |

## 文档

| 文档                                                 | 内容                                                                                          |
|------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| [docs/DEPLOY.zh-cn.md](docs/DEPLOY.zh-cn.md)         | 完整部署指南，包括构建、SoftHSM 配置、新建 CA、导入已有 CA、导入私钥、systemd、备份和故障排查 |
| [docs/CLI.zh-cn.md](docs/CLI.zh-cn.md)               | CLI 完整参考：所有命令、选项、取值格式和示例                                                  |
| [docs/example/config.yaml](docs/example/config.yaml) | 带注释的配置示例                                                                              |
| [scripts/](scripts/)                                 | SoftHSM 辅助脚本                                                                              |

英文文档见 [README.md](README.md)、[docs/DEPLOY.md](docs/DEPLOY.md) 和
[docs/CLI.md](docs/CLI.md)。

## 构建

### 依赖

- CMake 4.3 或更高版本
- 支持 C23 的 GCC 或 Clang
- OpenSSL 3（开发包）
- SQLite3（开发包）
- libwebsockets（开发包）
- libyaml（开发包）

PKCS #11 3.2 头文件是来自
[latchset/pkcs11-headers](https://github.com/latchset/pkcs11-headers) 的公有领域
副本，已随仓库提供（[third_party/pkcs11/](third_party/pkcs11/)），无需安装
p11-kit。

在 Debian/Ubuntu 上可以安装：

```sh
sudo apt install build-essential cmake \
  libssl-dev libsqlite3-dev libwebsockets-dev libyaml-dev
```

在 Fedora 上可以安装：

```sh
sudo dnf install gcc make cmake \
  openssl-devel sqlite-devel libwebsockets-devel libyaml-devel
```

如果使用 SoftHSM，还需要 `softhsm2` 和 `opensc`（提供 `pkcs11-tool`），转换密钥和
证书时通常还需要 `openssl` 命令行工具。

### 编译

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

构建产物包括：

- `build/anyca_cli`
- `build/anyca_server`
- `build/libanyca_core.so`（前两个程序运行时链接的共享库）

项目没有 `install` 目标。可直接从 `build/` 目录运行；如果复制到其他目录，
需要把 `LD_LIBRARY_PATH` 指向 `libanyca_core.so` 所在目录。生产环境的部署布局
见 [docs/DEPLOY.zh-cn.md](docs/DEPLOY.zh-cn.md)。

## 快速开始

下面的步骤用于在本机执行一次最小化的冒烟测试。生产部署请按
[docs/DEPLOY.zh-cn.md](docs/DEPLOY.zh-cn.md) 操作。

前提条件：

1. 已安装 SoftHSM，并且 CLI 和服务器使用同一个 `SOFTHSM2_CONF`；
2. 已初始化一个标签为 `AnyCA`、用户 PIN 为 `1234` 的令牌。初始化方法见
   [docs/DEPLOY.zh-cn.md#14-配置并初始化-softhsm](docs/DEPLOY.zh-cn.md#14-配置并初始化-softhsm)。

准备配置和 PIN 文件：

```sh
export PATH="$PWD/build:$PATH"
cp docs/example/config.yaml config.yaml

# 按实际环境修改 store.path、hsm_providers、crl_publish_path 和
# cacerts_publish_path。相对路径按进程的当前工作目录解析。

umask 077
printf '%s' '1234' > token.pin
```

创建 CA。CA 密钥和 OCSP 签名密钥会在 URI 指定的令牌中生成，两个密钥标签在对应
令牌中均不得预先存在：

```sh
anyca_cli ca create --name root-ca \
  --key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=root-ca-key?pin-source=token.pin' \
  --ocsp-key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=root-ca-ocsp-key?pin-source=token.pin' \
  --ocsp-responder-endpoint root-ca \
  --key-type ec --ec-curve p384 \
  --crl-publish-period-min 60 --ocsp-update-period-min 10
```

发布 CRL，然后启动服务器：

```sh
anyca_cli crl publish --all
anyca_server
```

服务器监听 `config.yaml` 中 `http.address` 和 `http.port` 指定的地址与端口，
在 `/ocsp/root-ca` 提供 OCSP 响应。如果保留示例配置中的发布路径，服务器启动时
还会把 CA 证书和 CRL 写入相应目录。签发测试证书、验证 OCSP、吊销证书以及作为
systemd 服务运行的完整流程见 [docs/DEPLOY.zh-cn.md](docs/DEPLOY.zh-cn.md)。

## HSM 密钥 URI

所有 HSM 密钥都用 RFC 7512 风格的 PKCS #11 URI 指定：

```text
pkcs11:[provider=<name>;][model=<model>;][serial=<serial>;]token=<label>;object=<key-label>[?pin-value=<pin>|?pin-source=<file>]
```

- `token` 是令牌标签，`object` 是密钥对象的 `CKA_LABEL`；私钥和对应的公钥使用
  同一个标签。
- `provider` 是 AnyCA 扩展属性，用来直接引用 `hsm_providers` 中的配置项。
- 省略 `provider` 时，AnyCA 用标准的 `model` 和 `serial` 属性选择配置项。因此
  需要在 `config.yaml` 中声明这些值：

```yaml
hsm_providers:
  - name: "softhsm"
    model: "SoftHSM v2"
    serial: "3dfe48398b2b6b63"   # 可选；每个令牌唯一
    library: "/usr/lib/softhsm/libsofthsm2.so"
```

- URI 必须提供 `pin-value` 或 `pin-source`，两者只能选一个。`pin-source` 从文件
  读取 PIN，并去掉末尾的 CR/LF，可避免 PIN 出现在命令行和进程列表中。
- 属性值支持 `%XX` 百分号转义。值中的字面量 `;`、`&`、`?`、`=` 必须转义。
- 由于 `;`、`?` 和 `&` 是 Shell 元字符，URI 必须用单引号或双引号包围。

示例：

```sh
--key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-ca-key?pin-source=/etc/anyca/token.pin'
```

`provider` 不是 RFC 7512 的标准属性，而是 AnyCA 的厂商扩展。推荐在配置中声明
`model` 和 `serial`，并在 URI 中使用标准属性；`provider` 适合配置项较多或令牌
属性不易确认的场景。CA 密钥 URI 和 OCSP 签名密钥 URI 可以选择不同的 provider，
因此两把密钥可以放在不同的 PKCS #11 模块中。

AnyCA 会把 URI 中解析出的 PIN 保存到 `store.db`，所以 `store.db` 和 PIN 文件都
必须限制访问权限。

## SoftHSM 辅助脚本

[scripts/](scripts/) 中的脚本封装了 `softhsm2-util` 和 `pkcs11-tool`，默认使用
`/usr/lib/softhsm/libsofthsm2.so`；可以通过 `PKCS11_MODULE` 环境变量指定其他
模块。请在仓库根目录下执行：

| 脚本                                                             | 用法                                                               |
|------------------------------------------------------------------|--------------------------------------------------------------------|
| [scripts/softhsm-init-token.sh](scripts/softhsm-init-token.sh)   | `softhsm-init-token.sh <令牌标签> <用户PIN> <SO PIN>`              |
| [scripts/softhsm-gen-key.sh](scripts/softhsm-gen-key.sh)         | `softhsm-gen-key.sh <令牌标签> <用户PIN> <算法> <密钥标签>`        |
| [scripts/softhsm-import-key.sh](scripts/softhsm-import-key.sh)   | `softhsm-import-key.sh <令牌标签> <用户PIN> <密钥标签> <私钥文件>` |
| [scripts/softhsm-list-tokens.sh](scripts/softhsm-list-tokens.sh) | 列出已初始化令牌的标签、序列号和 PKCS #11 URI                      |
| [scripts/softhsm-list-keys.sh](scripts/softhsm-list-keys.sh)     | `softhsm-list-keys.sh <令牌标签> <用户PIN>`，列出私钥及其 URI      |

`softhsm-gen-key.sh` 支持的算法为 `RSA2048`、`RSA3072`、`RSA4096`、
`ECC-P256`、`ECC-P384` 和 `ECC-P521`。

注意：`softhsm-import-key.sh` 仅写入私钥对象，而 AnyCA 还需要同标签的公钥对象。
因此，导入已有 CA 密钥时应使用 `softhsm2-util --import`，它会一次导入完整密钥对，
详见
[docs/DEPLOY.zh-cn.md#4-将已有私钥导入-softhsm](docs/DEPLOY.zh-cn.md#4-将已有私钥导入-softhsm)。
`softhsm-list-keys.sh` 输出的 URI 不包含 PIN，传给 `anyca_cli` 前需要追加
`?pin-value=<PIN>` 或 `?pin-source=<文件>`。

命令行中的 PIN 会出现在 Shell 历史记录和进程列表中。每个脚本也可通过环境变量
提供 PIN，从而省略相应参数：

```sh
PKCS11_PIN=<用户PIN> SOFTHSM_SO_PIN=<SO PIN> scripts/softhsm-init-token.sh <令牌标签>
PKCS11_PIN=<用户PIN> scripts/softhsm-gen-key.sh <令牌标签> <算法> <密钥标签>
PKCS11_PIN=<用户PIN> scripts/softhsm-import-key.sh <令牌标签> <密钥标签> <私钥文件>
PKCS11_PIN=<用户PIN> scripts/softhsm-list-keys.sh <令牌标签>
```

`softhsm2-util` 和 `pkcs11-tool` 仍会以参数形式接收 PIN，因此 PIN 仍会短暂出现在
进程列表中；只有 `softhsm-list-tokens.sh` 不需要 PIN。

## 启动校验与动态刷新

服务器启动时会逐一处理存储中的 CA 配置：

- 检查 CA 证书可以解析，并且是 CA 证书；
- 检查 OCSP 签名证书当前有效，并且要么就是 CA 证书本身，要么由该 CA 直接签发
  并包含 OCSPSigning 扩展密钥用途；
- 打开两个令牌，检查 CA 密钥和 OCSP 签名密钥分别与对应证书匹配；
- 在存储中登记 CA 的当前身份（名称与公钥哈希）。

任一项检查失败时，服务器会记录错误并跳过该 CA，其余 CA 继续启动。`ca import` 和
`ca create` 在写入配置前也会执行同类校验，失败时不会留下无效的 CA 配置。

运行中的服务器还会在 CLI 修改存储后重新加载 CA 配置：每次生成 OCSP 响应前和
每个 CRL 调度周期都会检查。新增、修改和删除的 CA 无需重启即可生效；如果修改后
的配置校验失败，服务器会继续使用该 CA 之前的配置。

## 外部库

| 库                              | 许可证        |
|---------------------------------|---------------|
| OpenSSL                         | Apache-2.0    |
| SQLite                          | Public Domain |
| libwebsockets                   | LGPL-2.1      |
| PKCS #11 3.2 头文件（公有领域） | Public Domain |
| libyaml                         | MIT           |

构建工具：CMake（BSD-3-Clause）。
