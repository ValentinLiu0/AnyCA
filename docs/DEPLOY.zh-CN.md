# 部署指南

本指南从一台全新的 Linux 主机开始，介绍如何部署 AnyCA OCSP 响应服务。内容覆盖两种
常见场景：

- **新建 CA**：AnyCA 生成 CA 密钥对、自签名 CA 证书、OCSP 签名密钥对和 OCSP
  签名证书。
- **已有 CA**：CA 证书和私钥已存在。先把 CA 私钥导入 SoftHSM，再准备 OCSP
  签名密钥，最后用 `ca import` 登记。

另有一节专门介绍
[将已有私钥导入 SoftHSM](#4-将已有私钥导入-softhsm)，适用于 CA 密钥、OCSP
签名密钥以及其他需要交给 AnyCA 使用的密钥。

所有命令行选项的完整说明见 [CLI.zh-cn.md](CLI.zh-cn.md)，带注释的配置示例见
[example/config.yaml](example/config.yaml)。

本指南使用 Bash、专用服务账户 `anyca` 和安装前缀 `/opt/anyca`。请按实际环境
替换名称和路径。

> **路径规则**：`config.yaml` 中的相对路径（包括 `store.path`、
> `crl_publish_path`、`cacerts_publish_path`）以及命令行中的相对路径，均相对于
> **进程的当前工作目录**解析，而不是相对于配置文件所在目录。生产配置请使用
> 绝对路径。

## 部署流程一览

| 步骤                 | 新建 CA                  | 已有 CA                  |
|----------------------|--------------------------|--------------------------|
| 准备主机、账户和目录 | 第 1 节                  | 第 1 节                  |
| 配置并初始化 SoftHSM | 第 1.4 节                | 第 1.4 节                |
| 导入 CA 私钥         | 不需要                   | 第 3.2、4 节             |
| 创建/登记 CA         | `ca create`（第 2.1 节） | `ca import`（第 3.4 节） |
| 发布 CRL             | 第 2.3 节                | 第 3.5 节                |
| 验证 OCSP            | 第 2.5 节                | 第 3.5 节                |
| 配置 systemd         | 第 6 节                  | 第 6 节                  |

## 1. 准备主机

### 1.1 依赖

构建依赖：

- CMake 4.3 或更高版本
- 支持 C23 的 GCC 或 Clang
- OpenSSL 3 开发文件
- SQLite3 开发文件
- libwebsockets 开发文件
- libyaml 开发文件

PKCS #11 3.2 头文件是来自 latchset/pkcs11-headers 的公有领域副本，已随仓库
提供（`third_party/pkcs11/`），无需安装 p11-kit。

运行环境和 HSM 工具：

- SoftHSM2（仅在使用 SoftHSM 作为 PKCS #11 模块时需要）
- OpenSC（`pkcs11-tool`），用于管理令牌
- `openssl` 命令行工具，用于转换密钥和证书

Debian/Ubuntu：

```sh
sudo apt install build-essential cmake \
  libssl-dev libsqlite3-dev libwebsockets-dev libyaml-dev \
  softhsm2 opensc openssl
```

Fedora：

```sh
sudo dnf install gcc make cmake \
  openssl-devel sqlite-devel libwebsockets-devel libyaml-devel \
  softhsm opensc openssl
```

如果发行版提供的 CMake 版本低于 4.3，请从 <https://cmake.org/download/> 安装新版
CMake，或使用单独的工具链。检查版本：

```sh
cmake --version
```

### 1.2 构建

在仓库根目录执行：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

构建产物：

- `build/anyca_cli`
- `build/anyca_server`
- `build/libanyca_core.so`（前两个程序的运行时依赖）

项目没有安装目标。可以直接从 `build/` 运行，也可以按下文复制到固定前缀。
在构建目录中，可执行文件通过 RPATH 找到 `libanyca_core.so`；复制到其他目录后，
需要把 `LD_LIBRARY_PATH` 指向库所在目录。

### 1.3 服务账户和目录布局

创建专用低权限账户和独立目录：

```sh
sudo useradd --system --user-group --home-dir /opt/anyca \
  --shell /usr/sbin/nologin anyca
sudo install -d -o anyca -g anyca -m 0750 /opt/anyca
sudo install -d -o anyca -g anyca -m 0750 \
  /opt/anyca/bin /opt/anyca/lib /opt/anyca/crl /opt/anyca/cacerts
sudo install -d -o anyca -g anyca -m 0700 /opt/anyca/pins
sudo install -o anyca -g anyca -m 0755 \
  build/anyca_cli build/anyca_server /opt/anyca/bin/
sudo install -o anyca -g anyca -m 0755 \
  build/libanyca_core.so /opt/anyca/lib/
```

完成后的目录结构大致如下：

```text
/opt/anyca/
├── bin/                 anyca_cli、anyca_server
├── lib/                 libanyca_core.so
├── config.yaml          AnyCA 配置
├── softhsm2.conf        SoftHSM 配置
├── store.db             CA 配置、证书和吊销记录
├── pins/                pin-source 引用的 PIN 文件（0700）
├── tokens/              SoftHSM 令牌目录（0700）
├── crl/                 发布的 CRL
└── cacerts/             发布的 CA 证书
```

后续命令均以服务账户身份执行：

```sh
sudo -u anyca -H /bin/bash
cd /opt/anyca
export PATH=/opt/anyca/bin:$PATH
export LD_LIBRARY_PATH=/opt/anyca/lib
export SOFTHSM2_CONF=/opt/anyca/softhsm2.conf
```

### 1.4 配置并初始化 SoftHSM

所有 SoftHSM 命令和服务器进程均需显式设置 `SOFTHSM2_CONF`。这样可避免依赖
发行版的默认配置或 `$HOME/.config/softhsm2/softhsm2.conf`，并确保 CLI 和服务器
使用同一个令牌存储。

创建 SoftHSM 配置和令牌目录：

```sh
cat > /opt/anyca/softhsm2.conf <<'EOF'
directories.tokendir = /opt/anyca/tokens
objectstore.backend = file
log.level = ERROR
EOF
install -d -m 0700 /opt/anyca/tokens
export SOFTHSM2_CONF=/opt/anyca/softhsm2.conf
```

初始化令牌。SO PIN 仅用于令牌管理；用户 PIN 用于 AnyCA 登录令牌：

```sh
read -rsp 'New SO PIN: ' SO_PIN; echo
read -rsp 'New user PIN: ' TOKEN_PIN; echo
softhsm2-util --init-token --free --label AnyCA \
  --so-pin "$SO_PIN" --pin "$TOKEN_PIN"
unset SO_PIN
```

将用户 PIN 保存到仅服务账户可读的文件中，供 `pin-source` 使用。文件末尾可以带
换行，CLI 会去掉末尾的 CR/LF：

```sh
printf '%s' "$TOKEN_PIN" > /opt/anyca/pins/token.pin
chmod 600 /opt/anyca/pins/token.pin
unset TOKEN_PIN
```

验证令牌并记下标签和序列号：

```sh
softhsm2-util --show-slots
```

SoftHSM 的 SO PIN 应离线保存。AnyCA 会把从 URI 中读到的用户 PIN 明文保存到
`store.db`，因此 PIN 文件和数据库都必须限制访问。详见
[第 7 节](#7-安全与运维)。

### 1.5 配置 AnyCA

复制示例配置，并改为绝对路径：

```sh
cp /path/to/anyca/docs/example/config.yaml /opt/anyca/config.yaml
chmod 600 /opt/anyca/config.yaml
```

本指南使用的最小配置：

```yaml
store:
  path: "/opt/anyca/store.db"

http:
  address: "127.0.0.1"
  port: 8080
  max_connections: 1024
  requests_per_second: 1000
  request_burst: 2000

crl_publish_path: "/opt/anyca/crl"
cacerts_publish_path: "/opt/anyca/cacerts"

hsm_providers:
  - name: "softhsm"
    model: "SoftHSM v2"
    library: "/usr/lib/softhsm/libsofthsm2.so"

certificate_usages:
  - name: "ca"
    basic_usages:
      - "digitalSignature"
      - "keyCertSign"
      - "cRLSign"
    enhanced_usage_oids: []
  - name: "code-signing"
    basic_usages:
      - "digitalSignature"
    enhanced_usage_oids:
      - "1.3.6.1.5.5.7.3.3"
```

字段说明：

- `store`、`http` 和至少一个 `hsm_providers` 条目在 YAML 结构中是必需的，
  即使某个命令本身不使用 HTTP。
- `store.path` 是 SQLite 数据库。首次使用时会自动创建表结构。schema 版本不
  兼容时程序会拒绝打开，此时需要新建数据库。
- `hsm_providers[].name` 是 PKCS #11 URI 中 `provider=<name>` 选择的名字。
  指定 `provider=` 时按名称选择，并使用 URI 中的 `model` 和 `serial` 做一致性
  校验；只有省略 `provider=` 时，才完全依靠 `model` 和 `serial` 匹配。
- `http.address` 设为 `127.0.0.1` 时，适合在前面放 TLS 反向代理。仅在客户端
  直连时才使用 `0.0.0.0`，并配置防火墙。
- `http.max_connections` 限制 libwebsockets 的文件描述符数量；
  `requests_per_second` 和 `request_burst` 配置按客户端（对端地址）隔离的令牌桶。
  省略或设置为 0 时使用默认值（1024、1000、2000）。systemd 的 `LimitNOFILE`
  必须大于 `max_connections`。
- `crl_publish_path` 和 `cacerts_publish_path` 是可选的，但 `crl publish`、
  服务器启动时发布 CA 证书以及服务器定时发布 CRL 都需要对应的目录。
- `certificate_usages` 必须包含命令行引用的配置项。`ca create` 默认使用
  `ca`，下面的示例还会使用 `code-signing`。

如果希望客户端从证书中自动发现 OCSP 和 CRL 地址，可以添加带公开 URL 的模板：

```yaml
certificate_templates:
  - name: "default"
    aia:
      issuer_uris:
        - "https://pki.example.com/cacerts/root-ca.crt"
      ocsp_uris:
        - "https://ocsp.example.com/ocsp/root-ca"
    crl_uris:
      - "https://pki.example.com/crl/root-ca/root-ca.crl"
```

这些 URI 会写入所有使用该模板的证书，因此请在签发前确认地址正确。文件名和
目录布局由 `cacerts_publish_path` 和 `crl_publish_path` 决定，参见第 2.3 节和
第 2.5 节。

## 2. 部署新 CA

### 2.1 创建 CA

`ca create` 会执行以下操作：

1. 在令牌中生成 CA 密钥对；
2. 在令牌中生成 OCSP 签名密钥对；
3. 生成自签名 CA 证书和由该 CA 签发的 OCSP 签名证书；
4. 把证书、密钥 URI 和相关配置保存到数据库。

```sh
anyca_cli -c /opt/anyca/config.yaml ca create \
  --name root-ca \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-ca-key?pin-source=/opt/anyca/pins/token.pin' \
  --ocsp-key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-ca-ocsp-key?pin-source=/opt/anyca/pins/token.pin' \
  --ocsp-responder-endpoint root-ca \
  --subject 'CN=Example Root CA,O=Example,C=US' \
  --key-type ec --ec-curve p384 \
  --crl-publish-period-min 60 --ocsp-update-period-min 10
```

预期输出：

```text
Created CA: root-ca
```

注意事项：

- 两个 `object` 标签在各自 URI 指定的令牌中均不得预先存在。
- CLI 会在生成任何密钥前检查 CA 名称和 OCSP 端点是否重复。
- 如果生成密钥后的某个步骤失败，本次创建的密钥对会被删除。如果删除也失败，
  CLI 会打印警告，此时需要手工删除令牌中的密钥。
- 生成的 CA 证书和 OCSP 签名证书有效期都是 3650 天。

检查登记结果：

```sh
anyca_cli -c /opt/anyca/config.yaml ca list
```

### 2.2 检查生成的密钥

```sh
export SOFTHSM2_CONF=/opt/anyca/softhsm2.conf
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label AnyCA --login --list-objects
```

CA 密钥和 OCSP 签名密钥各有一个私钥对象和一个同标签的公钥对象。AnyCA 按标签
查找公钥对象，因此两个对象都必须存在。

### 2.3 发布 CRL

```sh
anyca_cli -c /opt/anyca/config.yaml crl publish --all
```

`crl publish` 会打开令牌，使用 CA 密钥签名 CRL 并写入：

```text
/opt/anyca/crl/root-ca/root-ca.crl
```

该文件是 DER 编码。如果配置了 `cacerts_publish_path`，服务器启动时会从数据库
读取 CA 证书，并发布到 `/opt/anyca/cacerts/root-ca.crt`。请使用静态 Web 服务器
提供这两个目录，或将文件复制到现有分发系统。

### 2.4 签发测试证书

这一步可选，但可以端到端验证 CA 密钥、存储和 OCSP 响应。

生成叶子密钥和 PKCS #10 请求。下面的命令把叶子私钥保存在本地文件中；生产环境
通常由证书主体用自己的 PKCS #11 工具生成请求。

```sh
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /opt/anyca/leaf.key \
  -subj '/CN=leaf.example' \
  -outform DER -out /opt/anyca/leaf.csr
openssl req -in /opt/anyca/leaf.csr -inform DER -noout -verify
```

签发证书：

```sh
anyca_cli -c /opt/anyca/config.yaml cert issue \
  --ca-name root-ca \
  --in /opt/anyca/leaf.csr \
  --basic --is-ca false \
  --certificate-usage code-signing \
  --out /opt/anyca/leaf.der
```

如果配置了包含公开 AIA 和 CRL URL 的模板，请再加上
`--certificate-template default`。证书是 DER 编码，并会自动登记；签发后立即出现
在 `cert list` 中，OCSP 也会把它识别为 `good`，无需再执行 `cert record --add`。

要签发下级 CA 证书，请使用
`cert issue --basic --is-ca true --path-length 0 --certificate-usage ca`，
然后用 `ca import` 注册生成的证书。

### 2.5 启动服务器并验证 OCSP

```sh
anyca_server -c /opt/anyca/config.yaml
```

服务器以前台方式运行，日志写入 stderr，收到 SIGINT 或 SIGTERM 后正常退出。启动时：

- 加载数据库中的 CA，逐一校验密钥、证书和 OCSP 签名授权；
- 如果配置了 `cacerts_publish_path`，把 CA 证书发布到
  `/opt/anyca/cacerts/root-ca.crt`；
- 如果配置了 `crl_publish_path`，发布一次初始 CRL；
- 启动每分钟运行一次的 CRL 调度器，按各 CA 的 `crl_publish_period_min` 检查并
  发布 CRL。

`openssl ocsp` 客户端需要 PEM 证书，先转换：

```sh
openssl x509 -inform DER -in /opt/anyca/cacerts/root-ca.crt -out /tmp/root-ca.pem
openssl x509 -inform DER -in /opt/anyca/leaf.der -out /tmp/leaf.pem
```

在另一个终端查询：

```sh
openssl ocsp \
  -issuer /tmp/root-ca.pem \
  -cert /tmp/leaf.pem \
  -url http://127.0.0.1:8080/ocsp/root-ca \
  -no_nonce -noverify -resp_text
```

正常响应包含：

```text
Cert Status: good
```

`-noverify` 只是在这台测试机上关闭响应签名校验。生产客户端会使用 OCSP 签名
证书和 CA 验证响应。`/ocsp/<端点>` 同时支持 GET 和 POST：

- GET：`/ocsp/<端点>/<Base64 编码的 DER 请求>`；
- POST：请求体为 DER 编码的 OCSP 请求。

HTTP 请求体上限为 10 KiB，超过时返回 413；请求速率超过该客户端的限制时返回
503；除 GET 和 POST 之外的方法返回 405。

### 2.6 吊销证书

```sh
anyca_cli -c /opt/anyca/config.yaml cert revoke --add \
  --in /opt/anyca/leaf.der --reason 1

anyca_cli -c /opt/anyca/config.yaml crl publish --ca-name root-ca
```

服务器会在处理每个 OCSP 请求时读取数据库，因此下一次查询就会返回 `revoked`，
无需重启。CRL 会在手动执行 `crl publish` 时更新，或在服务器的定时器到期时更新
（本示例中为 60 分钟）。

## 3. 部署已有 CA

如果 CA 证书和私钥已存在且希望继续使用该 CA，请按本节操作。CA 私钥最终
必须位于 PKCS #11 令牌中；AnyCA 不会从文件读取私钥。

### 3.1 检查已有材料

CA 证书必须满足：

- 是 X.509 CA 证书：`X509_check_ca()` 必须接受，通常意味着 BasicConstraints
  为 `CA:TRUE`，且 KeyUsage 允许签发证书；
- 在有效期内；部署前用 `openssl x509 -dates` 检查，并在之后持续监控；
- 与私钥匹配（公钥相同）。

私钥可以是 RSA（建议至少 2048 位）或 EC（P-256、P-384、P-521）。SoftHSM 支持
导入 PKCS #8 格式的 RSA 和 EC 密钥。ML-DSA 密钥需要实现了 `CKM_ML_DSA` 的
PKCS #11 3.2 provider；SoftHSM 2.6 不支持，请使用 HSM 厂商的导入流程。

检查证书：

```sh
openssl x509 -in existing-ca.pem -noout -subject -issuer -dates
openssl x509 -in existing-ca.pem -noout -text | \
  grep -A2 -E 'Basic Constraints|Key Usage'
```

检查私钥和证书是否匹配：

```sh
openssl pkey -in existing-ca.key -pubout -out /tmp/existing-ca-key.pub
openssl x509 -in existing-ca.pem -pubkey -noout > /tmp/existing-ca-cert.pub
cmp /tmp/existing-ca-key.pub /tmp/existing-ca-cert.pub
```

匹配时，`cmp` 不输出内容并返回 0。把证书转换为 DER，供 `ca import` 使用：

```sh
openssl x509 -in existing-ca.pem -outform DER -out /opt/anyca/existing-ca.der
```

### 3.2 将 CA 私钥导入 SoftHSM

按照[第 4 节](#4-将已有私钥导入-softhsm)操作。使用唯一标签，例如
`existing-ca-key`，并确认私钥对象和公钥对象都存在。记下标签，后面要在 PKCS #11
URI 中使用。

### 3.3 准备 OCSP 签名密钥

OCSP 签名密钥同样必须位于令牌中。可以在令牌中直接生成：

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label AnyCA --login \
  --keypairgen --key-type EC:secp384r1 \
  --label existing-ca-ocsp-key --usage-sign
```

`ca import` 会用 CA 密钥为这个签名密钥生成 OCSP 签名证书。证书主题默认为
`CN=<CA 名称> OCSP Signer`，有效期 3650 天，扩展固定为：关键的 keyUsage
`digitalSignature`、关键的 basicConstraints（`cA=false`）、OCSPSigning
extendedKeyUsage。

### 3.4 登记 CA

```sh
anyca_cli -c /opt/anyca/config.yaml ca import \
  --name existing-ca \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=existing-ca-key?pin-source=/opt/anyca/pins/token.pin' \
  --in /opt/anyca/existing-ca.der \
  --ocsp-key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=existing-ca-ocsp-key?pin-source=/opt/anyca/pins/token.pin' \
  --ocsp-responder-endpoint existing-ca \
  --crl-publish-period-min 60 --ocsp-update-period-min 10
```

预期输出：

```text
Imported CA: existing-ca
```

登记前，CLI 会执行以下检查：

| 检查项                                                                     | 失败行为                 |
|----------------------------------------------------------------------------|--------------------------|
| CA 证书可按 DER 解析                                                       | 导入失败，不登记任何内容 |
| CA 证书是 CA 证书（`X509_check_ca`）                                       | 导入失败，不登记任何内容 |
| CA 密钥与 CA 证书匹配                                                      | 导入失败，不登记任何内容 |
| OCSP 签名密钥与生成的 OCSP 签名证书匹配                                    | 导入失败，不登记任何内容 |
| 生成的 OCSP 签名证书对该 CA 有效（由该 CA 直接签发并包含 OCSPSigning EKU） | 导入失败，不登记任何内容 |
| CA 名称和 OCSP 端点未被占用                                                | 在写入 CA 记录前拒绝     |

密钥与证书的匹配检查使用 HSM 密钥对固定挑战数据签名，再用证书公钥验证签名。
仅在全部检查通过后，CA 配置才会保留；失败时会回滚配置，如果回滚本身失败，CLI
会打印警告。

导入后，后续操作都从数据库读取 CA 证书。可以保留原始证书文件作为备份，但
AnyCA 不再需要它。

### 3.5 发布并运行

```sh
anyca_cli -c /opt/anyca/config.yaml ca list
anyca_cli -c /opt/anyca/config.yaml crl publish --all
anyca_server -c /opt/anyca/config.yaml
```

按照第 2.5 节执行冒烟测试，把 OCSP URL 中的 `root-ca` 换成 `existing-ca`。如果配置
了 `cacerts_publish_path`，服务器启动时会发布
`/opt/anyca/cacerts/existing-ca.crt`。使用该 CA 签发证书时，执行
`cert issue --ca-name existing-ca`。

服务器启动时执行与 `ca import` 相同的校验：打开 CA 和 OCSP 签名令牌，检查 CA
证书、OCSP 签名证书的授权关系，以及两组密钥与证书是否匹配。校验失败的 CA 会被
记录并跳过，其他 CA 继续启动。运行中的服务器在重新加载变更后的 CA 配置时会再次
校验；修复存储中的配置后无需重启即可生效。若重新加载仍然失败，服务器继续使用该
CA 上一次的配置。

## 4. 将已有私钥导入 SoftHSM

本节适用于已有 CA 私钥、已有 OCSP 签名私钥，或其他需要交给 AnyCA 使用的密钥。

建议使用 `softhsm2-util --import`，因为该命令一次导入**密钥对**（私钥和公钥）并使
两者使用同一个标签。AnyCA 需要公钥对象来读取公钥并校验密钥与证书的一致性。

### 4.1 将密钥转换为 PKCS #8

`softhsm2-util --import` 要求 PKCS #8 文件。如果密钥采用 PKCS #1
（`BEGIN RSA PRIVATE KEY`）、传统 EC 格式或加密容器，请先转换：

```sh
# 未加密的 PKCS #8。输出文件包含原始私钥。
openssl pkcs8 -topk8 -nocrypt -in existing-ca.key -out existing-ca.p8
chmod 600 existing-ca.p8
```

如果输入密钥已加密，同一条命令会提示输入原口令；`-nocrypt` 保证输出未加密。
请在可信主机上操作，将临时文件放在权限受限的文件系统中，并在导入后按密钥管理
策略删除。

导入前检查密钥类型和长度。下面的命令仅显示公钥部分，不会把私钥参数打印到终端：

```sh
openssl pkey -in existing-ca.key -pubout |
  openssl pkey -pubin -text -noout | head
```

RSA 密钥建议至少 2048 位；EC 密钥使用 P-256、P-384 或 P-521。

### 4.2 初始化令牌

如果令牌尚不存在：

```sh
export SOFTHSM2_CONF=/opt/anyca/softhsm2.conf
read -rsp 'New SO PIN: ' SO_PIN; echo
read -rsp 'New user PIN: ' TOKEN_PIN; echo
softhsm2-util --init-token --free --label AnyCA \
  --so-pin "$SO_PIN" --pin "$TOKEN_PIN"
unset SO_PIN
printf '%s' "$TOKEN_PIN" > /opt/anyca/pins/token.pin
chmod 600 /opt/anyca/pins/token.pin
```

验证令牌标签：

```sh
softhsm2-util --show-slots
```

### 4.3 导入密钥对

```sh
softhsm2-util --import /secure/existing-ca.p8 \
  --token AnyCA --pin "$TOKEN_PIN" \
  --label existing-ca-key --id 01
```

参数说明：

- `--token` 是令牌标签，不是槽位号；也可以使用 `--slot` 或 `--serial`。
- `--label` 是 AnyCA 在 PKCS #11 URI 的 `object=` 中使用的标签。
- SoftHSM 要求提供 `--id`，即使 AnyCA 按标签选择密钥。每把密钥使用唯一的十六
  进制 ID（例如 `01`、`02`……）。如果 ID 已存在，SoftHSM 会拒绝导入，请换一个
  ID。除非确实允许重复 ID，否则不要使用 `--force`。
- 不要传 `--no-public-key`：AnyCA 需要公钥对象。

省略 `--pin` 时，命令会提示输入用户 PIN。使用 `--pin` 会把展开后的 PIN 暴露在
进程列表中；如果把 PIN 直接写在命令里，它还会进入 Shell 历史。在多用户主机上
应使用受保护的临时 Shell 或交互式提示。

预期输出：

```text
The key pair has been imported.
```

### 4.4 验证密钥对

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label AnyCA --login --list-objects --type privkey
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label AnyCA --login --list-objects --type pubkey
```

两个列表都必须包含同标签、同 ID 的对象。私钥应具有 `sign` 用途，公钥应具有
`verify` 用途。

为 AnyCA 构造如下 URI：

```text
pkcs11:provider=softhsm;token=AnyCA;object=existing-ca-key?pin-source=/opt/anyca/pins/token.pin
```

- `provider=softhsm` 必须与 `hsm_providers` 中的 `name` 一致。
- 省略 `provider=` 时，AnyCA 会用标准的 `model` 和 `serial` 属性匹配
  provider 配置项。
- 令牌标签或对象标签中的空格和其他保留字符需要进行百分号编码（空格为 `%20`）。
- 在 Shell 中必须为 URI 加引号，因为 `;`、`?` 和 `&` 是 Shell 元字符。

该 URI 可作为 `ca import`、`ca update`、`cert new-root` 或 `hsm key-info`
的 `--key-uri`。OCSP 签名密钥则把 `object=` 换成签名密钥标签，作为
`--ocsp-key-uri` 传入。

### 4.5 导入 OCSP 签名密钥

流程与导入 CA 密钥相同：

```sh
softhsm2-util --import /secure/existing-ocsp.p8 \
  --token AnyCA --pin "$TOKEN_PIN" \
  --label existing-ca-ocsp-key --id 02
```

如果还没有 OCSP 签名密钥，可以直接在令牌中生成：

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label AnyCA --login \
  --keypairgen --key-type EC:secp384r1 \
  --label existing-ca-ocsp-key --usage-sign
```

### 4.6 其他导入方式

- `pkcs11-tool --keypairgen` 在令牌中生成新的密钥对，适合新密钥。
- `pkcs11-tool --write-object --type privkey` 只写入私钥对象。AnyCA 还需要同标签
  的公钥对象，因此仅这样做不够；请另外导入匹配的公钥对象，或优先使用
  `softhsm2-util --import`。
- 辅助脚本
  [../scripts/softhsm-import-key.sh](../scripts/softhsm-import-key.sh) 使用
  `pkcs11-tool --write-object --type privkey`，因此有同样的限制，不建议用它
  导入 AnyCA 的 CA 密钥。
- 硬件 PKCS #11 模块应使用厂商工具导入。AnyCA 只需要最终的令牌标签、对象标签
  和 PIN。

### 4.7 清理临时密钥材料

确认令牌中包含完整密钥对且备份或托管策略已满足后，删除未加密的 PKCS #8
文件：

```sh
shred -u /secure/existing-ca.p8
```

在 SSD、写时复制文件系统或支持快照的存储上，`shred` 不能保证物理擦除；更稳妥的
做法是把临时密钥放在加密文件系统中，并在用完后销毁整个文件系统或加密卷。

绝不要删除 CA 密钥的唯一副本。SoftHSM 令牌是 `directories.tokendir` 下的普通
文件，备份令牌目录时必须按密钥材料来保护。

## 5. URL 布局和反向代理

AnyCA 只通过明文 HTTP 提供 OCSP。典型公网部署会在前面部署 TLS 反向代理，并
使用静态内容服务器提供发布文件：

- OCSP：`http://127.0.0.1:8080/ocsp/<端点>` → 公网
  `https://ocsp.example.com/ocsp/<端点>`
- CA 证书：`/opt/anyca/cacerts/<CA 名称>.crt` → 公网
  `https://pki.example.com/cacerts/<CA 名称>.crt`
- CRL：`/opt/anyca/crl/<CA 名称>/<CA 名称>.crl` → 公网
  `https://pki.example.com/crl/<CA 名称>/<CA 名称>.crl`

OCSP 的最简 nginx 配置：

```nginx
location /ocsp/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 15s;
}
```

使用反向代理时，AnyCA 监听 `127.0.0.1`。如果客户端直连，请将 `http.address`
设为特定接口，并用防火墙限制访问；程序本身不提供 TLS。

发布目录位于 `/opt/anyca` 下，父目录权限为 `0750`。如果由其他用户（例如
`www-data`）提供静态文件服务，需要通过组成员关系或 ACL 授予该用户对
`/opt/anyca/crl` 和 `/opt/anyca/cacerts` 的读取和目录遍历权限。不要授予它对
`tokens/`、`pins/` 或 `store.db` 的访问权限。

## 6. 作为 systemd 服务运行

创建 `/etc/systemd/system/anyca.service`：

```ini
[Unit]
Description=AnyCA OCSP responder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=anyca
Group=anyca
WorkingDirectory=/opt/anyca
Environment=SOFTHSM2_CONF=/opt/anyca/softhsm2.conf
Environment=LD_LIBRARY_PATH=/opt/anyca/lib
ExecStart=/opt/anyca/bin/anyca_server -c /opt/anyca/config.yaml
Restart=on-failure
RestartSec=2
LimitNOFILE=4096
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/anyca

[Install]
WantedBy=multi-user.target
```

启用并启动：

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now anyca
sudo systemctl status anyca
sudo journalctl -u anyca -f
```

注意事项：

- 服务必须使用与初始化、导入密钥时相同的 `SOFTHSM2_CONF`。
- `LimitNOFILE` 必须大于 `http.max_connections`。`4096` 足以覆盖默认的 1024
  个连接并留出其他文件描述符；提高连接上限时也要提高 `LimitNOFILE`。
- 应以 `anyca` 用户运行 `anyca_cli`，或确保 umask 和权限让服务仍能写存储。
  用 root 运行 CLI 可能创建 root 所有的文件，导致服务无法更新。

运行中的服务器会在每次 OCSP 响应前和每个 CRL 调度周期从存储重新加载 CA 配置，
因此使用 `ca update` 或 `ca delete` 修改 CA 配置后无需重启。仅在修改
`config.yaml`（例如新增 `hsm_providers` 条目）后才需要重启服务：

```sh
sudo systemctl restart anyca
```

## 7. 安全与运维

### 7.1 保护机密

- `store.db` 以明文形式包含 CA 密钥 URI 和令牌 PIN。AnyCA 新建的数据库权限为
  `0600`；请使用 `stat` 确认（包括在其他工具中创建的数据库），并把它放在访问
  受限或启用静态加密的文件系统中。WAL 模式还会产生 `store.db-wal` 和
  `store.db-shm`，这些文件同样包含敏感数据，也必须限制访问。
- `pins/*.pin` 只能由服务账户读取。`pin-source` 可避免 PIN 出现在 `argv`、
  Shell 历史和进程列表中，但不会从 `store.db` 中移除 PIN。
- SoftHSM 是软件 HSM，不是防篡改设备。如需更高保障，请使用硬件 PKCS #11 模块，并按
  厂商流程导入密钥；AnyCA 只需要 provider 配置项和 PKCS #11 URI。
- 考虑把 CA 密钥和 OCSP 签名密钥放在不同令牌中，使用不同 PIN 和访问策略。
  两个 URI 可以选择不同的 `hsm_providers`。
- 限制可运行 `anyca_cli` 以及读取令牌目录的人员。
- 停止服务后备份 `/opt/anyca/tokens`、`store.db`、`config.yaml` 和 PIN 文件。
  备份包含私钥和 PIN，必须加密。

### 7.2 可用性

- `http.max_connections` 限制 libwebsockets 的文件描述符数量。systemd 的
  `LimitNOFILE` 必须高于该值。
- `http.requests_per_second` 和 `http.request_burst` 使用按客户端（对端地址）
  隔离的令牌桶，超限请求返回 HTTP 503。请根据预期 OCSP 负载和反向代理自身的
  限制调整。
- 响应程序在单个 libwebsockets 线程上处理请求，并用会话锁串行化核心与存储
  访问，因此 CRL 发布会短暂延迟 OCSP 响应。进程内共享 HSM 令牌会话；只有在
  多个实例能安全共享存储且 HSM 支持并发会话时才运行多实例。
- 使用可靠的静态服务器或 CDN 提供 CRL 和 CA 证书。客户端可能会缓存它们。
- 保持主机时钟同步（例如使用 chrony 或 systemd-timesyncd）。证书有效期、CRL
  时间和 OCSP 的 `thisUpdate`/`nextUpdate` 都依赖时钟。
- 监控 CA 证书和 OCSP 签名证书的到期时间。OCSP 签名证书过期会导致 CA 加载
  失败，服务器启动时会跳过该 CA。

### 7.3 CA 证书和密钥轮换

OCSP 响应和 CRL 都绑定签发者身份：OCSP CertID 包含签发者名称和公钥的哈希，
CRL 用签发者公钥验证。因此用 `ca update --in` 或 `ca update --key-uri`
直接替换存储中的 CA 证书或密钥，会影响旧 CA 签发的所有证书：

- 旧身份签发的证书不再匹配响应程序的签发者名称哈希和公钥哈希。即使序列号仍在
  存储中，响应程序也会返回 `unknown`。
- `<crl_publish_path>/<CA 名称>/<CA 名称>.crl` 会被新密钥签名的 CRL 覆盖。仍持有
  旧证书的客户端无法用证书中的签发者验证该 CRL，原 CRL 编号序列和内容也会丢失。
- `<cacerts_publish_path>/<CA 名称>.crt` 会被新证书覆盖。任何固定或缓存旧文件的
  系统都需要更新。

如果只续期 CA 证书而保持主体和密钥不变，影响较小：现有 CertID 仍然匹配，CRL
也仍可验证，因为二者都依赖签发者名称和公钥，而不是 CA 证书序列号。但发布的 CA
文件仍会变化；如果旧证书已泄露，不得继续信任它。

安全轮换 CA 的步骤如下：

1. 用新名称创建新的 CA 配置（`ca create` 或 `ca import`），并指定不同的 OCSP
   端点（`--ocsp-responder-endpoint`）。新名称会在 `crl_publish_path` 和
   `cacerts_publish_path` 下自动生成自己的 `<CA 名称>` 子目录。绝不能把同一个
   CA 名称、OCSP 端点或发布 URL 路径复用于另一个身份。
2. 继续运行旧 CA 配置、密钥和发布文件，直到旧 CA 签发的所有证书过期或被吊销。
   保持旧 OCSP 端点和旧 CRL 路径可访问，不要在该路径重新发布不同身份签名的 CRL。
3. 用新 CA 签发新证书，并把新 CA 证书分发到信任库。过渡期间客户端可以同时信任
   旧 CA 证书和新 CA 证书。
4. 只有在旧 CA 的最后一张证书过期后，才能停用旧 CA。如果客户端仍可能引用旧 CRL 和 CA
   证书，请把它们归档到稳定路径，然后用 `ca delete` 删除配置、用 `hsm keydel`
   删除密钥。

`ca update --in` 和 `ca update --key-uri` 会校验新的密钥和证书，并在需要时重新
签发 OCSP 签名证书，但无法修复旧身份所签发证书的 OCSP 或 CRL 状态。这些操作只适用
于主体和密钥不变的证书续期，不适用于 CA 轮换。

### 7.4 常用命令

| 任务                           | 命令                                                                                          |
|--------------------------------|-----------------------------------------------------------------------------------------------|
| 列出 CA                        | `anyca_cli -c /opt/anyca/config.yaml ca list`                                                 |
| 列出某个 CA 的证书             | `anyca_cli -c /opt/anyca/config.yaml cert list --ca-name root-ca`                             |
| 列出吊销记录                   | `anyca_cli -c /opt/anyca/config.yaml cert list --revocation --ca-name root-ca`                |
| 按证书吊销                     | `anyca_cli -c /opt/anyca/config.yaml cert revoke --add --in leaf.der --reason 1`              |
| 删除吊销记录                   | `anyca_cli -c /opt/anyca/config.yaml cert revoke --delete --in leaf.der`                      |
| 重新发布 CRL                   | `anyca_cli -c /opt/anyca/config.yaml crl publish --ca-name root-ca`                           |
| 修改 CRL 周期                  | `anyca_cli -c /opt/anyca/config.yaml ca update --ca-name root-ca --crl-publish-period-min 30` |
| 续签 OCSP 签名证书             | `anyca_cli -c /opt/anyca/config.yaml ca ocsp-renew --ca-name root-ca --days 30`               |
| 续期 CA 证书（主体和密钥不变） | `anyca_cli -c /opt/anyca/config.yaml ca update --ca-name root-ca --in new-ca.der`             |
| 删除 CA 配置                   | `anyca_cli -c /opt/anyca/config.yaml ca delete --ca-name root-ca`                             |

服务器会在启动时发布 CA 证书，前提是配置了 `cacerts_publish_path`。服务器重新
加载配置时如果发现存储的证书发生变化，也会重新发布该文件；因此执行
`ca update --in` 修改数据库中的证书，或用 `ca ocsp-renew` 更新 OCSP 签名证书
后，无需重启即可生效。替换 CA 证书或密钥前请先阅读 7.3 节：原地更换身份会让
旧 CA 签发的证书的 OCSP 和 CRL 失效。

`ca delete` 只删除 CA 配置，不会删除存储中的证书/吊销记录、令牌中的密钥，也
不会删除发布目录中的 CRL 和 CA 证书文件。如果不再需要密钥，请使用 PKCS #11
管理工具单独删除。

### 7.5 备份

需要备份以下内容：

- `/opt/anyca/tokens/`：SoftHSM 令牌，包含 CA 私钥；
- `/opt/anyca/store.db`：CA 配置、证书和吊销记录；
- `/opt/anyca/config.yaml`；
- `/opt/anyca/pins/`：令牌 PIN 文件；
- 发布目录（可选，可重新生成）。

最稳妥的做法是在停止服务后再复制这些文件。如果必须在运行中备份 SQLite，请使用
SQLite 的备份功能，而不是直接复制正在写入的数据库：

```sh
sqlite3 /opt/anyca/store.db ".backup '/secure/backup/store.db'"
```

备份包含私钥和 PIN，必须加密保存，并限制访问。请定期演练恢复流程。

## 8. 故障排查

| 现象                                                    | 可能原因和处理                                                                                                                                           |
|---------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `cannot load configuration` 或 `config_load failed`     | `-c` 路径错误，或进程工作目录与预期不同。使用绝对路径。                                                                                                  |
| `ca import` 后找不到 CA                                 | CLI 和服务器可能使用不同的 `store.db`。检查 `store.path`；相对路径按各自进程的工作目录解析。                                                             |
| `Cannot open HSM token ...` 或 `CKR_TOKEN_NOT_PRESENT`  | 令牌标签不匹配、`SOFTHSM2_CONF` 错误，或服务账户无法读取令牌目录。在相同环境下运行 `softhsm2-util --show-slots` 对比。                                   |
| `CKR_PIN_INCORRECT`                                     | URI 中的 PIN 与令牌不再匹配。更新 PIN 文件后，用 `ca update --key-uri` 和 `--ocsp-key-uri` 重新登记 URI，或重新导入 CA。                                 |
| `the HSM key does not match the certificate for CA ...` | URI 选错了密钥标签，或证书不属于该密钥。用 `hsm key-info` 和 `openssl pkey -pubout` 比较公钥。                                                           |
| `Certificate for CA ... is not a CA certificate`        | 证书缺少 CA BasicConstraints/KeyUsage，或把非 CA 证书传给了 `ca import`。导入正确的 CA 证书。                                                            |
| `OCSP signing certificate is not authorized for CA ...` | 签名证书已过期、不是由该 CA 直接签发，或缺少 OCSPSigning EKU。使用 `ca ocsp-renew --ca-name <名称>` 续签。                                               |
| `CA name or OCSP responder endpoint is already in use`  | 名称或端点已被占用。换一个 `--name`/`--ocsp-responder-endpoint`，或先删除已有 CA。                                                                       |
| `softhsm2-util --import` 报告格式错误                   | 密钥不是 PKCS #8。用 `openssl pkcs8 -topk8 -nocrypt` 转换。                                                                                              |
| `ca import` 找不到公钥或密钥对象                        | 密钥被作为仅私钥对象导入。使用不带 `--no-public-key` 的 `softhsm2-util --import`，或另外导入匹配的公钥对象。                                             |
| `Unsupported store schema`                              | 数据库由不兼容的旧版本创建。新建数据库，或按发布说明迁移。                                                                                               |
| 响应程序返回 HTTP 503                                   | 超过该客户端的速率或突发限制。提高 `http.requests_per_second`/`http.request_burst`，或在代理层增加容量和限流。检查服务器日志中的限流警告。               |
| 响应程序返回 HTTP 413                                   | POST 请求体超过 10 KiB。检查客户端是否发送了过大的 OCSP 请求。                                                                                           |
| 响应程序返回 HTTP 405 或 400                            | 使用了 GET/POST 以外的方法，或请求路径不是 `/ocsp/<端点>`。                                                                                              |
| 服务器启动但跳过某个 CA                                 | 查看前面的 `LOGE` 日志。常见原因包括令牌访问失败、签名证书过期、签名证书不是由该 CA 签发，或密钥/证书不匹配。                                            |
| 吊销后 OCSP 仍返回 `good`                               | 证书没有登记在服务器加载的 CA 下，或 CLI 与服务器使用不同存储。检查 `cert list --revocation --ca-name ...` 和 `store.path`。                             |
| OCSP 返回 `unknown`                                     | 证书序列号没有登记。用 `cert record --add --in <证书>` 登记。                                                                                            |
| CRL 没有更新                                            | 执行 `crl publish`，或等待 CA 的 `--crl-publish-period-min` 周期。服务器在启动时和调度器检查到周期已到时发布 CRL；未配置 `crl_publish_path` 时不会发布。 |
| `ca create` 在密钥生成后失败                            | 本次调用创建的密钥对会被删除。如果清理也失败，错误信息会给出警告；请用 `hsm keydel`、`pkcs11-tool --delete-object` 或厂商工具删除对应标签。              |

## 9. 部署检查清单

- [ ] OpenSSL、SQLite、libwebsockets 和 libyaml 依赖与构建保持一致，且
      `third_party/pkcs11/pkcs11.h` 存在。
- [ ] `anyca_cli`、`anyca_server` 和所有 SoftHSM 命令使用相同的
      `SOFTHSM2_CONF` 和令牌目录。
- [ ] `config.yaml` 中的存储和发布目录使用绝对路径。
- [ ] `hsm_providers` 包含模块路径；URI 中的 `provider=` 与其 `name` 一致。
- [ ] CA 密钥和 OCSP 签名密钥都有私钥对象和公钥对象。
- [ ] `ca list` 显示预期的 CA、端点、密钥哈希和周期。
- [ ] `crl publish --all` 生成预期的 DER CRL。
- [ ] 服务器启动时写出预期的 DER CA 证书（如果配置了 `cacerts_publish_path`）。
- [ ] OCSP 冒烟测试对正常证书返回 `good`，对已吊销证书返回 `revoked`。
- [ ] `store.db`、PIN 文件和令牌目录只有服务账户可读。
- [ ] systemd 的 `LimitNOFILE` 大于 `http.max_connections`。
- [ ] 存储、令牌目录、配置和 PIN 文件的备份已测试、加密并限制访问。
- [ ] 主机时钟已同步。
- [ ] 已监控 CA 证书和 OCSP 签名证书的到期时间。
