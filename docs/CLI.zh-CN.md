# AnyCA 命令行工具

`anyca_cli` 是 AnyCA 的管理工具，用于：

- 在存储数据库中登记和维护 CA 配置；
- 根据 PKCS #10 证书请求签发证书，或生成独立的自签名根证书；
- 记录、吊销和查询已签发证书；
- 生成 OCSP 签名证书；
- 构建并发布 DER 编码的 CRL；
- 查看和管理 PKCS #11 令牌与密钥。

CLI 只从 HSM 读取公钥，并通过已配置的 HSM provider 请求签名；私钥始终留在令牌
中。除 `cert issue` 的请求文件外，所有证书输入和输出都是 DER 编码；该命令同时
接受 DER 和 PEM 编码的证书请求。

完整部署流程（包括 SoftHSM 初始化、导入已有 CA 和导入私钥）参见
[DEPLOY.zh-cn.md](DEPLOY.zh-cn.md)。

## 使用概览

典型流程如下：

1. 在 YAML 配置文件（默认 `config.yaml`，可用 `--config` 指定）中配置
   `store.path`、`http` 和至少一个 `hsm_providers` 条目。
2. 使用 `ca create` 新建 CA，程序会在令牌中生成 CA 密钥对和 OCSP 签名密钥对；
   也可以使用 `ca import` 接管已有 CA。CA 证书、密钥位置、PIN、周期和 OCSP 端点
   都会保存到 SQLite。
3. 使用 `cert issue` 根据证书请求签发证书，或使用 `cert new-root` 生成独立的
   自签名根证书。使用 `ca ocsp-renew` 续签 CA 的 OCSP 签名证书。通过 `cert issue`
   签发的证书会
   自动登记。
4. 使用 `cert revoke --add` 吊销证书，用 `cert revoke --delete` 撤销吊销；
   `cert record` 可以手工增删证书记录，`cert list` 查看两类记录。
5. 使用 `ca publish-crl` 或 `crl publish` 发布 DER CRL。如果配置了
   `cacerts_publish_path` 和 `crl_publish_path`，服务器在启动时也会发布 CA 证书
   和 CRL。
6. 运行 `anyca_server`，为已登记的 CA 提供 OCSP 响应。

各命令对配置的依赖如下：

- 所有 `ca`、`crl` 命令，以及除 `cert new-root` 外的 `cert` 命令，都需要
  `store.path`，因为这些命令要读写存储数据库。
- `cert new-root` 和所有 `hsm` 命令仅需配置文件，不打开存储。
- 运行中的 `anyca_server` 会在处理下一次 OCSP 请求或 CRL 调度时重新加载
  存储中的 CA 配置，因此修改 CA 配置（`ca create`、`ca import`、`ca update`、
  `ca delete`、`ca ocsp-renew`）无需重启即可生效。

## 命令概要

```text
anyca_cli [--config <path>] ca create [options]
anyca_cli [--config <path>] ca import [options]
anyca_cli [--config <path>] ca list
anyca_cli [--config <path>] ca update (--ca-name <name>|--ca-id <id>) [field options...]
anyca_cli [--config <path>] ca delete (--ca-name <name>|--ca-id <id>)
anyca_cli [--config <path>] ca publish-crl (--ca-name <name>|--ca-id <id>)
anyca_cli [--config <path>] ca ocsp-renew (--ca-name <name>|--ca-id <id>) [options]
anyca_cli [--config <path>] cert issue (--ca-name <name>|--ca-id <id>) --in <path> (--basic|--enforce) [options]
anyca_cli [--config <path>] cert new-root [options]
anyca_cli [--config <path>] cert record (--add|--delete) [options]
anyca_cli [--config <path>] cert revoke (--add|--delete) [options]
anyca_cli [--config <path>] cert list (--ca-name <name>|--ca-id <id>) [--revocation] [--n <count>]
anyca_cli [--config <path>] crl publish (--ca-name <name>|--ca-id <id>|--all)
anyca_cli [--config <path>] hsm list
anyca_cli [--config <path>] hsm token-info --provider <name> --token <label>
anyca_cli [--config <path>] hsm key-list --provider <name> --token <label> [--pin-source <path>|--pin-value <pin>]
anyca_cli [--config <path>] hsm key-info --key-uri <uri>
anyca_cli [--config <path>] hsm fetch-uri --provider <name> --token <label> --label <key-label> [--pin-source <path>|--pin-value <pin>]
anyca_cli [--config <path>] hsm search-key --in <path> --provider <name> --token <label> [--pin-source <path>|--pin-value <pin>]
anyca_cli [--config <path>] hsm keygen [options]
anyca_cli [--config <path>] hsm keydel --key-uri <uri>
anyca_cli [--config <path>] hsm pin-set --key-uri <uri> --new-pin <pin>
```

## 全局选项

| 选项                  | 说明                                     |
|-----------------------|------------------------------------------|
| `-c, --config <path>` | 指定 YAML 配置文件，默认 `config.yaml`。 |
| `-h, --help`          | 打印帮助并退出。                         |
| `-V, --version`       | 打印版本号并退出。                       |

全局选项既可以放在命令名之前，也可以放在命令名之后；以下三种写法等价：

```sh
anyca_cli -c /etc/anyca/config.yaml ca list
anyca_cli ca list -c /etc/anyca/config.yaml
anyca_cli ca list --config=/etc/anyca/config.yaml
```

长选项既支持 `--name value`，也支持 `--name=value` 两种写法。只有明确允许空值的选项才接受
空字符串。

帮助信息分为三级：

```sh
anyca_cli --help                      # 命令总览
anyca_cli ca --help                   # ca 的子命令
anyca_cli ca create --help            # ca create 的全部选项
```

以文件为输入的命令统一用 `--in` 指定输入文件，用 `--out` 指定输出文件。

相对路径均相对于**进程的当前工作目录**解析，而不是配置文件所在目录，也不
相对于可执行文件所在目录。这条规则适用于 `store.path`、`crl_publish_path`、
`cacerts_publish_path` 以及 `--in`、`--out`、`--pin-source` 等命令行路径。生产
环境建议使用绝对路径。

`anyca_server` 接受相同的 `-c`、`--config` 和 `--config=<path>` 写法，并可用
`-V`/`--version` 打印相同的版本号。

## 配置文件

配置文件采用 YAML 格式。示例参见 [example/config.yaml](example/config.yaml)。顶层字段
如下：

| 字段                       | 必需 | 说明                                                      |
|----------------------------|------|-----------------------------------------------------------|
| `store.path`               | 是   | SQLite 数据库路径。首次使用时自动创建表结构。             |
| `http.address`             | 是   | 服务器监听地址。                                          |
| `http.port`                | 是   | 服务器监听端口。                                          |
| `http.max_connections`     | 否   | libwebsockets 文件描述符上限，默认 1024。                 |
| `http.requests_per_second` | 否   | 单个客户端的请求速率上限，默认 1000 次/秒。               |
| `http.request_burst`       | 否   | 单个客户端在空闲后允许的突发请求数，默认 2000。           |
| `crl_publish_path`         | 否   | CRL 发布目录。未设置时不能发布 CRL。                      |
| `cacerts_publish_path`     | 否   | CA 证书发布目录。未设置时服务器不发布 CA 证书。           |
| `hsm_providers`            | 是   | PKCS #11 provider 列表，至少一项。                        |
| `certificate_usages`       | 否   | 证书用途配置，供 `--certificate-usage` 引用。             |
| `certificate_templates`    | 否   | AIA 和 CRL 分发点模板，供 `--certificate-template` 引用。 |
| `certificate_policies`     | 否   | 证书策略配置，供 `--certificate-policy` 引用。            |

即使某个命令不使用 HTTP 或某些配置项，YAML 结构本身仍要求 `store`、`http` 和
至少一个 `hsm_providers` 条目存在。

### `hsm_providers`

每一项用于描述一个 PKCS #11 模块：

```yaml
hsm_providers:
  - name: "softhsm"
    model: "SoftHSM v2"
    serial: "3dfe48398b2b6b63"   # 可选
    library: "/usr/lib/softhsm/libsofthsm2.so"
```

- `name` 是 URI 中 `provider=` 或 `hsm` 命令的 `--provider` 使用的名字。
- `library` 是 PKCS #11 模块路径。
- `model` 和 `serial` 均可选。URI 省略 `provider=` 时，CLI 用它们选择配置项。
- 不同 provider 可以指向不同模块；同一模块路径在同一进程中只加载一次。

### `certificate_usages`

每一项定义一组 keyUsage 位和可选的 extendedKeyUsage OID：

```yaml
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
      - "1.3.6.1.5.5.7.3.3"   # codeSigning
```

`basic_usages` 接受的名称：

| 名称                | keyUsage 位                                   |
|---------------------|-----------------------------------------------|
| `digitalSignature`  | digitalSignature                              |
| `nonRepudiation`    | nonRepudiation                                |
| `contentCommitment` | contentCommitment（与 nonRepudiation 同一位） |
| `keyEncipherment`   | keyEncipherment                               |
| `dataEncipherment`  | dataEncipherment                              |
| `keyAgreement`      | keyAgreement                                  |
| `keyCertSign`       | keyCertSign                                   |
| `cRLSign`           | cRLSign                                       |
| `encipherOnly`      | encipherOnly                                  |
| `decipherOnly`      | decipherOnly                                  |

`enhanced_usage_oids` 为空时不生成 extendedKeyUsage 扩展。签发自签名证书时
不会添加 EKU 扩展。

### `certificate_templates`

模板为签发的证书配置 AIA 和 CRL 分发点：

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

- `aia.issuer_uris` 生成 id-ad-caIssuers 条目。
- `aia.ocsp_uris` 生成 id-ad-OCSP 条目，供客户端自动发现 OCSP 服务的地址。
- `crl_uris` 生成 cRLDistributionPoints。
- 所有 URI 列表均可省略；不包含任何 URI 的模板不会添加扩展。

### `certificate_policies`

```yaml
certificate_policies:
  - name: "code-signing"
    cps:
      - oid: "2.23.140.1.4.1"
        uri: "https://example.com/cp/2.23.140.1.4.1/"   # 可选
```

每个 `cps` 条目都会添加一个证书策略 OID；如果提供 `uri`，还会添加 CPS URI 限定符。

### 存储数据库

- 数据库使用 WAL 模式。首次打开时自动创建表和索引。
- 程序会拒绝打开 schema 版本不兼容的数据库。升级版本后，请新建数据库，或按发布说明
  迁移。
- CA 配置中的 PIN 以明文形式保存，因为服务需要自动登录令牌。必须限制
  `store.db` 及其 `-wal`、`-shm` 文件的访问权限。
- 运行中的服务器会在存储发生变化时重新加载 CA 配置，无需重启。

## PKCS #11 URI

所有 HSM 密钥都使用 RFC 7512 风格的 PKCS #11 URI 标识。URI 分为路径部分和可选的
查询部分：

```text
pkcs11:[provider=<name>;][model=<model>;][serial=<serial>;]token=<label>;object=<label>[;type=private][?pin-value=<pin>]
pkcs11:[provider=<name>;][model=<model>;][serial=<serial>;]token=<label>;object=<label>?pin-source=<file>
```

路径部分的属性以 `;` 分隔，查询部分的属性以 `&` 分隔。

### 属性

| 属性           | 说明                                                          |
|----------------|---------------------------------------------------------------|
| `provider`     | AnyCA 扩展属性，引用 `hsm_providers` 中的 `name`。            |
| `token`        | PKCS #11 令牌标签，必需。                                     |
| `object`       | 密钥对象的 `CKA_LABEL`，必需。私钥和公钥使用同一个标签。      |
| `model`        | RFC 7512 标准属性；省略 `provider` 时用于选择 provider。      |
| `serial`       | RFC 7512 标准属性；省略 `provider` 时用于细化 provider 选择。 |
| `manufacturer` | 为兼容 RFC 7512 而接受，但不参与匹配。                        |
| `type`         | 只接受 `private`。                                            |
| `pin-value`    | 直接给出令牌用户 PIN。                                        |
| `pin-source`   | 从文件读取 PIN，去掉末尾的 CR/LF。                            |

约束：

- URI 必须包含 `token`、`object`，并且必须提供 `pin-value` 或 `pin-source`
  之一，二者不能同时出现。
- 还必须至少提供 `provider`、`model`、`serial` 中的一个来定位 provider。
- `pin-source` 指向的文件不能为空，也不能包含 NUL 字节。该文件必须是普通文件
  （拒绝符号链接），属主为当前用户或 root，且不得有任何组或其他用户权限位；
  否则拒绝读取 PIN。
- 属性值支持 `%XX` 转义。值中的字面 `;`、`&`、`?`、`=` 必须百分号编码。
- 由于 `;`、`?`、`&` 是 Shell 元字符，URI 必须加引号。

### provider 的选择规则

指定 `provider` 时：

- 该名称必须存在于 `hsm_providers` 中。
- 如果 URI 和配置项都声明了 `model`，两者必须相同；配置项没有声明 `model`
  时不做检查。
- `serial` 的规则相同。

省略 `provider` 时：

- CLI 只考虑声明值与 URI 属性不冲突的配置项。
- 声明了 URI 中全部选择属性的配置项优先；例如 URI 同时给出 `model` 和
  `serial` 时，两项都声明的配置项优先于只声明其中一项的配置项。
- 最终必须且只能匹配一个配置项，否则命令报错。

示例：

```sh
# 使用 provider 名称
--key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-ca-key?pin-source=/etc/anyca/token.pin'

# 使用标准属性
--key-uri 'pkcs11:model=SoftHSM%20v2;serial=3dfe48398b2b6b63;token=AnyCA;object=root-ca-key?pin-value=1234'
```

同一进程再次打开同一令牌时，会共享登录状态和会话池。不同模块中同名标签的
令牌仍是彼此独立的令牌。

## 取值格式

### 可分辨名称（DN）

`--subject` 接受两种写法：

```text
CN=Example,O=AnyCA,C=CN
/CN=Example/O=AnyCA/C=CN
```

属性类型使用 OpenSSL 支持的短名称（如 `CN`、`O`、`OU`、`C`、`ST`、`L`、
`emailAddress`）。值支持 RFC 2253 风格的反斜杠转义，例如 `\,`、`\+`、
`\\`。属性名和值两端的空格会被去掉。

### 序列号

`--serial` 使用十六进制表示，可以带 `0x` 前缀，也允许前导零。规则：

- 最多 20 字节；
- 不能全为零；
- 恰好 20 字节时，最高位不能为 1（必须是非负整数）；
- CLI 输出序列号时使用大写十六进制。

### 时间

`--not-after` 和 `--revoked-at` 使用 Unix 时间（从 1970-01-01 UTC 起的秒数）。
`cert list`、`ca list` 等命令输出的时间同样是 Unix 时间。

### CA 选择

`--ca-name` 和 `--ca-id` 互斥；具体命令可能要求必须指定其中一个：

- `--ca-name` 按 CA 配置名称选择。
- `--ca-id` 按 `ca list` 输出的数字 id 选择。该 id 对应存储中登记的 CA 身份；
  只有当登记时的公钥哈希与当前 CA 证书匹配时才接受。重新生成密钥或替换证书后，
  旧 id 会被拒绝，此时请改用 `--ca-name`。

### 布尔值

`--is-ca` 接受 `true`、`yes`、`1`、`false`、`no`、`0`，不区分大小写。

### 哈希算法

证书命令的 `--digest` 和 CA 命令的 `--ocsp-signer-hash-algorithm` 接受
`sha1`、`sha256`、`sha384`、`sha512`，不区分大小写。默认是 `sha384`。

### 证书和请求文件

- CA 证书、签发结果以及 `cert record --in` 和 `cert revoke --in` 都是 DER。
- `cert issue --in` 接受 PEM 或 DER 编码的 PKCS #10 请求。
- `hsm search-key --in` 接受 DER 或 PEM 编码的证书、PKCS #10 请求或
  SubjectPublicKeyInfo 公钥。

## CA 命令

CA 配置保存在存储数据库中，其中包括 CA 密钥位置、OCSP 签名密钥位置、两份 DER
证书、CRL 周期、OCSP nextUpdate 周期和响应端点。运行中的服务器会在存储发生变化
时重新加载这些配置。

### `ca create`

创建一个新的自签名 CA：

1. 在 `--key-uri` 指定的令牌中生成 CA 密钥对；
2. 在 `--ocsp-key-uri` 指定的令牌中生成 OCSP 签名密钥对；
3. 生成自签名 CA 证书和由该 CA 签发的 OCSP 签名证书；
4. 把 CA 配置、证书和密钥 URI 写入存储。

| 选项                                                    | 说明                                                                              |
|---------------------------------------------------------|-----------------------------------------------------------------------------------|
| `--name <name>`                                         | CA 名称，必填。不能包含 `/`、`\`、`:`，也不能是 `.` 或 `..`。                     |
| `--key-uri <uri>`                                       | CA 密钥 URI；URI 的 `object` 是要新建的密钥标签，必填。                           |
| `--ocsp-key-uri <uri>`                                  | OCSP 签名密钥 URI；URI 的 `object` 是要新建的密钥标签，必填。                     |
| `--ocsp-responder-endpoint <name>`                      | OCSP 端点名称，不能包含 `/`，必填。                                               |
| `--subject <dn>`                                        | CA 主题。默认 `CN=<名称>`，特殊字符会被转义。                                     |
| `--certificate-usage <name>`                            | 使用的 `certificate_usages` 配置项。默认 `ca`。                                   |
| `--key-type <rsa\|ec\|ml-dsa-44\|ml-dsa-65\|ml-dsa-87>` | 生成的密钥类型。默认 `rsa`。                                                      |
| `--rsa-bits <n>`                                        | RSA 模长，`2048`–`16384`。默认 `3072`。仅 RSA。                                   |
| `--ec-curve <p256\|p384\|p521>`                         | EC 曲线。默认 `p384`。仅 EC。                                                     |
| `--ocsp-signer-hash-algorithm <alg>`                    | CA 证书和 OCSP 签名证书使用的签名摘要算法。默认 `sha384`。                        |
| `--crl-publish-period-min <n>`                          | CRL nextUpdate 周期（分钟）。默认 `10080`（7 天）。`0` 表示不启动周期发布定时器。 |
| `--ocsp-update-period-min <n>`                          | OCSP nextUpdate 周期（分钟）。默认 `10`。`0` 表示响应中不包含 nextUpdate。        |

`--crl-publish-period-min 0` 只关闭周期发布：CA 仍会在服务器启动时发布一次，
也可用 `crl publish` 手动发布，但定时器不会自动续发。发布的 CRL 始终包含
nextUpdate；周期为 `0` 时使用默认的 7 天。

说明：

- `--key-type` 同时作用于两对新生成的密钥；`--rsa-bits` 仅用于 RSA，
  `--ec-curve` 仅用于 EC。
- 两个 `object` 标签在对应令牌中均不得预先存在，否则命令在生成任何密钥前失败。
- 重复的 CA 名称或 OCSP 端点同样会在生成密钥前被拒绝。
- 生成的 CA 证书有效期为 3650 天，OCSP 签名证书有效期同样为 3650 天。
- OCSP 签名证书主体默认为 `CN=<CA 名称> OCSP Signer`，包含以下固定扩展：
  关键的 keyUsage `digitalSignature`、关键的 basicConstraints（`cA=false`）和
  OCSPSigning extendedKeyUsage。notBefore 提前一小时，使证书立即可用。
- `--ocsp-signer-hash-algorithm` 的值会随 CA 保存，供后续 `ca ocsp-renew`
  默认使用。
- 生成密钥后，如果某个步骤失败，本次创建的密钥对会被删除。如果删除也失败，
  CLI 会打印警告，需要手工清理令牌。
- 两个 URI 可以指向不同的 `hsm_providers`，因此 CA 密钥和 OCSP 签名密钥可以
  位于不同的 PKCS #11 模块。
- ML-DSA 需要实现了 `CKM_ML_DSA_KEY_PAIR_GEN` 和 `CKM_ML_DSA` 的 PKCS #11 3.2
  provider；SoftHSM 2.6 不支持。`--ocsp-signer-hash-algorithm` 对 ML-DSA
  证书无效，因为 ML-DSA 直接对 TBS 签名。

成功时输出：

```text
Created CA: root-ca
```

示例：

```sh
anyca_cli ca create --name root-ca \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-ca-key?pin-source=/etc/anyca/token.pin' \
  --ocsp-key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-ca-ocsp-key?pin-source=/etc/anyca/token.pin' \
  --ocsp-responder-endpoint root-ca \
  --subject 'CN=Example Root CA,O=Example,C=US' \
  --key-type ec --ec-curve p384 \
  --crl-publish-period-min 60 --ocsp-update-period-min 10
```

### `ca import`

导入已有 CA。CA 证书以 DER 格式读入并保存到数据库，CA 私钥必须已位于
PKCS #11 令牌中。命令会用 CA 密钥为指定的 OCSP 签名密钥生成一张 OCSP 签名证书。

| 选项                                 | 说明                                                                  |
|--------------------------------------|-----------------------------------------------------------------------|
| `--name <name>`                      | CA 名称，必填。                                                       |
| `--key-uri <uri>`                    | CA 私钥的 PKCS #11 URI，必填。                                        |
| `--in <path>`                        | DER 编码的 CA 证书，必填，且必须与 CA 密钥匹配。                      |
| `--ocsp-key-uri <uri>`               | OCSP 签名密钥的 PKCS #11 URI，必填。                                  |
| `--ocsp-responder-endpoint <name>`   | OCSP 端点名称，不能包含 `/`，必填。                                   |
| `--ocsp-signer-hash-algorithm <alg>` | 生成 OCSP 签名证书使用的摘要算法。默认 `sha384`，并随 CA 保存。       |
| `--crl-publish-period-min <n>`       | CRL nextUpdate 周期（分钟）。默认 `10080`；`0` 表示不启动周期定时器。 |
| `--ocsp-update-period-min <n>`       | OCSP nextUpdate 周期（分钟）。默认 `10`；`0` 表示不包含 nextUpdate。  |

`--crl-publish-period-min 0` 只关闭周期发布：CA 仍会在服务器启动时发布一次，
也可用 `crl publish` 手动发布，但定时器不会自动续发。发布的 CRL 始终包含
nextUpdate；周期为 `0` 时使用默认的 7 天。

导入前会执行以下检查：

| 检查项                                                                     | 失败行为                 |
|----------------------------------------------------------------------------|--------------------------|
| CA 证书可以按 DER 解析                                                     | 导入失败，不登记任何内容 |
| CA 证书确实是 CA 证书（`X509_check_ca`）                                   | 导入失败，不登记任何内容 |
| CA 密钥与 CA 证书匹配                                                      | 导入失败，不登记任何内容 |
| OCSP 签名密钥与生成的 OCSP 签名证书匹配                                    | 导入失败，不登记任何内容 |
| 生成的 OCSP 签名证书对该 CA 有效（由该 CA 直接签发并包含 OCSPSigning EKU） | 导入失败，不登记任何内容 |
| CA 名称和 OCSP 端点未被占用                                                | 在写入 CA 记录前拒绝     |

密钥与证书的匹配检查通过以下方式完成：“用 HSM 密钥对固定挑战数据签名，再用
证书公钥验证签名”，因此即使令牌中的公钥对象被替换，也无法通过检查。全部检查通过后，
才会保留 CA 配置；失败时会回滚已写入的记录，如果回滚本身失败，CLI 会打印
警告。

成功时输出：

```text
Imported CA: existing-ca
```

示例：

```sh
anyca_cli ca import --name existing-ca \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=existing-ca-key?pin-source=/etc/anyca/token.pin' \
  --in /etc/anyca/existing-ca.der \
  --ocsp-key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=existing-ca-ocsp-key?pin-source=/etc/anyca/token.pin' \
  --ocsp-responder-endpoint existing-ca \
  --crl-publish-period-min 60 --ocsp-update-period-min 10
```

如果要把一张由父 CA 签发的证书注册为下级 CA，先用父 CA 执行
`cert issue --basic --is-ca true --certificate-usage ca`，再用 `ca import`
注册生成的证书。

### `ca list`

列出存储中的 CA 配置及其当前身份：

```sh
anyca_cli ca list
```

输出示例：

```text
CA root-ca (id 1)
  key: softhsm/AnyCA/root-ca-key
  OCSP signer: softhsm/AnyCA/root-ca-ocsp-key
  OCSP digest: sha384
  endpoint: root-ca
  periods: CRL 60 min, OCSP 10 min, CRL number 1794905864
  key hash: 19683FFEEE3393923FE039F112B51ACF88EC6D44F7300BCB3F90C07944C1F296
```

各项含义：

- `id` 是存储中登记的 CA 身份编号，可用于 `--ca-id`。如果 CA 还没有登记身份，
  这里显示 `(not registered)`。
- `key` 和 `OCSP signer` 显示 provider、令牌标签和密钥标签，不显示 PIN。
- `key hash` 是 CA 证书 DER SubjectPublicKeyInfo 的 SHA-256。
- `CRL number` 是最近一次预留的 CRL 编号。首次发布前为 `0`，第一次预留以当前
  Unix 时间为起点，之后保持单调递增。

### `ca update`

修改已存储的 CA 配置。必须使用 `--ca-name` 或 `--ca-id` 指定 CA，并至少提供一个
待修改字段：

| 选项                                 | 说明                                                  |
|--------------------------------------|-------------------------------------------------------|
| `--key-uri <uri>`                    | 替换 CA 的 provider、令牌、PIN 和密钥标签。           |
| `--in <path>`                        | 替换存储中的 CA 证书（DER）。                         |
| `--ocsp-key-uri <uri>`               | 替换 OCSP 签名密钥的 provider、令牌、PIN 和密钥标签。 |
| `--ocsp-signer-hash-algorithm <alg>` | 修改保存的 OCSP 签名摘要算法。                        |
| `--crl-publish-period-min <n>`       | 修改 CRL 周期。                                       |
| `--ocsp-update-period-min <n>`       | 修改 OCSP nextUpdate 周期。                           |
| `--ocsp-responder-endpoint <name>`   | 修改 OCSP 端点。                                      |

说明：

- CA 名称是主键，不能用这个命令修改。
- 修改后的端点不能与其他 CA 冲突。
- 提供 `--key-uri`、`--in` 或 `--ocsp-key-uri` 时，命令会在写入前校验新的身份：
  CA 密钥必须与 CA 证书匹配；OCSP 签名密钥必须与由该 CA 直接签发、带
  OCSPSigning EKU 的签名证书匹配。
- 指定 `--ocsp-key-uri` 时总是重新签发 OCSP 签名证书（旧证书不可能匹配新密钥）；
  只指定 `--key-uri` 或 `--in` 时，仅当保存的签名证书不再可用时才重新签发。
  重新签发的证书会登记为该 CA 的已签发证书。
- 校验或重新签发失败时命令返回非零，不修改已保存的 CA 配置。
- `--in` 仅适用于同一 CA 身份（主体和密钥不变）的证书续期。更换主体或密钥会改变
  签发者身份：旧证书的 OCSP 将返回 `unknown`，也无法使用新发布的 CRL。轮换步骤
  见 `DEPLOY.zh-cn.md`。更换密钥后旧的 `--ca-id` 不再匹配该 CA，请改用
  `--ca-name`。
- 运行中的服务器会在处理下一次 OCSP 请求或 CRL 调度时重新加载修改后的配置。

```sh
anyca_cli ca update --ca-name root-ca \
  --crl-publish-period-min 30 --ocsp-update-period-min 10
```

成功时输出修改的字段数量和生效时机提示。

### `ca delete`

删除 CA 配置：

```sh
anyca_cli ca delete --ca-name root-ca
```

此命令仅删除 CA 配置，不会删除：

- 存储中的已签发证书记录和吊销记录；
- 令牌中的 CA 密钥或 OCSP 签名密钥；
- 发布目录中的 CRL 和 CA 证书文件。

如果需要删除密钥，请使用 `hsm keydel` 或 PKCS #11 厂商工具。

删除配置后，若令牌中仍保留同名密钥对象，用相同标签重新创建 CA 会因
`HSM_ERR_DUPLICATE` 失败；请先删除旧密钥对象，或改用新的标签。

### `ca publish-crl`

为一个 CA 构建、签名并发布 CRL：

```sh
anyca_cli ca publish-crl --ca-name root-ca
```

该命令要求已配置 `crl_publish_path`。它会按服务器启动时相同的规则加载 CA，
校验目标 CA 的密钥与证书，然后用 CA 密钥签名 CRL，并写入：

```text
<crl_publish_path>/<CA 名称>/<CA 名称>.crl
```

该文件是 DER 编码。`crl publish` 执行相同操作，另外支持 `--all`。

### `ca ocsp-renew`

创建或续签某个 CA 的 OCSP 签名证书。

| 选项                                 | 说明                                                                  |
|--------------------------------------|-----------------------------------------------------------------------|
| `--ca-name <name>`                   | 存储中的 CA。与 `--ca-id` 二选一，必填。                              |
| `--ca-id <id>`                       | 按 `ca list` 输出的 id 指定 CA。与 `--ca-name` 互斥。                 |
| `--subject <dn>`                     | 证书主体。默认 `CN=<CA 名称> OCSP Signer`。                           |
| `--days <n>`                         | 有效期（天），`1`–`365000`。默认 `3650`。                             |
| `--ocsp-signer-hash-algorithm <alg>` | 本次使用的签名摘要算法。默认使用 CA 保存的值（未设置时为 `sha384`）。 |
| `--serial <hex>`                     | 序列号，最多 20 字节。默认随机。                                      |
| `--out <path>`                       | 额外把 DER 证书写到该文件。                                           |

行为说明：

- CA 密钥和 OCSP 签名密钥从已存储的 CA 配置读取。
- 无论现有 OCSP 签名证书是否过期，都会被新证书替换。
- 新证书会登记为该 CA 的已签发证书，因此会出现在 `cert list` 中。
- `--ocsp-signer-hash-algorithm` 只影响本次生成的证书，不会修改数据库中保存的
  默认值。
- 扩展固定为：关键的 keyUsage `digitalSignature`、关键的 basicConstraints
  （`cA=false`）、OCSPSigning extendedKeyUsage。notBefore 提前一小时。
- 新证书会先登记为该 CA 的已签发证书，然后写入 `--out`，最后更新 CA 配置。
  `--out` 使用原子发布（同目录临时文件后 rename）；如果写入失败，命令返回失败、
  不打印成功提示，CA 当前使用的 OCSP 签名证书保持不变（已签发证书记录仍保留）。
- 运行中的服务器会在下一次 OCSP 响应时使用新证书，无需重启。

```sh
anyca_cli ca ocsp-renew --ca-name root-ca --days 30 \
  --ocsp-signer-hash-algorithm sha512 --out ocsp-signer.der
```

成功时输出已存储的证书字节数，并提示生效时机。

## 证书命令

`cert issue` 使用已存储的 CA 根据证书请求签发证书；`cert new-root` 生成独立的自签名
根证书；`cert record`、`cert revoke` 和 `cert list` 管理存储中的证书清单。

### OCSP 状态如何确定

OCSP 响应程序根据存储中的记录确定证书状态：

| OCSP 状态 | 条件                           |
|-----------|--------------------------------|
| `good`    | 序列号已登记，且没有吊销记录。 |
| `revoked` | 存在该序列号的吊销记录。       |
| `unknown` | 序列号没有登记。               |

因此，`cert issue` 签发的证书会自动登记，状态立即为 `good`。对于由其他工具签发
的证书，需要用 `cert record --add` 手工登记，否则 OCSP 会返回 `unknown`。
吊销前证书必须已登记；`cert revoke --add` 会自动补一条占位记录。

### `cert issue`

使用已存储的 CA 签发 PKCS #10 请求。

| 选项                            | 说明                                                                         |
|---------------------------------|------------------------------------------------------------------------------|
| `--ca-name <name>`              | 签发 CA。与 `--ca-id` 二选一，必填。                                         |
| `--ca-id <id>`                  | 按 `ca list` 输出的 id 指定签发 CA。                                         |
| `--in <path>`                   | PKCS #10 请求，DER 或 PEM，必填。                                            |
| `--basic`                       | 只复制请求中的主体，扩展由配置生成。                                         |
| `--enforce`                     | 按请求中的扩展直接签发。                                                     |
| `--is-ca <true\|false>`         | basicConstraints 的 cA 值。使用 `--basic` 时必填。                           |
| `--path-length <n\|none>`       | basicConstraints 的 pathLenConstraint。默认不包含；要求 `--is-ca true`。     |
| `--certificate-usage <name>`    | `certificate_usages` 配置项。使用 `--basic` 时必填。                         |
| `--certificate-template <name>` | `certificate_templates` 配置项，添加 AIA 和 CRL 分发点。仅 `--basic` 可用。  |
| `--certificate-policy <name>`   | `certificate_policies` 配置项，添加 certificatePolicies。仅 `--basic` 可用。 |
| `--days <n>`                    | 有效期（天），`1`–`365000`。默认 `3650`。                                    |
| `--digest <alg>`                | 签名摘要算法。默认 `sha384`。                                                |
| `--serial <hex>`                | 序列号，最多 20 字节。默认随机 16 字节。                                     |
| `--out <path>`                  | 输出 DER 证书，必填。                                                        |
| `--no-aki`                      | 不添加 authorityKeyIdentifier。                                              |
| `--no-ski`                      | 不添加 subjectKeyIdentifier。                                                |

`--basic` 和 `--enforce` 必须指定且只能指定其中一个。

#### basic 模式

- 仅复制请求中的 subject 和公钥，忽略请求中的所有扩展。
- 始终添加关键的 basicConstraints 和 keyUsage。
- 当用途配置包含 `enhanced_usage_oids` 时，添加非关键的 extendedKeyUsage。
- `--certificate-template` 添加 authorityInfoAccess 和
  cRLDistributionPoints。
- `--certificate-policy` 添加 certificatePolicies，包括可选的 CPS URI 限定符。
- CA 证书会添加根据公钥计算的 subjectKeyIdentifier；非 CA 证书不添加 SKI。
- 默认添加 authorityKeyIdentifier。
- 如果用途配置包含 `keyCertSign`，必须同时指定 `--is-ca true`。

#### enforce 模式

- 按请求中的扩展签发；除 subjectKeyIdentifier 和 authorityKeyIdentifier
  外，复制请求中的所有其他扩展。
- 即使请求把 keyUsage 或 basicConstraints 标记为非关键，输出证书仍会把它们
  设为关键扩展。
- 所有请求的扩展都会原样复制，因此 CSR 可以请求 CA basicConstraints 或任意
  keyUsage。CLI 使用该模式时会打印警告，签发前应检查请求内容。
- 从请求的 basicConstraints 扩展读取 cA 值；没有该扩展时按非 CA 证书处理。
- 不接受 `--is-ca`、`--path-length`、`--certificate-usage`、
  `--certificate-template` 和 `--certificate-policy`。
- CA 证书添加计算得到的 subjectKeyIdentifier；非 CA 证书保留请求中的
  subjectKeyIdentifier（如果请求带有）。
- 默认添加 authorityKeyIdentifier。

#### 两种模式共同的行为

- 请求必须先通过自签名校验；签名无效或格式错误时不会签发。
- `--no-aki` 和 `--no-ski` 分别关闭对应扩展。
- 签发的证书先登记到该 CA 的已签发证书记录，然后写入 `--out`，因此客户端能
  取到的证书一定可以被吊销。
- 如果序列号已登记，则更新其 notAfter，而不是插入重复记录。
- `--out` 使用原子发布（同目录临时文件后 rename）。如果写入失败，登记仍然保留，
  命令返回失败且不打印成功提示。

示例：

```sh
# basic：主体来自 CSR，扩展来自配置。
anyca_cli cert issue --ca-name root-ca --in leaf.csr \
  --basic --is-ca false --certificate-usage code-signing \
  --certificate-template default --certificate-policy code-signing \
  --out leaf.der

# enforce：按 CSR 中请求的扩展签发。
anyca_cli cert issue --ca-name root-ca --in leaf.csr --enforce \
  --out leaf.der

# 下级 CA：先签发 CA 证书，再用 ca import 注册。
anyca_cli cert issue --ca-name root-ca --in sub-ca.csr \
  --basic --is-ca true --path-length 0 --certificate-usage ca \
  --out sub-ca.der

anyca_cli ca import --name sub-ca --in sub-ca.der \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=sub-ca-key?pin-source=token.pin' \
  --ocsp-key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=sub-ca-ocsp-key?pin-source=token.pin' \
  --ocsp-responder-endpoint sub-ca
```

### `cert new-root`

生成一张自签名证书。签发密钥与主体密钥是同一个 HSM 密钥。

| 选项                            | 说明                                                 |
|---------------------------------|------------------------------------------------------|
| `--subject <dn>`                | 主体可分辨名称，必填。                               |
| `--key-uri <uri>`               | 作为主体公钥和签名密钥的 PKCS #11 URI，必填。        |
| `--certificate-usage <name>`    | `certificate_usages` 配置项，必填。                  |
| `--certificate-template <name>` | 可选的 `certificate_templates` 配置项。              |
| `--is-ca <true\|false>`         | basicConstraints 的 cA 值。默认 `true`。             |
| `--path-length <n\|none>`       | pathLenConstraint。默认不包含；要求 `--is-ca true`。 |
| `--days <n>`                    | 有效期（天），`1`–`365000`。默认 `3650`。            |
| `--digest <alg>`                | 签名摘要算法。默认 `sha384`。                        |
| `--serial <hex>`                | 序列号，最多 20 字节。默认随机 16 字节。             |
| `--out <path>`                  | 输出 DER 证书，必填。                                |

行为说明：

- 该命令只读取配置和 HSM，不打开存储数据库。
- 证书写入 `--out`，但**不会注册为 CA**。要创建受管理的自签名 CA，请使用
  `ca create`。
- 始终添加 subjectKeyIdentifier、basicConstraints 和 keyUsage。
- 不添加 authorityKeyIdentifier，也不添加 extendedKeyUsage。
- 用途配置包含 `keyCertSign` 时要求 `--is-ca true`。
- 指定模板时，模板会添加 AIA 和 cRLDistributionPoints。

```sh
anyca_cli cert new-root --subject "CN=AnyCA Root,O=AnyCA,C=CN" \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-key?pin-value=1234' \
  --certificate-usage ca --is-ca true --path-length 1 --days 7300 \
  --out root.der
```

### `cert record`

添加或删除已签发证书记录。此命令用于把外部工具签发的证书纳入 OCSP 管理。

| 选项                 | 说明                                                                             |
|----------------------|----------------------------------------------------------------------------------|
| `--add`              | 添加证书记录。与 `--delete` 二选一，必填。                                       |
| `--delete`           | 删除证书记录。仍处于吊销状态的记录不能删除。                                     |
| `--in <path>`        | DER 证书，用于推导签发 CA、序列号和 notAfter。                                   |
| `--ca-name <name>`   | 签发 CA。不使用 `--in` 时必填；与 `--ca-id` 互斥。                               |
| `--ca-id <id>`       | 按 `ca list` 输出的 id 指定签发 CA。                                             |
| `--serial <hex>`     | 证书序列号。不使用 `--in` 时必填；与 `--in` 同用时必须匹配。                     |
| `--not-after <time>` | notAfter，Unix 时间，仅 `--add` 可用。使用 `--in` 时默认取证书值，否则默认 `0`。 |

使用 `--in` 时：

- CLI 会用每个已配置的 CA 验证该证书，以确定签发 CA。如果多个 CA 都能验证，
  必须显式指定 `--ca-name` 或 `--ca-id`。
- 如果指定了 CA，证书必须确实由该 CA 签发（包括签名校验）。
- `--serial` 可选；提供时必须与证书中的序列号一致。

不使用 `--in` 时：

- 必须提供 `--ca-name` 或 `--ca-id`，以及 `--serial`。
- 不提供 `--not-after` 时，记录中的 notAfter 为 `0`（未知）。

示例：

```sh
anyca_cli cert record --add --in leaf.der --ca-name root-ca
anyca_cli cert record --delete --in leaf.der
anyca_cli cert record --delete --ca-name root-ca --serial 6619A5CE9DF9B325DB30BC4EF45C3D29
```

### `cert revoke`

添加或删除吊销记录。

| 选项                  | 说明                                                         |
|-----------------------|--------------------------------------------------------------|
| `--add`               | 记录吊销。与 `--delete` 二选一，必填。                       |
| `--delete`            | 删除吊销记录，使证书恢复为 `good`。                          |
| `--in <path>`         | DER 证书，用于推导签发 CA 和序列号。                         |
| `--ca-name <name>`    | 签发 CA。不使用 `--in` 时必填；与 `--ca-id` 互斥。           |
| `--ca-id <id>`        | 按 `ca list` 输出的 id 指定签发 CA。                         |
| `--serial <hex>`      | 证书序列号。不使用 `--in` 时必填；与 `--in` 同用时必须匹配。 |
| `--revoked-at <time>` | 吊销时间，Unix 时间，仅 `--add` 可用。默认当前时间。         |
| `--reason <n>`        | RFC 5280 reasonCode，仅 `--add` 可用。默认 `0`。             |

使用 `--in` 时的 CA 匹配规则与 `cert record` 相同。

`--add`：

- 如果证书尚未登记，CLI 会先写入一条占位证书记录，并打印警告。占位记录的
  notAfter 来自 `--in`，没有 `--in` 时为 `0`。
- 重复吊销同一证书会报错。
- `--reason` 接受 `0`–`10`，但排除 `7`。

`--delete`：

- 删除吊销记录，证书记录本身保留。
- 如果证书没有吊销记录，命令报错。
- `--revoked-at` 和 `--reason` 不能与 `--delete` 一起使用。

RFC 5280 reasonCode：

| 值   | 含义                 |
|------|----------------------|
| `0`  | unspecified          |
| `1`  | keyCompromise        |
| `2`  | cACompromise         |
| `3`  | affiliationChanged   |
| `4`  | superseded           |
| `5`  | cessationOfOperation |
| `6`  | certificateHold      |
| `7`  | 未使用，不能指定     |
| `8`  | removeFromCRL        |
| `9`  | privilegeWithdrawn   |
| `10` | aACompromise         |

```sh
anyca_cli cert revoke --add --in leaf.der --reason 1
anyca_cli cert revoke --delete --in leaf.der
```

### `cert list`

列出某个 CA 的证书记录或吊销记录。

| 选项               | 说明                                          |
|--------------------|-----------------------------------------------|
| `--ca-name <name>` | 存储中的 CA。与 `--ca-id` 二选一，必填。      |
| `--ca-id <id>`     | 按 `ca list` 输出的 id 指定 CA。              |
| `--revocation`     | 列出吊销记录而不是证书记录。                  |
| `--n <count>`      | 只列出最近的 `<count>` 条记录，必须为正整数。 |

证书记录按 notAfter 从新到旧排列，notAfter 相同的按序列号从大到小排列；
notAfter 未知的记录排在最后。吊销记录按 revokedAt 从新到旧排列。

证书记录的输出包含序列号、notAfter，以及证书已吊销时的吊销时间和 reason；
吊销记录的输出包含序列号、revokedAt 和 reason。所有时间都是 Unix 时间。

```sh
anyca_cli cert list --ca-name root-ca
anyca_cli cert list --ca-name root-ca --revocation --n 20
```

## CRL 命令

### `crl publish`

为一个或全部 CA 构建、签名并发布 CRL：

```sh
anyca_cli crl publish --ca-name root-ca
anyca_cli crl publish --all
```

- `--ca-name`、`--ca-id` 和 `--all` 互斥，必须指定其中一个。
- 要求配置了 `crl_publish_path`。
- 命令会按服务器启动时相同的规则加载 CA，并校验目标 CA 的密钥和证书。
- CRL 使用 CA 密钥签名，摘要固定为 SHA-384，包含 CRL Number 和
  authorityKeyIdentifier。
- 输出文件为 `<crl_publish_path>/<CA 名称>/<CA 名称>.crl`，DER 编码。
- 使用 `--all` 时，如果部分 CA 发布失败，命令会报告失败数量并返回非零状态；
  其余 CA 仍会继续发布。

## HSM 命令

HSM 命令用于查看和管理 `hsm_providers` 条目及其令牌。所有命令仅读取配置文件和
PKCS #11 模块，不打开存储数据库。

`hsm key-list`、`hsm fetch-uri` 和 `hsm search-key` 直接接受 `--provider` 和
`--token`；其余与密钥相关的命令使用完整的 PKCS #11 URI。

需要 PIN 时：

- `--pin-source <path>` 从文件读取 PIN，去掉末尾的 CR/LF；
- `--pin-value <pin>` 直接在命令行给出 PIN；
- 两者互斥。

### `hsm list`

列出配置中的所有 HSM provider：

```sh
anyca_cli hsm list
```

输出包含 provider 名称、模块路径、model 和 serial。未配置的字段显示 `<unset>`。

### `hsm token-info`

打开指定 provider 的 PKCS #11 模块，查找指定令牌但不登录，并打印模块和令牌信息：

| 选项                | 说明                           |
|---------------------|--------------------------------|
| `--provider <name>` | `hsm_providers` 配置项，必填。 |
| `--token <label>`   | 令牌标签，必填。               |

输出包括模块厂商、描述、Cryptoki 版本、库版本，以及令牌的厂商、型号、序列号、
标志、登录状态和会话数。

```sh
anyca_cli hsm token-info --provider softhsm --token AnyCA
```

### `hsm key-list`

列出指定令牌中的 RSA、EC 和 ML-DSA 密钥对象：

| 选项                  | 说明                           |
|-----------------------|--------------------------------|
| `--provider <name>`   | `hsm_providers` 配置项，必填。 |
| `--token <label>`     | 令牌标签，必填。               |
| `--pin-source <path>` | 从文件读取 PIN 并登录。        |
| `--pin-value <pin>`   | 在命令行给出 PIN 并登录。      |

每个私钥对象和公钥对象各输出一条记录。同一密钥对的标签相同。

```text
Key: ca-key
  algorithm: RSA2048
  type: private
  uri: pkcs11:provider=softhsm;token=AnyCA;object=ca-key

Key: ca-key
  algorithm: RSA2048
  type: public
  uri: pkcs11:provider=softhsm;token=AnyCA;object=ca-key
```

说明：

- 不提供 PIN 时不登录令牌，许多令牌只暴露公钥对象。
- 提供 `--pin-source` 或 `--pin-value` 后会登录令牌，同时列出私钥对象。
- 输出中的 URI 不含 PIN。传给需要 `--key-uri` 的命令前，请追加
  `?pin-value=<PIN>` 或 `?pin-source=<文件>`。
- 没有可见密钥时输出 `No keys found in token <label>.`。

```sh
anyca_cli hsm key-list --provider softhsm --token AnyCA \
  --pin-source /etc/anyca/token.pin
```

### `hsm key-info`

读取 URI 中 `object` 对应的公钥，并打印密钥类型和长度：

| 选项              | 说明                      |
|-------------------|---------------------------|
| `--key-uri <uri>` | PKCS #11 密钥 URI，必填。 |

RSA 密钥输出模长位数；EC 密钥输出曲线名称和编码后的点长度；ML-DSA 密钥输出
参数集和原始公钥长度。

```sh
anyca_cli hsm key-info \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-ca-key?pin-source=/etc/anyca/token.pin'
```

### `hsm fetch-uri`

根据 provider、令牌和密钥标签生成 PKCS #11 URI：

| 选项                  | 说明                           |
|-----------------------|--------------------------------|
| `--provider <name>`   | `hsm_providers` 配置项，必填。 |
| `--token <label>`     | 令牌标签，必填。               |
| `--label <key-label>` | 密钥的 `CKA_LABEL`，必填。     |
| `--pin-source <path>` | 在 URI 中加入 `pin-source`。   |
| `--pin-value <pin>`   | 在 URI 中加入 `pin-value`。    |

所有值都会做百分号编码。提供 PIN 选项时，URI 会带上相同的 PIN，可以直接作为
CA 和证书命令的 `--key-uri` 使用。

```sh
anyca_cli hsm fetch-uri --provider softhsm --token AnyCA \
  --label root-ca-key --pin-source /etc/anyca/token.pin
```

输出示例：

```text
pkcs11:provider=softhsm;token=AnyCA;object=root-ca-key?pin-source=%2Fetc%2Fanyca%2Ftoken.pin
```

该命令只读取配置来校验 provider 名称，不打开令牌，因此不会检查密钥标签是否
存在。未提供 PIN 选项时，输出 URI 不含查询部分，使用前需要自行追加凭据。

### `hsm search-key`

查找公钥与给定证书、证书请求或公钥相匹配的令牌密钥：

| 选项                  | 说明                                               |
|-----------------------|----------------------------------------------------|
| `--in <path>`         | DER 或 PEM 格式的证书、PKCS #10 请求或公钥，必填。 |
| `--provider <name>`   | `hsm_providers` 配置项，必填。                     |
| `--token <label>`     | 令牌标签，必填。                                   |
| `--pin-source <path>` | 从文件读取 PIN 并登录。                            |
| `--pin-value <pin>`   | 在命令行给出 PIN 并登录。                          |

说明：

- 命令提取输入中的公钥与令牌密钥比较，不验证输入文件中的签名。
- 输出格式与 `hsm key-list` 相同；匹配到某个标签时，该标签下所有可见的私钥和
  公钥对象都会输出。
- 未提供 PIN 时只搜索公钥对象，并会在 stderr 提示匹配的私钥未被搜索。
- 没有匹配项时输出 `No matching key found.`，并以成功状态退出；输入无法解析
  才算错误。

```sh
anyca_cli hsm search-key --in leaf.der --provider softhsm --token AnyCA \
  --pin-source /etc/anyca/token.pin
```

### `hsm keygen`

在 URI 指定的令牌中生成 RSA、EC 或 ML-DSA 密钥对：

| 选项                                                    | 说明                                            |
|---------------------------------------------------------|-------------------------------------------------|
| `--key-uri <uri>`                                       | 指定新密钥对的 PKCS #11 URI，必填。             |
| `--key-type <rsa\|ec\|ml-dsa-44\|ml-dsa-65\|ml-dsa-87>` | 密钥类型。默认 `rsa`。                          |
| `--rsa-bits <n>`                                        | RSA 模长，`2048`–`16384`。默认 `3072`。仅 RSA。 |
| `--ec-curve <p256\|p384\|p521>`                         | EC 曲线。默认 `p384`。仅 EC。                   |

ML-DSA 需要实现了 `CKM_ML_DSA_KEY_PAIR_GEN` 和 `CKM_ML_DSA` 的 PKCS #11 3.2
provider（例如厂商模块或较新的 HSM）；SoftHSM 2.6 不支持。生成的密钥可以像
RSA/EC 密钥一样用于证书、CRL 和 OCSP 响应。带
`CKA_ALWAYS_AUTHENTICATE` 的密钥每次签名都需要 PIN；CLI 和服务器会从保存的
密钥 URI 中提供。

密钥对使用 URI 的 `object` 作为标签，该标签不得预先存在。

```sh
anyca_cli hsm keygen \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=leaf-key?pin-source=/etc/anyca/token.pin' \
  --key-type ec --ec-curve p384
```

### `hsm keydel`

销毁 URI 中 `object` 对应的私钥和公钥对象：

| 选项              | 说明                      |
|-------------------|---------------------------|
| `--key-uri <uri>` | PKCS #11 密钥 URI，必填。 |

删除不存在的密钥对也会成功。

```sh
anyca_cli hsm keydel \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=leaf-key?pin-source=/etc/anyca/token.pin'
```

### `hsm pin-set`

修改 HSM 令牌的用户 PIN：

| 选项              | 说明                                                     |
|-------------------|----------------------------------------------------------|
| `--key-uri <uri>` | 提供 provider、令牌和旧 PIN 的 PKCS #11 密钥 URI，必填。 |
| `--new-pin <pin>` | 新的用户 PIN，必填。                                     |

旧 PIN 从 URI 读取，命令会先登录令牌。

```sh
anyca_cli hsm pin-set \
  --key-uri 'pkcs11:provider=softhsm;token=AnyCA;object=root-ca-key?pin-source=/etc/anyca/token.pin' \
  --new-pin 5678
```

修改后还需要：

1. 更新 `pin-source` 指向的 PIN 文件；
2. 用 `ca update --key-uri ... --ocsp-key-uri ...` 更新数据库中保存的 PIN；
3. 重启 `anyca_server`。

`--new-pin` 会出现在进程列表和 Shell 历史中，请在受保护的环境中执行。

## 完整示例

下面的流程演示如何从零创建 CA、签发和吊销证书、发布 CRL 并启动服务器。
示例假设配置文件和 PIN 文件位于当前工作目录。

```sh
# 1. 创建自签名 CA，同时生成 OCSP 签名密钥和证书。
anyca_cli ca create --name root-ca \
  --key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=root-ca-key?pin-source=token.pin' \
  --ocsp-key-uri 'pkcs11:model=SoftHSM%20v2;token=AnyCA;object=root-ca-ocsp-key?pin-source=token.pin' \
  --ocsp-responder-endpoint root-ca --crl-publish-period-min 60

# 2. 查看已存储的 CA 配置。
anyca_cli ca list

# 3. 生成证书请求并签发终端证书。
openssl req -new -newkey rsa:2048 -nodes -keyout leaf.key \
  -subj "/CN=leaf.example" -outform DER -out leaf.csr

anyca_cli cert issue --ca-name root-ca --in leaf.csr \
  --basic --is-ca false --certificate-usage code-signing \
  --certificate-template default --out leaf.der

# 4. 吊销证书并发布更新后的 CRL。
anyca_cli cert revoke --add --in leaf.der --reason 1
anyca_cli crl publish --ca-name root-ca

# 5. 查看证书记录和吊销记录。
anyca_cli cert list --ca-name root-ca
anyca_cli cert list --ca-name root-ca --revocation

# 6. 续签 OCSP 签名证书。
anyca_cli ca ocsp-renew --ca-name root-ca --days 30

# 7. 启动服务器；启动时会发布 CA 证书和 CRL。
anyca_server
```

如果要接管已有 CA，把第 1 步替换为 `ca import`，并提供 `--in` 和两个密钥
URI。如果要创建下级 CA，先用父 CA 签发其 CA 证书，再用 `ca import` 注册。

## 退出状态

- 成功时返回 `0`，失败时返回非零状态。
- 用法错误会向 stderr 输出对应命令的帮助。
- 命令结果写入 stdout，诊断和错误信息写入 stderr。

## 安全提示

- `pin-value` 会把 PIN 放在命令行上，可能出现在进程列表和 Shell 历史中。建议
  改用 `pin-source=<文件>`，并把 PIN 文件权限限制为服务账户可读。
- AnyCA 会把解析出的 PIN 以明文保存到 `store.db`。`pin-source` 只能避免 PIN
  出现在命令行，不能避免它进入数据库。`store.db` 和 SoftHSM 令牌目录都应限制
  访问。
- `hsm key-list`、`hsm fetch-uri` 和 `hsm search-key` 的 `--pin-value` 同样会
  暴露 PIN。`hsm fetch-uri --pin-value` 还会把 PIN 写进它输出的 URI。
- `hsm pin-set --new-pin` 会出现在进程列表中。执行后请立即更新 PIN 文件和数据库
  中的 CA 配置。
- `scripts/softhsm-*.sh` 也可以从 `PKCS11_PIN`（初始化令牌时还有
  `SOFTHSM_SO_PIN`）读取 PIN，并从参数中省略它，避免 PIN 进入 Shell 历史；
  但底层的 `softhsm2-util` 和 `pkcs11-tool` 仍会以参数接收 PIN。
- SoftHSM 是软件 HSM，不是防篡改设备。需要更高保障时请使用硬件 PKCS #11 模块，
  并通过厂商工具导入密钥。
