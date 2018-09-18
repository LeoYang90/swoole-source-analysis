# Swoole 源码分析——Server模块之OpenSSL(上)

## 前言

自从 `Let's Encrypt` 上线之后，`HTTPS` 网站数量占比越来越高，相信不久的未来就可以实现全网 `HTTPS`，大部分主流浏览器也对 `HTTP` 网页给出明显的 `不安全` 标志。

`SSL` 是在 `TCP` 层之上为客户端服务端之间数据传输运用复杂的加密算法，`swoole` 使用 `SSL` 加密只需要两个步骤：

```
$serv = new swoole_server("0.0.0.0", 443, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$key_dir = dirname(dirname(__DIR__)).'/tests/ssl';

$serv->set(array(
    'worker_num' => 4,
    'ssl_cert_file' => $key_dir.'/ssl.crt',
    'ssl_key_file' => $key_dir.'/ssl.key',
));
```

## `SSL`/`TLS` 安全通信

由于 `HTTPS` 的推出受到了很多人的欢迎，在 `SSL` 更新到 3.0 时，`IETF` 对 `SSL3.0` 进行了标准化，并添加了少数机制(但是几乎和 `SSL3.0` 无差异)，标准化后的 `IETF` 更名为 `TLS1.0` (`Transport Layer Security` 安全传输层协议)，可以说 `TLS` 就是 `SSL` 的新版本 3.1，并同时发布“ `RFC2246-TLS` 加密协议详解”。

首先我们先来了解一下 `SSL`/`TLS` 的原理。

以下内容来源于参考文献：[TLS和安全通信](https://github.com/k8sp/tls/blob/master/tls.md)


### 加密技术

`TLS` 依赖两种加密技术：

1. 对称加密（`symmetric encryption`）
1. 非对称加密（`asymmetric encryption`）


### 对称加密

对称加密的一方（比如小红）用秘钥 K 给文本 M 加密；另一方（比如小明）用
同一个秘钥解密：

```
小红 : C = E(M, K)
小明 : M = D(C, K)
```

这有一个问题：当一方生成了秘钥 `K` 之后得把 `K` 分享给另一方。但是穿越 `Sin
City` 的道路危险中途很可能有人窃听到 `K`，窃听者就可以假扮双方中的任何一
方与另一方通信。这叫中间人攻击。


### 非对称加密

非对称加密利用成对的两个秘钥：`K1` 和 `K2`。小红用其中一个加密文本，小明可
以用另一个解密文本。比如，小红用 `K1` 加密，小明用 `K2` 解密：

```
小红 : C = E(M, K1)
小明 : M = D(C, K2)
```

这样一来，双方中的一方（比如小红）可以生成 `K1` 和 `K2`，然后把其中一个秘钥（比如 `K1`）私藏，称为*私钥*；另一个（比如K2）公开，称为*公钥*。另一方（比如小明）得到公钥之后，双方就可以通信。

然而，中间人还是可能截获公钥 `K2`，然后自己弄一对秘钥（`κ1`, `κ2`），然后告诉小明说 `κ2` 是小红的公钥。这样中间人每次可以用截获的 `K2` 解密小红发给小明的文本（甚至可能修改文本），再用 `κ1` 加密了发出去；小明用 `κ2` 解密接收。

### 数字签名和CA

为了帮小明确定得到的公钥确实是小红的 `K2`，而不是中间人伪造的 `κ2`，牛人们发明了*数字签名（digital signature）*技术。

数字签名的做法是：

1. 小红把自己的公钥和 `ID`（身份证号码，或者域名）合为*身份证申请（certificate signing request，CSR）*，
1. 小红把 `CSR` 发给一个德高望重的人（被称为 `certificate authority`，`CA`），比如小亮，
1. 小亮用自己的私钥加密小红的 `CSR`，得到的密文被称为*数字签名（digital signature）*，
1. 小亮把 `signature` 和 `CSR` 的明文合在一起称为 *CA签署的身份证（`CA` `signed certificate`，`CRT`）*，发给小红，

```
小红：CSR = 小红公钥+小红域名
     signature = E(CSR, 小亮的私钥)
     CRT = CSR + signature
```

每当其他人（比如小明）找小红聊天（建立 `HTTPS` 连接）的时候，小红出示自己的小亮签署的身份证。拿到这个身份证的人，只要他是相信小亮的——在自己机器上安装了小亮的身份证，就可以

1. 从小亮的身份证中的小亮的 `CSR` 里提取小亮的公钥；
1. 然后用小亮的公钥解密小红的身份证中小亮的 `signature`，得到一个小红的 `CSR`；
1. 如果这个 `CSR` 和小红身份证中的 `CSR` 明文一致，则说明“这个小红的身份证是小亮确认过并且签名的”。

```
小明：小亮的公钥 = 小亮的CRT.CSR.小亮的公钥
     CSR' = D(CRT.signature, 小亮的公钥)
     if CSR' == CRT.CSR then OK
```

由此过程可以看出来：随便谁都可以当 `CA` ——只要愿意公开自己的公钥，即可用自己的私钥去加密别人的认证。那我们要是信错了 `CA`，被他摆一道怎么办？答案是：没办法。我们选择信任社会，要相信如果 `CA` 说谎，万一被识破，就没有人
再相信他了。现实中，很多操作系统（`Windows`、`Mac OS X`）和浏览器（`Chrome`、`Firefox`、`IE`）会内置一些靠谱的 `CA` 的身份证。


### 信任链

小亮如果担心没有人信任自己是个好 `CA`（就像没人信CNNIC一样），可以找一个大家都信的 `CA`，比如老王，用老王的私钥在小亮的身份证上签名：

```
小亮：CSR = 小亮的公钥+小亮域名
     signature = E(CSR, 老王的私钥)
     CRT = CSR + signature
```

如果浏览器或者操作系统里安装了老王的公钥则可以验证“小亮的身份证是老王确认并且签名过的”。

这样，小亮在签署小红的身份证的时候，可以在小红身份证后面附上自己的身份证。这样小红的身份证就有“两页”了。

当小明和小红通信的时候：

1. 小明会先要求小红出示自己的身份证；
1. 小明虽然不信任小亮，但是信任老王，所以小明可以用老王的身份证里的老
   王的公钥来验证小红身份证附带的小亮的身份证，于是就可以信任小亮了；
1. 然后小明用小亮身份证里的公钥验证小红的身份证。

要是怕小明连自己也也不信任，老王可以再找一个小明信任的人来签名确认自己的身份证。这个过程可以不断递推，从而形成了一条信任链（`trust of chain`)


### 根身份证和自签名

信任链总会有个顶端，被称为*根身份证（root CA）*。那么根身份证是谁签名的呢？答案是：自己签名。实际上，我们每个人都可以自己签名认证自己的身份证，得到*自签名的身份证（self-signed certificate）*。具体过程是：

1. 生成一对秘钥：公钥 `K2` 和私钥 `K1`，
2. 创建自己的 `CSR`，
3. 用自己的秘钥加密 `CSR` 得到 `signature`，然后把 `CSR` 明文和 `signature` 一起发布。

任何人只要信任我们自签名的身份证 `CRT`，也就可以用 `CRT.CSR.K2` 作为公钥加密要传递给我们的文本。我们可以用自己的私钥 `K1` 来解密文本。

一般来说，自签名的根身份证用于公司内部使用。

如果老王就是根 `CA` 了，那么上述各位的身份证的信任链如下：

```
小红：CSR = 小红公钥+小红域名
     signature = E(CSR, 小亮的私钥)
     CRT = CSR + signature

小亮：CSR = 小亮的公钥+小亮域名
     signature = E(小亮的CSR, 老王的私钥)
     CRT = 小亮的CSR + signature

老王：CSR = 老王的公钥+老王的域名
     signature = E(老王的CSR, 老王自己的私钥)
     CRT = 老王的CSR + signature
```

### 双方TLS认证

上述例子解释了通信的一方如何验证另一方的身份。这种情况的一个常见应用是：我们通过浏览器访问银行的网页。这里的关键是，我们要能验证银行的身份证，然后才敢于在网页里输入账号和密码。浏览器验证银行的身份证的过程如下：

1. 在浏览器和银行的HTTPS服务建立安全连接的过程中，银行的HTTPS服务会把
   它的身份证发给浏览器
1. 浏览器使用内置的CA的身份证来验证银行的身份证。

浏览器验证了银行的 `HTTPS` 服务的身份之后，就轮到银行验证浏览器的用户的身份了：

1. 浏览器展示银行HTTPS服务发来的登陆页面；
1. 用户在这个页面里输入账号和密码，银行的HTTPS服务由此验证用户的身份。

在这个过程中，银行 `HTTPS` 服务器的身份是通过 `TLS` 身份证来验证的。而我们（用户）的身份是通过我们输入的账号和密码来验证的。

有时通信的双方都是程序（而不是人）。此时，让一方输入账号和密码，不如让双方都通过 `TLS` 身份证来互相验证方便。尤其是在很多分布式系统里，有多种类型的程序互相通信，而不只是两方通信。

比如在 `Kubernetes` 机群里，不光操作机群的客户端程序 `kubectl` 要能验证 `Kubernetes master node`（具体的说是 `apiserver`）的身份，才能放心地把包括敏感信息（比如数据库密码）的计算作业提交给 `apiserver`。类似的，`apiserver` 也要能验证 `kubectl `的身份，以确认提交作业的是公司的合法雇员，而不是外贼。

为此，通信各方都需要有各自的身份证。一个公司可以自签名一个 `CA` 身份证，并且用它来给每个雇员以及每个程序签署身份证。这样，只要每台电脑上都预先安装好公司自己的 `CA` 身份证，就可以用这个身份证验证每个雇员和程序的身份了。
这是目前很多公司的常用做法。


### 加密和解密的性能

因为 `TLS` 模式下所有传输的数据都是加密的，大家会关注加密和解密的性能。客观的说，非对称加密技术的加密和解密比较慢，相对来说，对称加密技术的加密解密过程更快。所以实际的连接和握手过程中，通信双方会协商一个对称加密秘钥，之后的数据通信过程中的加密都是利用对称加密技术来实现的。

具体的做法是：握手的时候，双方各自生成一个随机数，并且以非对称加密的方式分享给对方。然后每一方都把自己的随机数和对方的随机数拼起来，就是接下来通信时候使用的对称加密方法的秘钥了。


## `OpenSSL` 操作指南

接下来，我们来看看如何生成 `HTTPS` 所需要的证书。

以下内容来源于参考文献：[openssl的介绍和使用](https://segmentfault.com/a/1190000014963014)

### `openssl` 简介

`OpenSSL` 是一个开源项目，其组成主要包括一下三个组件：

- openssl：多用途的命令行工具
- libcrypto：加密算法库
- libssl：加密模块应用库，实现了ssl及tls

`openssl` 可以实现：秘钥证书管理、对称加密和非对称加密更多简介和官网。

### 指令

平时我们使用 `openssl` 最多的莫过于使用指令了，而最为常见的几个指令如下：

- `genrsa` 生成RSA参数
- `req`
- `x509`
- `rsa`
- `ca`

#### `genrsa` 简介

平时主要用来生成私钥，选择使用的算法、对称加密密码和私钥长度来生成私钥。也就是生成 `key` 文件。

基本用法：

```
openssl genrsa [args] [numbits]
```

其中常见的参数：【更多参数查看：`openssl genrsa -help`】

```
args1 对生成的私钥文件是否要使用加密算法进行对称加密: 
    -des : CBC模式的DES加密 
    -des3 : CBC模式的3DES加密 
    -aes128 : CBC模式的AES128加密 
    -aes192 : CBC模式的AES192加密 
    -aes256 : CBC模式的AES256加密 
args2 对称加密密码
    -passout passwords
    其中passwords为对称加密(des、3des、aes)的密码(使用这个参数就省去了console交互提示输入密码的环节) 
args3 输出文件
    -out file : 输出证书私钥文件 
[numbits]: 密钥长度，理解为私钥长度 

```

生成一个 2048 位的 `RSA` 私钥，并用 `des3` 加密(密码为 `123456` )，保存为 `server.key` 文件

```
openssl genrsa -des3 -passout pass:123456 -out server.key  2048 
// -des3 是第一个参数args1；  
// -passout pass:123456 是第二个参数写法 args2
// -out server.key 第三个参数args3；   
// 2048 最后一个[numbits]参数

```

生成的 `key` 文件是 `PEM` 格式的

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,DB98A9512DD7CBCF

yKTM+eoxBvptGrkEixhljqHSuE+ucTh3VqYQsgO6+8Wbh1docbFUKzLKHrferJBH
...
-----END RSA PRIVATE KEY-----

```

虽说文件头尾都标注着 `RSA PRIVATE KEY`，但实际上这个文件里既包括公钥也包括私钥。

#### `req` 命令

`req` 的基本功能主要有两个：生成证书请求和生成自签名证书，也就是 `csr` 文件，或者自签名的 `crt` 文件。当然这并不是其全部功能，但是这两个最为常见；

常见使用方法：

```
openssl req [args] outfile

```

主要参数：【更多参数查看：`openssl req -help`】

```
args1 是输入输入文件格式：
    -inform arg
    -inform DER 使用输入文件格式为DER
    -inform PEM 使用输入文件格式为PEM
args2 输出文件格式:
    -outform arg   
    -outform DER 使用输出文件格式为DER
    -outform PEM 使用输出文件格式为PEM
args3 是待处理文件 
    -in inputfilepath
args4 待输出文件
    -out outputfilepath
args5 用于签名待生成的请求证书的私钥文件的解密密码
    -passin passwords       
args6 用于签名待生成的请求证书的私钥文件
    -key file
args7 指定输入密钥的编码格式 
    -keyform arg  
    -keyform  DER
    -keyform  NET
    -keyform  PEM
args8 生成新的证书请求 
    -new

args9 输出一个X509格式的证书,签名证书时使用 
     -x509          
args10 使用 X509 签名证书的有效时间  
    -days  // -days 3650 有效期10年
 
args11 生成一个bits长度的RSA私钥文件，用于签发【生成私钥、并生成自签名证书】 
    -newkey rsa:bits 
  
args12设置HASH算法-[digest]【生成私钥指定的hash摘要算法】
    -md5
    -sha1  // 高版本浏览器开始不信任这种算法
    -md2
    -mdc2
    -md4
args13指定openssl配置文件,很多内容不容易通过参数配置，可以指定配置文件
    -config filepath   
args14 显示格式txt【用于查看证书、私钥信息】
    -text
```

使用的案例：利用私钥生成证书请求 `csr`

```
openssl req -new -key server.key -out server.csr

```

`server.csr` 文件也是 `PEM` 格式的，文件头尾标注为 `CERTIFICATE REQUEST`:

```
-----BEGIN CERTIFICATE REQUEST-----
MIIC0TCCAbkCAQAwgYsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTERMA8GA1UE
...
-----END CERTIFICATE REQUEST-----

```

使用案例：利用私钥生成自签名证书

```
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt

```

#### `x509` 命令

`x509` 是一个功能很丰富的证书处理工具。可以用来显示证书的内容，转换其格式，给 `CSR` 签名等 `X.509` 证书的管理工作；

用法如下：

```
openssl x509 [args]

```

参数如下：【更多参数查看：`openssl x509 -help`】

```
args1 是输入输入文件格式：
    -inform arg
    -inform DER 使用输入文件格式为DER
    -inform PEM 使用输入文件格式为PEM
args2 输出文件格式:
    -outform arg   
    -outform DER 使用输出文件格式为DER
    -outform PEM 使用输出文件格式为PEM
args3 是待处理X509证书文件 
    -in inputfilepath
args4 待输出X509证书文件
    -out outputfilepath
args5表明输入文件是一个"请求签发证书文件(CSR)"，等待进行签发
    -req            
args6签名证书的有效时间  
    -days  // -days 3650 有效期10年      
args7 指定用于签发请求证书的根CA证书 
    -CA arg 
args8 根CA证书格式(默认是PEM)     
    -CAform arg     
args9 指定用于签发请求证书的CA私钥证书文件    
    -CAkey arg      
args10 指定根CA私钥证书文件格式(默认为PEM格式)
    -CAkeyform arg  
args11 指定序列号文件(serial number file)    
    -CAserial arg   
args12 如果序列号文件(serial number file)没有指定，则自动创建它 
    -CAcreateserial 
args13设置HASH算法-[digest]【生成私钥指定的hash摘要算法】
    -md5
    -sha1  // 高版本浏览器开始不信任这种算法
    -md2
    -mdc2
    -md4

```

使用实例： 使用根 `CA` 证书[ `ca.crt` ]和私钥[ `ca.key` ]对"请求签发证书"[ `server.csr` ]进行签发，生成 `x509` 格式证书

```
openssl x509 -req -days 3650 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out serverx509.crt

```

`server.crt` 也是 `PEM` 格式的。文件头尾的标记为 `CERTIFICATE`:

```
-----BEGIN CERTIFICATE-----
MIIDlDCCAnwCCQDQ1UvQyFD7jDANBgkqhkiG9w0BAQsFADCBizELMAkGA1UEBhMC
...
-----END CERTIFICATE-----

```

## `DER`、`CRT`、`CER`、`PEM`、`KEY`、`PFX/P12` 格式

下文参考文献：[DER、CRT、CER、PEM格式的证书及转换](https://blog.csdn.net/xiangguiwang/article/details/76400805)

### 证书和编码

`X.509` 证书,其核心是根据 `RFC 5280` 编码或数字签名的数字文档。

实际上，术语 `X.509` 证书通常指的是 `IETF` 的 `PKIX` 证书和 `X.509 v3` 证书标准的 `CRL` 文件，即如 `RFC 5280`（通常称为`PKIX for Public Key Infrastructure（X.509）`）中规定的。

### X509文件扩展

我们首先要了解的是每种类型的文件扩展名。 很多人不清楚DER，PEM，CRT和CER结尾的文件是什么，更有甚者错误地说是可以互换的。 在某些情况下，某些可以互换，最佳做法是识别证书的编码方式，然后正确标记。 正确标签的证书将更容易操纵

### 编码--决定扩展名方式

#### `.DER` 扩展名

`.DER` = `DER` 扩展用于二进制 `DER` 编码证书。

这些文件也可能承载 `CER` 或 `CRT` 扩展。 正确的说法是“我有一个 `DER` 编码的证书”不是“我有一个 `DER` 证书”。

#### `.PEM` 扩展名

`.PEM = PEM` 扩展用于不同类型的 `X.509v3` 文件，是以“ - BEGIN ...”前缀的 `ASCII（Base64）` 数据。

#### 常见的扩展

- `.CRT` 扩展名

`.CRT = CRT` 扩展用于证书。 证书可以被编码为二进制 `DER` 或 `ASCII PEM`。 `CER` 和 `CRT` 扩展几乎是同义词。 最常见的于 `Unix` 或类 `Unix` 系统。

- `.CER` 扩展名

`CER = .crt` 的替代形式（`Microsoft Convention`）您可以在微软系统环境下将 `.crt` 转换为 `.cer`（ `.DER` 编码的 `.cer`，或 `base64 [PEM]` 编码的 `.cer`）。

- `.KEY` 扩展名

`.KEY = KEY` 扩展名用于公钥和私钥 `PKCS＃8`。 键可以被编码为二进制 `DER` 或 `ASCII PEM`。

- `PFX/P12`  扩展名

`predecessor of PKCS#12`,对 `*nix` 服务器来说,一般 `CRT` 和 `KEY` 是分开存放在不同文件中的,但 `Windows` 的 `IIS` 则将它们存在一个 `PFX` 文件中,(因此这个文件包含了证书及私钥)这样会不会不安全？应该不会,`PFX` 通常会有一个"提取密码", 你想把里面的东西读取出来的话,它就要求你提供提取密码,`PFX` 使用的时 `DER` 编码,如何把 `PFX` 转换为 `PEM` 编码？

```
openssl pkcs12 -in for-iis.pfx -out for-iis.pem -nodes
```

这个时候会提示你输入提取代码. `for-iis.pem` 就是可读的文本.
生成 `pfx` 的命令类似这样:

```
openssl pkcs12 -export -out certificate.pfx -inkey privateKey.key -in certificate.crt -certfile CACert.crt
```

其中 `CACert.crt` 是 `CA` (权威证书颁发机构)的根证书,有的话也通过 `-certfile` 参数一起带进去.这么看来,`PFX` 其实是个证书密钥库.

### 常见的 `OpenSSL` 证书操作

证书操作有四种基本类型。查看，转换，组合和提取。

#### 查看证书

即使PEM编码的证书是 `ASCII`，它们也是不可读的。这里有一些命令可以让你以可读的形式输出证书的内容;

- 查看 `PEM` 编码证书

```
openssl x509 -in cert.pem -text –noout

openssl x509 -in cert.cer -text –noout

openssl x509 -in cert.crt -text –noout

如果您遇到这个错误，这意味着您正在尝试查看DER编码的证书，并需要使用“查看DER编码证书”中的命令。
unable to load certificate

12626:error:0906D06C:PEMroutines:PEM_read_bio:no start line:pem_lib.c:647:Expecting: TRUSTEDCERTIFICATE

```

- 查看 `DER` 编码证书

```
openssl x509 -in certificate.der -inform der -text -noout

如果您遇到以下错误，则表示您尝试使用DER编码证书的命令查看PEM编码证书。在“查看PEM编码的证书”中使用命令
unable to load certificate

13978:error:0D0680A8:asn1 encodingroutines:ASN1_CHECK_TLEN:wrong tag:tasn_dec.c:1306:

13978:error:0D07803A:asn1 encodingroutines:ASN1_ITEM_EX_D2I:nested asn1 error:tasn_dec.c:380:Type=X509

```

#### 转换证书格式

转换可以将一种类型的编码证书存入另一种。（即PEM到DER转换）

```
openssl x509 -in cert.crt -outform der-out cert.der

openssl x509 -in cert.crt -inform der -outform pem -out cert.pem

```

#### 组合证书

在某些情况下，将多个 `X.509` 基础设施组合到单个文件中是有利的。一个常见的例子是将私钥和公钥两者结合到相同的证书中。

组合密钥和链的最简单的方法是将每个文件转换为 `PEM` 编码的证书，然后将每个文件的内容简单地复制到一个新文件中。这适用于组合文件以在 `Apache` 中使用的应用程序

#### 证书提取

一些证书将以组合形式出现。 一个文件可以包含以下任何一个：证书，私钥，公钥，签名证书，证书颁发机构（CA）和/或权限链。


## `SSL`/`TLS` 握手流程

### 简洁版流程

* 第一步，爱丽丝给出协议版本号、一个客户端生成的随机数（`Client random`），以及客户端支持的加密方法。
* 第二步，鲍勃确认双方使用的加密方法，并给出数字证书、以及一个服务器生成的随机数（`Server random`）。
* 第三步，爱丽丝确认数字证书有效，然后生成一个新的随机数（`Premaster secret`），并使用数字证书中的公钥，加密这个随机数，发给鲍勃。
* 第四步，鲍勃使用自己的私钥，获取爱丽丝发来的随机数（即 `Premaster secret`）。
* 第五步，爱丽丝和鲍勃根据约定的加密方法，使用前面的三个随机数，生成"对话密钥"（`session key`），对话密钥被切片生成两个对称密钥和 `MAC` 密钥，用来加密接下来的整个对话过程。

注意这个例子只是传统的 `RSA` 模式密钥交换的 `SSL` 握手流程。

### 详细流程

以下内容参考文献：

[SSL/TLS协议运行机制的概述](http://www.ruanyifeng.com/blog/2014/02/ssl_tls.html)

[SSL/TLS协议详解](https://blog.csdn.net/column/details/17425.html)

#### 客户端发出请求（`ClientHello`）

握手第一步是客户端向服务端发送 `Client Hello` 消息，这个消息里包含了
	
- 一个客户端生成的随机数 `Client random`、
- 客户端支持的加密套件（`Support Ciphers`）
- 支持的协议版本 `SSL Version`，比如TLS 1.0版。
- 支持的压缩方法
- `Session id` 用于会话复用
- `Extension` 拓展字段的存在，是因为 `SSL` 协议起草之初有些功能没有考虑到，后续这些功能被加进 `RFC`，而为了兼容 `SSL`，把这些功能的描述放到 `Extension` 中。
	- `Server_name(SNI)`: 客户端在 `client hello` 中带上 `server name` 拓展（如果使用 `ip` 地址进行访问，那么就不会有 `server name` 拓展），它会捎带上域名地址，服务器解析到 `server name` 后，就会根据 `server name` 中的域名，选择合适的证书。
	- `Elliptic_curves/ec_point_formats`: 使用椭圆曲线密钥交换算法的时候用到，里面列举了自己支持的椭圆曲线算法，供服务器选择。
	- `SessionTicket TLS`: 会话复用时使用。
	- `status_request`: 请求 `OCSP`，服务器可以发送 `cettificate status` 到客户端，里面带上 `ocsp` 的信息。
	- `signature_algorithms`: 表示自己支持的签名算法，服务器收到这个拓展，在进行例如 `server key exchange` 签名等操作时，需要参考客户端这个拓展。
	- `application_layer_negotiation(ALPN)`: 用以描述支持的上层协议，h2、http/1.1、spdy等。可以把他想象成IP头中的protocol，描述了上层是TCP还是UDP还是ICMP。目前主流浏览器，若要使用HTTP2，则必须使用这个拓展。
	- `Renegotiation info`: 如果是重新协商（即加密的 `hello`），那么会带上上次协商的 12 字节的 `finished`，如果是新 `hello` 请求，那么里面字段为0。

 切记及时服务器端不支持renegotiation，在server hello响应时也需要带上这个拓展

这里需要注意的是，客户端发送的信息之中不包括服务器的域名。也就是说，理论上服务器只能包含一个网站，否则会分不清应该向客户端提供哪一个网站的数字证书。这就是为什么通常一台服务器只能有一张数字证书的原因。

对于虚拟主机的用户来说，这当然很不方便。2006年，TLS协议加入了一个 `Server Name Indication` 扩展，允许客户端向服务器提供它所请求的域名。

#### 服务器回应（`SeverHello`）

服务器收到客户端请求后，向客户端发出回应，这叫做SeverHello。服务器的回应包含以下内容。

- 确认使用的加密通信协议版本，比如 `TLS 1.0` 版本。如果浏览器与服务器支持的版本不一致，服务器关闭加密通信。
- 一个服务器生成的随机数，稍后用于生成"对话密钥"。注意，至此客户端和服务端都拥有了两个随机数
- 从 `Client Hello` 传过来的 `Support Ciphers` 里确定一份加密套件，这个套件决定了后续加密和生成摘要时具体使用哪些算法，比如 `RSA` 公钥加密。
- `session id`（`sessionid` 会话复用需要带上，当然命中 `session ticket` 时也需要带上）
- 拓展。一般会带上空的 `renegotiation info`（前提是客户端提供了 `EMPTY_SCSV` 加密套件或者有`renegotiation info` 拓展），以表示自己支持 `secure renegotiation`。

除了上面这些信息，如果服务器需要确认客户端的身份，就会再包含一项请求，要求客户端提供"客户端证书"

#### 服务器证书发送 (`Server Certificate`)

发送服务器证书，将服务器配置的证书（链）发送到客户端。

注意证书链的顺序，最下层证书在前（用户证书在前，上级证书在后）。发送的证书是二进制格式，并非 `base64` 之后的格式。

#### 服务器端秘钥交换 （`server key exchange`）

对于使用DHE/ECDHE非对称密钥协商算法的SSL握手，将发送该类型握手。

`RSA` 算法不会继续该握手流程（`DH`、`ECDH` 也不会发送 `server key exchange`）。

`ECDHE` 下主要有几点重要的信息：

- 指明自己使用的椭圆曲线（一般根据客户端的拓展中 `supported_groups` 中的选择椭圆曲线算法）。
- 公钥。服务器本地计算一个大数（`BIGNUM`），乘上曲线的 `base point`，得到一个新的 `point`，这个 `point` 就是公钥，用 `04+x+y` 的格式组织起来。`04` 表示 `unconpressed point` ，和客户端的 `ec_point_formats` 有关。
- 签名。和 `RSA` 握手不同，`RSA` 情况下，只要能值正常协商密钥，那么必然服务器端有证书对应的私钥，也间接表明了服务器拥有该证书。`DHE/ECDHE` 不同，证书对应的私钥并不参与密钥协商，如果要证明服务器拥有证书，则必然有签名的操作（就像双向认证的情况下，客户端需要发送 `certificate verify`）。被签名数据从 `curve type` 起，至 `point` 的 `y` 为止。对于 `TLS1.2`，签名前使用 `client hello` 拓展中提供的哈希算法。`TLS1.0` 和`TLS1.1`，如果本地证书是 `ECC` 证书，即若要使用 `ECDSA` 签名，这种哈希算法为 `SHA1`，其他的情况摘要算法为`md5+sha1`。
- 计算哈希之后就调用 `RSA` 或者 `ECDSA` 进行签名。注意的是，`TLS1.2` 时要带上 2 字节的 “`Signature Hash Algorithm`”。

    - 椭圆曲线数字签名算法（`ECDSA`）是使用椭圆曲线密码（`ECC`）对数字签名算法（`DSA`）的模拟。 
    - `DSA` 算法是 `RSA` 算法的反向算法，服务端利用私钥加密，客户端用公钥进行验证，速度更快，但是不能加密，只能用于签名验证，因为公钥是公开的。

    
`DHE` 下主要有几点重要的信息：

- 指明自己使用的 `DH` 参数，`p` 和 `q`。
- 服务器端计算私钥 `Xb`，计算 `q^Xb mod p`，将结果 `Pb` 发给客户端，自己仅且自己保存 `Xb`。
- 签名流程与上述类似，不再赘述。

#### 服务端证书请求 (`certificate request`)

双向认证时，服务器会发送 `certificate request`，表明自己想要收到客户端的证书。

这个类型的握手主要包含了 `ca` 证书的 `subject` ，用以告诉客户端自己需要哪些证书，不是由这些 `ca` 签发的证书“我”不要。

客户端，例如浏览器在收到这个请求时，如果不存在对应的证书，则发送一个空的 `certificate` 至服务器，如果存在一个证书，则发送该 `certificate` 至服务器。如果存在多个对应的证书，则会弹出一个弹出框让你选择。

`Certificate request` 还包含了想要证书的签名的类型，`RSA` 还是 `ECDSA`，对于 `TLS1.2` 还会包括摘要信息。

#### 服务端结束 (`Server hello done`)

服务器告诉客户完成它的初始化流通消息。 

#### 客户端证书发送 (`client certificate`)

如果服务器端请求了客户端的证书，客户端即使没有证书，也需要发送该类型的握手报文，只是这种情况下，里面的内容为0。

如果浏览器有对应的证书，则会发送证书，当然，也有可能发送上级证书（即发送证书链），这个完全取决于浏览器。

#### 客户端密钥交换 （`client key exchange`）

- `ECDH/ECDHE` 下比较简单了，和 `server key exchange` 处理一样，客户端随机生成一个大数，然后乘上 `base point`，得到的结果就是 `public key`。

- `DHE` 下客户端计算随机数 `Xa`，然后该报文中的 `Pubkey` 就是 `q^Xa mop p`

- `RSA` 下客户端随机生成 48 字节的预主密钥，然后使用 `pkcs1` 规则填充至公钥一样的长度，随后调用 `RSA` 进行运算，得到 `Encrypted PreMaster`。填充规则如下：`00 + 02 + non_zero + 0 + pre_master`。


        "不管是客户端还是服务器，都需要随机数，这样生成的密钥才不会每次都一样。由于SSL协议中证书是静态的，因此十分有必要引入一种随机因素来保证协商出来的密钥的随机性。
        对于RSA密钥交换算法来说，pre-master-key本身就是一个随机数，再加上hello消息中的随机，三个随机数通过一个密钥导出器最终导出一个对称密钥。
         pre master的存在在于SSL协议不信任每个主机都能产生完全随机的随机数，如果随机数不随机，那么pre master secret就有可能被猜出来，那么仅适用pre master secret作为密钥就不合适了，因此必须引入新的随机因素，那么客户端和服务器加上pre master secret三个随机数一同生成的密钥就不容易被猜出了，一个伪随机可能完全不随机，可是是三个伪随机就十分接近随机了，每增加一个自由度，随机性增加的可不是一。"

#### 服务端证书验证 (`Certificate verify`)

发送这个类型的握手需要2个前提条件

- 服务器端请求了客户端证书
- 客户端发送了非0长的证书

此时，客户端想要证明自己拥有该证书，必然需要私钥签名一段数据发给服务器验证。

签名的数据是客户端发送 `certificate verify` 前，所有收到和发送的握手信息（不包括5字节的 `record`）。其实这个流程和签名 `server key exchange` 基本一样。计算摘要，然后签名运算。

#### 加密标识 (`Change cipher`)

指示 `Server` 从现在开始发送的消息都是加密过的。

#### 服务器握手结束通知 (`Encrypted handshake message`)

其实这个报文的目的就是告诉对端自己在整个握手过程中收到了什么数据，发送了什么数据。来保证中间没人篡改报文。

其次，这个报文作用就是确认秘钥的正确性。因为 `Encrypted handshake message` 是使用对称秘钥进行加密的第一个报文，如果这个报文加解密校验成功，那么就说明对称秘钥是正确的。

计算方法也比较简单，将之前所有的握手数据（包括接受、发送），计算 `md` 哈希运算，然后计算 `prf`，然后就是使用协商好的对称密钥进行加密了。

MD运算：
- 对于 `TLS1.2`，摘要算法是 `sha256`，即 `md_result = sha256(all_handshake)`；
- 对于 `TLS1.0 1.1`，摘要算法是 `md5` 和 `sha1` 结果的拼接，即 `md_result  =  md5(all_handshake) + sha1(all_handshake)`。
- 特殊情况：如果加密套件中指定了 `sha384` 算法，例如 `RSA_WITH_AES256_CBC_SHA384` 加密套件，则无论协商使用 `tls` 哪个版本，都用 `sha384`，即 `md_result = sha384(all_handshake)`。

PRF运算:

计算完哈希后，客户端按这种格式：“`client finished”+ md_result`，作为 `prf` 的输入。`PRF` 的输出指定为 12字节。12 字节的数据前填充 4 字节 `message` 头部信息，就可以送入对称加密流程进行加密了。

`PRF` 运算其实就是 `P_HASH` 运算，`P_HASH` 就是不断 `hmac` 运算，直到计算出预定指定长度的值为止。


## 秘钥交换算法

`HTTPS` 通过 `TLS` 层和证书机制提供了内容加密、身份认证和数据完整性三大功能，可以有效防止数据被监听或篡改，还能抵御 `MITM`（中间人）攻击。`TLS` 在实施加密过程中，需要用到非对称密钥交换和对称内容加密两大算法。

对称内容加密强度非常高，加解密速度也很快，只是无法安全地生成和保管密钥。在 `TLS` 协议中，应用数据都是经过对称加密后传输的，传输中所使用的对称密钥，则是在握手阶段通过非对称密钥交换而来。常见的 `AES-GCM`、`ChaCha20-Poly1305`，都是对称加密算法。

非对称密钥交换能在不安全的数据通道中，产生只有通信双方才知道的对称加密密钥。目前最常用的密钥交换算法有 `RSA` 和 `ECDHE`：`RSA` 历史悠久，支持度好，但不支持 `PFS`（`Perfect Forward Secrecy`）；而 `ECDHE` 是使用了 `ECC`（椭圆曲线）的 `DH`（`Diffie-Hellman`）算法，计算速度快，支持 `PFS`。

只有非对称密钥交换，依然无法抵御 `MITM` 攻击，还得引入身份认证机制。对于大部分 `HTTPS `网站来说，服务端一般通过 `HTTP` 应用层的帐号体系就能完成客户端身份认证；而浏览器想要验证服务端身份，需要用到服务端提供的证书。

在 `RSA` 密钥交换中，浏览器使用证书提供的 `RSA` 公钥加密相关信息，如果服务端能解密，意味着服务端拥有证书对应的私钥，同时也能算出对称加密所需密钥。密钥交换和服务端认证合并在一起。

在 `ECDHE` 密钥交换中，服务端使用证书私钥对相关信息进行签名，如果浏览器能用证书公钥验证签名，就说明服务端确实拥有对应私钥，从而完成了服务端认证。密钥交换和服务端认证是完全分开的。

可用于数字签名的算法主要有 `RSA` 和 `ECDSA`，也就是目前密钥交换 + 签名主流选择：

- `RSA` 密钥交换（无需签名）；
- `ECDHE` 密钥交换、`RSA` 签名；
- `ECDHE` 密钥交换、`ECDSA` 签名；
- `ECDH` 密钥交换、`RSA` 签名；
- `ECDH` 密钥交换、`ECDSA` 签名；

内置 `ECDSA` 公钥的证书一般被称之为 `ECC` 证书，内置 `RSA` 公钥的证书就是 `RSA` 证书。由于 256 位 `ECC Key` 在安全性上等同于 3072 位 `RSA Key`，加上 `ECC` 运算速度更快，`ECDHE` 密钥交换 + `ECDSA` 数字签名无疑是最好的选择。由于同等安全条件下，`ECC` 算法所需的 `Key` 更短，所以 `ECC` 证书文件体积比 `RSA` 证书要小一些。

`RSA` 证书可以用于 `RSA` 密钥交换（`RSA` 非对称加密）或 `ECDHE` 密钥交换（`RSA` 非对称签名）；而 `ECC` 证书只能用于 `ECDHE` 密钥交换（`ECDSA` 非对称签名）。

并不是所有浏览器都支持 `ECDHE` 密钥交换，也就是说 `ECC` 证书的兼容性要差一些。

### 完全正向保密

"`Forward Secrecy`" 或 "`Perfect Forward Secrecy`-完全正向保密" 协议描述了秘钥协商（比如秘钥交换）方法的特点。实际上这意味着及时你的服务器的秘钥有危险，通讯仅有可能被一类人窃听，他们必须设法获的每次会话都会生成的秘钥对。

完全正向保密是通过每次握手时为秘钥协商随机生成密钥对来完成（和所有会话一个 `key` 相反）。实现这个技术（提供完全正向保密-`Perfect Forward Secrecy`）的方法被称为 "`ephemeral`"。

通常目前有2个方法用于完成完全正向保密（`Perfect Forward Secrecy`）:

`DHE` - 一个迪菲-赫尔曼密钥交换密钥协议（`Diffie Hellman key-agreement protocol`）短暂（`ephemeral`）版本。

`ECDHE` - 一个椭圆曲线密钥交换密钥协议（ `Elliptic Curve Diffie Hellman key-agreement protocol`）短暂（`ephemeral`）版本。

短暂（`ephemeral`）方法有性能缺点，因为生成 `key` 非常耗费资源。

以下内容参考文献：[TLS/SSL 协议详解 (30) SSL中的RSA、DHE、ECDHE、ECDH流程与区别](https://blog.csdn.net/mrpre/article/details/78025940)

### `RSA` 密钥交换算法

我们先来看看传统的秘钥交换算法—— `RSA` 秘钥交换算法。它是不符合完全正向保密的，但是是我们上面讲的经典秘钥交换。

RSA的核心涉及公钥私钥的概念

- 使用公钥加密的数据只有私钥能解密
- 使用私钥加密的数据只有公钥能解密


我们构建这么一种场景，服务器配置有公钥+私钥，客户端是离散的。

RSA算法流程文字描述如下：

- 任意客户端对服务器发起带有随机码的请求，服务器发回另一个随机码和自己的公钥到客户端（公钥明文传输）。
- 客户端生成随机码，和前两个随机码合并，使用随机数算法生成一个密钥 `S`，使用收到的公钥进行加密，生成 `C`，把 `C` 发送到服务器。
- 服务器收到 `C`，使用公钥对应的私钥进行解密，得到 `S`。
- 上述交换步骤后，客户端和服务器都得到了 `S`，`S` 为密钥（预主密钥）。

我们来看看上述过程中，为何第三方无法得到 `S`。首先第一步后，客户端有公钥，服务器有公钥和私钥。由于公钥是明文传输的，所以可以假设第三方也有公钥。

第二步后，客户端发送 `C`，服务器能够使用自己的私钥进行解密，而第三方只有公钥，无法解密。即第三方无法计算得到 `S`。

上述中，服务器发送的公钥在 `SSL` 中是通过 `certificate` 报文发送的，`certificate` 中的包含了公钥。`C` 是通过 `Client key exchange` 报文发送的。

其实，在实际 `SSL` 实际设计中，`S` 其实并没有直接被当成密钥加密，这里为了描述原理，省去了对 `S` 后续进行 `KDF` 哈希等操作，并不影响实际理解 `RSA`。

`RSA` 有一个问题，就是如果私钥泄漏，即私钥被第三方知道，那么第三方就能从 `C` 中解密得到 `S`，即只要保存所有的 `A` 和 `B` 的报文，等到私钥被泄漏的那一天，或者有办法快从 `C` 中计算 `S` 的方法出现（量子计算机分解大素数），那么 `A` 和 `B` 就没有什么私密性可言了。

这就是所谓的前向不安全，私钥参与了密钥交换，安全性取决于私钥是否安全保存。

### `DHE` 密钥交换算法

DHE算法流程文字描述如下：

- 客户端计算一个随机值 `Xa`，使用 `Xa` 作为指数，即计算 `Pa = q^Xa mod p`，其中 `q` 和 `p` 是全世界公认的一对值。客户端把 `Pa` 发送至服务器，`Xa` 作为自己私钥，仅且自己知道。
- 服务器和客户端计算流程一样，生成一个随机值 `Xb`，使用 `Xb` 作为指数，计算 `Pb = q^Xb mod p`，将结果 `Pb`发送至客户端，`Xb` 仅自己保存。
- 客户端收到 `Pb` 后计算 `Sa = Pb ^Xa mod p`；服务器收到 `Pa` 后计算 `Sb = Pa^Xb mod p`
- 算法保证了 `Sa = Sb = S`，故密钥交换成功，`S` 为密钥（预主密钥）。

上述途中，`Sa` 和 `Sb` 得到的结果是相同的，即记为 `S`。

上述密钥交换流程中，和 `RSA` 密钥交换有较大不同，`DHE` 密钥交换时，服务器私钥没有参与进来。也就是说，私钥即使泄漏，也不会导致会话加密密钥 `S` 被第三方解密。

实际使用过程中，私钥的功能被削弱到用来身份认证。

`DHE` 参数和 `Pb` 都是通过 `server key exchange` 发送给客户端，`Pa` 通过 `client key exchange` 发送给服务器。`server key exchange` 的结尾处需要使用服务器私钥对该报文本身进行签名，以表明自己拥有私钥。

### `ECDHE` 密钥交换算法

只要理解 `DHE` 密钥交换原理，那么理解 `ECDHE` 密钥交换原理其实并不难（如果不想深究的话）。

`ECDHE` 的运算是把 `DHE` 中模幂运算替换成了点乘运算，速度更快，可逆更难。

`ECDHE` 算法流程文字描述如下：

- 客户端随机生成随机值 `Ra`，计算 `Pa(x, y) = Ra * Q(x, y)`，`Q(x, y)` 为全世界公认的某个椭圆曲线算法的基点。将 `Pa(x, y)` 发送至服务器。
- 服务器随机生成随机值 `Pb`，计算 `Pb(x,y) = Rb * Q(x, y)`。将 `Pb(x, y)` 发送至客户端。
- 客户端计算 `Sa(x, y) = Ra * Pb(x, y)`；服务器计算 `Sb(x, y) = Rb *Pa(x, y)`
- 算法保证了 `Sa = Sb = S`，提取其中的 `S` 的 `x` 向量作为密钥（预主密钥）。

`SSL` 协议中，上图中椭圆曲线名和 `Pb` 通过 `server key exchange` 报文发送；`Pa` 通过 `client key exchange` 报文发送。

### `ECDHE` 与 `ECDH` 算法的区别

字面少了一个 `E`，`E` 代表了“临时”，即在握手流程中，作为服务器端，`ECDH` 少了一步计算 `Pb` 的过程，`Pb` 用证书中的公钥代替，而证书对应的私钥就是 `Xb`。由此可见，使用 `ECDH` 密钥交换算法，服务器必须采用 `ECC` 证书；服务器不发送 `server key exchange` 报文，因为发送 `certificate` 报文时，证书本身就包含了 `Pb` 信息。

### `ECDHE` 与 `RSA` 的区别

 `ECDHE（DHE）` 算法属于 `DH` 类密钥交换算法， 私钥不参与密钥的协商，故即使私钥泄漏，客户端和服务器之间加密的报文都无法被解密。由于 `ECDHE` 每条会话都重新计算一个密钥（`Ra`、`Rb`），故一条会话被解密后，其他会话仍旧安全。

然而，`ECDH` 算法服务器端的私钥是固定的，即证书的私钥作为 `Rb`，故 `ECDH` 不被认为前向安全，因为私钥泄漏相当于 `Rb` 泄漏，`Rb`泄漏，导致会话密钥可被第三方计算。

### 加密套件

以下内容来源：[SSL协议中的加密套件](https://baijiahao.baidu.com/s?id=1575306266576831&wfr=spider&for=pc)

加密套件（`CipherList`）是指在 `ssl` 通信中，服务器和客户端所使用的加密算法的组合。在 `ssl` 握手初期，客户端将自身支持的加密套件列表发送给服务器；在握手阶段，服务器根据自己的配置从中尽可能的选出一个套件，作为之后所要使用的加密方式。这些算法包括：认证算法、密钥交换算法、对称算法和摘要算法等。

每种加密套件的名字里包含了四部分信息，分别是:

- 第一部分是密钥交换，用于决定客户端与服务器之间在握手的过程中如何认证。使用非对称加密算法来生成会话密钥，因为非对称算法不会将重要数据在通信中传输。用到的算法包括 `RSA`，`Diffie-Hellman`，`ECDH`，`PSK` 等

- 第二部分是加密算法，主要是对传输的数据进行加密传输用的。一般有对称加和非对称加密，但是非对称加密算法太耗性能，再者有些非对称加密算法有内容长度的限制，所以真正要传输的数据会使用对称加密来进行加密。算法名称后通常会带有两个数字，分别表示密钥的长度和初始向量的长度，比如 `DES 56/56`, `RC2 56/128`, `RC4 128/128`, `AES 128/128`, `AES 256/256`

- 第三部分是会话校验（`MAC`）算法，为了防止握手本身被窜改（这里极容易和证书签名算法混淆）。算法包括`MD5`，`SHA`等。

- 第四部分是 `PRF`（伪随机数函数），用于生成“`master secret`”。

例如 `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`

从其名字可知，它是：

- 基于 `TLS` 协议的；
- 使用 `ECDHE`、`RSA` 作为密钥交换算法与证书签名类型；
- 加密算法是 `AES`（密钥和初始向量的长度都是 256）；
- `MAC` 算法（这里就是哈希算法）是 `SHA`。

在客户端和服务器端建立安全连接之前，双方都必须指定适合自己的加密套件。加密套件的选择可以通过组合的字符串来控制。
服务器在选择算法时，会有优先级，是以客户端提供的的为最优，还是服务器端配置的为最优。所谓的客户端最优，就是根据客户端提供的加密套件，从上到下，看是否有本地支持的，有的话则使用。所谓服务器端最优，就是服务器端根据自身配置的加密套件顺序，一个个在 `client hello` 中找，找到了就使用。

其次，当服务器配置 `ECC` 证书时，加密套件只能选择 `XXX_ECDSA_XXX` 或者 `ECDH_XXX`。当服务器配置 `RSA` 证书时，只能选择 `RSA_XXX` 或者 `ECDHE_RSA_XXX` 形式的加密套件。

需要注意的是，如果加密套件选择 `ECDH_RSA` 或者 `ECDH_ECDSA` 时，由于 `ECDH` 加密套件默认表明了握手需要 `ECC` 公钥（即 `ECC` 证书的公钥充当握手中 `server key exchange` 中的公钥，证书的私钥同样也是握手过程中的私钥，握手过程不需要 `server key exchange`），所以第二部分 `_RSA` 和 `_ECDSA` 表明的是想要的服务器证书签名类型。

换句话说，`CA` 颁发的证书可以是用 `CA` 自己的 `RSA` 私钥进行签名的 `RSA` 证书，也可以用 `CA` 的 `ECC` 私钥进行签名的 `ECC` 证书。具体是哪个，取决于 *`CA` 部门*和申请证书的类别。

证书内部存储的 `CSR` 的公钥是具体*申请*证书人员生成的，可以是 `RSA` 算法的公钥，也可以是 `ECC` 算法的公钥。取决于提交给 `CA` 之前生成的 `CSR` 方法。

比如说服务器选择了 `ECDH_RSA` 加密套件，但是发送的证书却是 `ECDSA` 签名的证书，虽然说证书签名类型不影响整个握手，但是对于校验严格的客户端，这种情况可能会导致客户端断开链接。

加密套件也可以用字符串的形式，举例：`ALL:!ADH:RC4+RSA:+SSLv2:@STRENGTH`

`Openssl` 定义了 4 中选择符号：“＋”，“－”，“！”，“@”。其中，“＋”表示取交集；“－”表示临时删除一个算法；“！”表示永久删除一个算法；“@“表示了排序方法。

多个描述之间可以用“：”、“，”、“ ”、“；”来分开。选择加密套件的时候按照从左到的顺序构成双向链表，存放与内存中。

`ALL:!ADH:RC4+RSA:+SSLv2:@STRENGTH` 表示的意义是：

首先选择所有的加密套件（不包含eNULL，即空对称加密算法），然后在得到的双向链表之中去掉身份验证采用 `DH` 的加密套件；加入包含 `RC4` 算法并将包含 `RSA` 的加密套件放在双向链表的尾部；再将支持 `SSLV2` 的加密套件放在尾部；最后得到的结果按照安全强度进行排序。

可以使用命令 ： `openssl ciphers -V 'ALL:!ADH:RC4+RSA:+SSLv2:@STRENGTH' |  column -t` 来查看具体加密套件。