# Swoole 源码分析——Server模块之OpenSSL(下)

## 前言

上一篇文章我们讲了 `OpenSSL` 的原理，接下来，我们来说说如何利用 `openssl` 第三方库进行开发，来为 `tcp` 层进行 `SSL` 隧道加密

## `OpenSSL` 初始化

在 `swoole` 中，如果想要进行 `ssl` 加密，只需要如下设置即可：

```
$serv = new swoole_server("0.0.0.0", 443, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$key_dir = dirname(dirname(__DIR__)).'/tests/ssl';

$serv->set(array(
    'worker_num' => 4,
    'ssl_cert_file' => $key_dir.'/ssl.crt',
    'ssl_key_file' => $key_dir.'/ssl.key',
));
```

## `_construct` 构造函数

我们先看看在构造函数中 `SWOOLE_SSL` 起了什么作用：

```c
REGISTER_LONG_CONSTANT("SWOOLE_SSL", SW_SOCK_SSL, CONST_CS | CONST_PERSISTENT);

PHP_METHOD(swoole_server, __construct)
{
    char *serv_host;
    long serv_port = 0;
    long sock_type = SW_SOCK_TCP;
    long serv_mode = SW_MODE_PROCESS;
    
    ...
    
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lll", &serv_host, &host_len, &serv_port, &serv_mode, &sock_type) == FAILURE)
    {
        swoole_php_fatal_error(E_ERROR, "invalid swoole_server parameters.");
        return;
    }
    
    ...

    swListenPort *port = swServer_add_port(serv, sock_type, serv_host, serv_port);
    
    ....
}


#define SW_SSL_CIPHER_LIST               "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"
#define SW_SSL_ECDH_CURVE                "secp384r1"

swListenPort* swServer_add_port(swServer *serv, int type, char *host, int port)
{
    ...
    
    swListenPort *ls = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenPort));
    
    ...
    
    if (type & SW_SOCK_SSL)
    {
        type = type & (~SW_SOCK_SSL);
        if (swSocket_is_stream(type))
        {
            ls->type = type;
            ls->ssl = 1;
// #ifdef SW_USE_OPENSSL
            ls->ssl_config.prefer_server_ciphers = 1;
            ls->ssl_config.session_tickets = 0;
            ls->ssl_config.stapling = 1;
            ls->ssl_config.stapling_verify = 1;
            ls->ssl_config.ciphers = sw_strdup(SW_SSL_CIPHER_LIST);
            ls->ssl_config.ecdh_curve = sw_strdup(SW_SSL_ECDH_CURVE);
#endif
        }
    }
    
    ...
}

```

我们可以看到，初始化过程中，会将常量 `SWOOLE_SSL` 转化为 `SW_SOCK_SSL`。然后调用 `swServer_add_port` 函数，在该函数中会设定很多用于 `SSL` 的参数。

- `prefer_server_ciphers` 加密套件偏向于服务端而不是客户端，也就是说会从服务端的加密套件从头到尾依次查找最合适的，而不是从客户端提供的列表寻找。
- `session_tickets` 初始化，由于 `SSL` 握手的非对称运算无论是 `RSA` 还是 `ECDHE`，都会消耗性能，故为了提高性能，对于之前已经进行过握手的 `SSL` 连接，尽可能减少握手 `round time trip` 以及运算。 `SSL` 提供 2 中不同的会话复用机制:
    > (1) `session id` 会话复用。
    
    > 对于已经建立的 `SSL` 会话，使用 `session id` 为 `key`（`session id` 来自第一次请求的 `server hello` 中的 `session id` 字段），主密钥为 `value` 组成一对键值，保存在本地，服务器和客户端都保存一份。
    
    > 当第二次握手时，客户端若想使用会话复用，则发起的 `client hello` 中 `session id` 会置上对应的值，服务器收到这个 `client hello`，解析 `session id`，查找本地是否有该 `session id`，如果有，判断当前的加密套件和上个会话的加密套件是否一致，一致则允许使用会话复用，于是自己的 `server hello` 中 `session id` 也置上和 `client hello` 中一样的值。然后计算对称秘钥，解析后续的操作。
    
    > 如果服务器未查到客户端的 `session id` 指定的会话（可能是会话已经老化），则会重新握手，`session id` 要么重新计算（和 `client hello` 中 `session id` 不一样），要么置成 0，这两个方式都会告诉客户端这次会话不进行会话复用。
    
    > (2) `session ticket` 会话复用
    
    > Session id会话复用有2个缺点，其一就是服务器会大量堆积会话，特别是在实际使用时，会话老化时间配置为数小时，这种情况对服务器内存占用非常高。

    > 其次，如果服务器是集群模式搭建，那么客户端和A各自保存的会话，在合B尝试会话复用时会失败（当然，你想用redis搭个集群存session id也行，就是太麻烦）。
    
    > Session ticket的工作流程如下：

    > 1：客户端发起client hello，拓展中带上空的session ticket TLS，表明自己支持session ticket。

    > 2：服务器在握手过程中，如果支持session ticket，则发送New session ticket类型的握手报文，其中包含了能够恢复包括主密钥在内的会话信息，当然，最简单的就是只发送master key。为了让中间人不可见，这个session ticket部分会进行编码、加密等操作。

    > 3：客户端收到这个session ticket，就把当前的master key和这个ticket组成一对键值保存起来。服务器无需保存任何会话信息，客户端也无需知道session ticket具体表示什么。

    > 4：当客户端尝试会话复用时，会在client hello的拓展中加上session ticket，然后服务器收到session ticket，回去进行解密、解码能相关操作，来恢复会话信息。如果能够恢复会话信息，那么久提取会话信息的主密钥进行后续的操作。

- `stapling` 与 `stapling_verify`: 
    
    > `OCSP`（`Online Certificate Status Protocol`，在线证书状态协议）是用来检验证书合法性的在线查询服务，一般由证书所属 `CA` 提供。
    
    > 假如服务端的私钥被泄漏，对应的证书就会被加入黑名单，为了验证服务端的证书是否在黑名单中，某些客户端会在 `TLS` 握手阶段进一步协商时，实时查询 `OCSP` 接口，并在获得结果前阻塞后续流程。`OCSP` 查询本质是一次完整的 `HTTP` 请求 - 响应，这中间 `DNS` 查询、建立 `TCP`、服务端处理等环节都可能耗费很长时间，导致最终建立 `TLS` 连接时间变得更长。
    
    > 而 `OCSP Stapling`（`OCSP` 封套），是指服务端主动获取 `OCSP` 查询结果并随着证书一起发送给客户端，从而让客户端跳过自己去验证的过程，提高 `TLS` 握手效率。
    
- `ciphers` 秘钥套件：默认的加密套件是 `"EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"`，关于加密套件我们在上一章已经讲解完毕
- `ecdh_curve`: 是 `ECDH` 算法所需要的椭圆加密参数。

到这里，`SSL` 的初始化已经完成。

## `Set` 设置 `SSL` 参数

```c
PHP_METHOD(swoole_server, set)
{
    zval *zset = NULL;
    
    ...
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset) == FAILURE)
    {
        return;
    }
    
    ...

    sw_zend_call_method_with_1_params(&port_object, swoole_server_port_class_entry_ptr, NULL, "set", &retval, zset);
}

static PHP_METHOD(swoole_server_port, set)
{
    ...
    
    if (port->ssl)
    {
        if (php_swoole_array_get_value(vht, "ssl_cert_file", v))
        {
            convert_to_string(v);
            if (access(Z_STRVAL_P(v), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found.", Z_STRVAL_P(v));
                return;
            }
            if (port->ssl_option.cert_file)
            {
                sw_free(port->ssl_option.cert_file);
            }
            port->ssl_option.cert_file = sw_strdup(Z_STRVAL_P(v));
            port->open_ssl_encrypt = 1;
        }
        if (php_swoole_array_get_value(vht, "ssl_key_file", v))
        {
            convert_to_string(v);
            if (access(Z_STRVAL_P(v), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl key file[%s] not found.", Z_STRVAL_P(v));
                return;
            }
            if (port->ssl_option.key_file)
            {
                sw_free(port->ssl_option.key_file);
            }
            port->ssl_option.key_file = sw_strdup(Z_STRVAL_P(v));
        }
        if (php_swoole_array_get_value(vht, "ssl_method", v))
        {
            convert_to_long(v);
            port->ssl_option.method = (int) Z_LVAL_P(v);
        }
        //verify client cert
        if (php_swoole_array_get_value(vht, "ssl_client_cert_file", v))
        {
            convert_to_string(v);
            if (access(Z_STRVAL_P(v), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found.", port->ssl_option.cert_file);
                return;
            }
            if (port->ssl_option.client_cert_file)
            {
                sw_free(port->ssl_option.client_cert_file);
            }
            port->ssl_option.client_cert_file = sw_strdup(Z_STRVAL_P(v));
        }
        if (php_swoole_array_get_value(vht, "ssl_verify_depth", v))
        {
            convert_to_long(v);
            port->ssl_option.verify_depth = (int) Z_LVAL_P(v);
        }
        if (php_swoole_array_get_value(vht, "ssl_prefer_server_ciphers", v))
        {
            convert_to_boolean(v);
            port->ssl_config.prefer_server_ciphers = Z_BVAL_P(v);
        }

        if (php_swoole_array_get_value(vht, "ssl_ciphers", v))
        {
            convert_to_string(v);
            if (port->ssl_config.ciphers)
            {
                sw_free(port->ssl_config.ciphers);
            }
            port->ssl_config.ciphers = sw_strdup(Z_STRVAL_P(v));
        }
        if (php_swoole_array_get_value(vht, "ssl_ecdh_curve", v))
        {
            convert_to_string(v);
            if (port->ssl_config.ecdh_curve)
            {
                sw_free(port->ssl_config.ecdh_curve);
            }
            port->ssl_config.ecdh_curve = sw_strdup(Z_STRVAL_P(v));
        }
        if (php_swoole_array_get_value(vht, "ssl_dhparam", v))
        {
            convert_to_string(v);
            if (port->ssl_config.dhparam)
            {
                sw_free(port->ssl_config.dhparam);
            }
            port->ssl_config.dhparam = sw_strdup(Z_STRVAL_P(v));
        }

        if (swPort_enable_ssl_encrypt(port) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "swPort_enable_ssl_encrypt() failed.");
            RETURN_FALSE;
        }
    }
    
    ...


}

```

这些 `SSL` 参数都是可以自定义设置的，上面代码最关键的是 `swPort_enable_ssl_encrypt` 函数，该函数调用了 `openssl` 第三方库进行 `ssl` 上下文的初始化：


```c
int swPort_enable_ssl_encrypt(swListenPort *ls)
{
    if (ls->ssl_option.cert_file == NULL || ls->ssl_option.key_file == NULL)
    {
        swWarn("SSL error, require ssl_cert_file and ssl_key_file.");
        return SW_ERR;
    }
    ls->ssl_context = swSSL_get_context(&ls->ssl_option);
    if (ls->ssl_context == NULL)
    {
        swWarn("swSSL_get_context() error.");
        return SW_ERR;
    }
    if (ls->ssl_option.client_cert_file
            && swSSL_set_client_certificate(ls->ssl_context, ls->ssl_option.client_cert_file,
                    ls->ssl_option.verify_depth) == SW_ERR)
    {
        swWarn("swSSL_set_client_certificate() error.");
        return SW_ERR;
    }
    if (ls->open_http_protocol)
    {
        ls->ssl_config.http = 1;
    }
    if (ls->open_http2_protocol)
    {
        ls->ssl_config.http_v2 = 1;
        swSSL_server_http_advise(ls->ssl_context, &ls->ssl_config);
    }
    if (swSSL_server_set_cipher(ls->ssl_context, &ls->ssl_config) < 0)
    {
        swWarn("swSSL_server_set_cipher() error.");
        return SW_ERR;
    }
    return SW_OK;
}
```

### `swSSL_get_context`

可以看到，上面最关键的函数就是 `swSSL_get_context` 函数，该函数初始化 `SSL` 并构建上下文环境的步骤为：

- 当 `OpenSSL` 版本大于 `1.1.0` 后，`SSL` 简化了初始化过程，只需要调用 `OPENSSL_init_ssl` 函数即可，在此之前必须手动调用 `SSL_library_init`(`openssl` 初始化)、`SSL_load_error_strings`（加载错误常量）、`OpenSSL_add_all_algorithms` （加载算法）
- 利用 `swSSL_get_method` 函数选择不同版本的 `SSL_METHOD`。
- 利用 `SSL_CTX_new` 函数创建上下文
- 为服务器配置参数，关于这些参数可以参考官方文档：[List of SSL OP Flags](https://wiki.openssl.org/index.php/List_of_SSL_OP_Flags)，其中很多配置对于最新版本来说，没有任何影响，仅仅作为兼容旧版本而保留。
- `SSL` 的 `KEY` 文件一般都是由对称加密算法所加密，这时候就需要调用 `SSL_CTX_set_default_passwd_cb` 与 `SSL_CTX_set_default_passwd_cb_userdata`，否则在启动 `swoole` 的时候，就需要手动在命令行中输入该密码。
- 接着就需要将私钥文件和证书文件的路径传入 `SSL`，相应的函数是 `SSL_CTX_use_certificate_file` 、 `SSL_CTX_use_certificate_chain_file` 与 `SSL_CTX_use_PrivateKey_file`，然后利用 `SSL_CTX_check_private_key` 来验证私钥。


```c
void swSSL_init(void)
{
    if (openssl_init)
    {
        return;
    }
#if OPENSSL_VERSION_NUMBER >= 0x10100003L && !defined(LIBRESSL_VERSION_NUMBER)
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);
#else
    OPENSSL_config(NULL);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif
    openssl_init = 1;
}

SSL_CTX* swSSL_get_context(swSSL_option *option)
{
    if (!openssl_init)
    {
        swSSL_init();
    }

    SSL_CTX *ssl_context = SSL_CTX_new(swSSL_get_method(option->method));
    if (ssl_context == NULL)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_options(ssl_context, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
    SSL_CTX_set_options(ssl_context, SSL_OP_MSIE_SSLV2_RSA_PADDING);
    SSL_CTX_set_options(ssl_context, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_TLS_D5_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_TLS_BLOCK_PADDING_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
    SSL_CTX_set_options(ssl_context, SSL_OP_SINGLE_DH_USE);

    if (option->passphrase)
    {
        SSL_CTX_set_default_passwd_cb_userdata(ssl_context, option);
        SSL_CTX_set_default_passwd_cb(ssl_context, swSSL_passwd_callback);
    }

    if (option->cert_file)
    {
        /*
         * set the local certificate from CertFile
         */
        if (SSL_CTX_use_certificate_file(ssl_context, option->cert_file, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        /*
         * if the crt file have many certificate entry ,means certificate chain
         * we need call this function
         */
        if (SSL_CTX_use_certificate_chain_file(ssl_context, option->cert_file) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        /*
         * set the private key from KeyFile (may be the same as CertFile)
         */
        if (SSL_CTX_use_PrivateKey_file(ssl_context, option->key_file, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        /*
         * verify private key
         */
        if (!SSL_CTX_check_private_key(ssl_context))
        {
            swWarn("Private key does not match the public certificate");
            return NULL;
        }
    }

    return ssl_context;
}

static int swSSL_passwd_callback(char *buf, int num, int verify, void *data)
{
    swSSL_option *option = (swSSL_option *) data;
    if (option->passphrase)
    {
        size_t len = strlen(option->passphrase);
        if (len < num - 1)
        {
            memcpy(buf, option->passphrase, len + 1);
            return (int) len;
        }
    }
    return 0;
}
```

### `swSSL_get_method `

我们来看看如何利用不同版本的 `OpenSSL` 选取不同的 `SSL_METHOD`。`swoole` 默认使用 `SW_SSLv23_METHOD`，该方法支持 `SSLv2` 与 `SSLv3`: 

```c
static const SSL_METHOD *swSSL_get_method(int method)
{
    switch (method)
    {
#ifndef OPENSSL_NO_SSL3_METHOD
    case SW_SSLv3_METHOD:
        return SSLv3_method();
    case SW_SSLv3_SERVER_METHOD:
        return SSLv3_server_method();
    case SW_SSLv3_CLIENT_METHOD:
        return SSLv3_client_method();
#endif
    case SW_SSLv23_SERVER_METHOD:
        return SSLv23_server_method();
    case SW_SSLv23_CLIENT_METHOD:
        return SSLv23_client_method();
/**
 * openssl 1.1.0
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    case SW_TLSv1_METHOD:
        return TLSv1_method();
    case SW_TLSv1_SERVER_METHOD:
        return TLSv1_server_method();
    case SW_TLSv1_CLIENT_METHOD:
        return TLSv1_client_method();
#ifdef TLS1_1_VERSION
    case SW_TLSv1_1_METHOD:
        return TLSv1_1_method();
    case SW_TLSv1_1_SERVER_METHOD:
        return TLSv1_1_server_method();
    case SW_TLSv1_1_CLIENT_METHOD:
        return TLSv1_1_client_method();
#endif
#ifdef TLS1_2_VERSION
    case SW_TLSv1_2_METHOD:
        return TLSv1_2_method();
    case SW_TLSv1_2_SERVER_METHOD:
        return TLSv1_2_server_method();
    case SW_TLSv1_2_CLIENT_METHOD:
        return TLSv1_2_client_method();
#endif
    case SW_DTLSv1_METHOD:
        return DTLSv1_method();
    case SW_DTLSv1_SERVER_METHOD:
        return DTLSv1_server_method();
    case SW_DTLSv1_CLIENT_METHOD:
        return DTLSv1_client_method();
#endif
    case SW_SSLv23_METHOD:
    default:
        return SSLv23_method();
    }
    return SSLv23_method();
}
```	

### `双向验证`

`swSSL_get_context` 函数之后，如果使用了双向验证，那么还需要

- 利用 `SSL_CTX_set_verify` 函数与 `SSL_VERIFY_PEER` 参数要求客户端发送证书来进行双向验证
- `SSL_CTX_set_verify_depth` 函数用于设置证书链的个数，证书链不能多于该参数
- `SSL_CTX_load_verify_locations` 用于加载可信任的 `CA` 证书，注意这个并不是客户端用于验证的证书，而是用来设定服务端 **可信任** 的 `CA` 机构
- `SSL_load_client_CA_file`、`SSL_CTX_set_client_CA_list` 用于设置服务端可信任的 `CA` 证书的列表，在握手过程中将会发送给客户端。：

```c
int swSSL_set_client_certificate(SSL_CTX *ctx, char *cert_file, int depth)
{
    STACK_OF(X509_NAME) *list;

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, swSSL_verify_callback);
    SSL_CTX_set_verify_depth(ctx, depth);

    if (SSL_CTX_load_verify_locations(ctx, cert_file, NULL) == 0)
    {
        swWarn("SSL_CTX_load_verify_locations(\"%s\") failed.", cert_file);
        return SW_ERR;
    }

    ERR_clear_error();
    list = SSL_load_client_CA_file(cert_file);
    if (list == NULL)
    {
        swWarn("SSL_load_client_CA_file(\"%s\") failed.", cert_file);
        return SW_ERR;
    }

    ERR_clear_error();
    SSL_CTX_set_client_CA_list(ctx, list);

    return SW_OK;
}
```
### `NPN/ALPN` 协议支持

如果使用了 `http2` 协议，还要调用 `swSSL_server_http_advise` 函数:

- `NPN` 与 `ALPN` 都是为了支持 `HTTP/2` 而开发的 `TLS` 扩展，`1.0.2` 版本之后才开始支持 `ALPN`。当客户端进行 `SSL` 握手的时候，客户端和服务端之间会利用 `NPN` 协议或者 `ALPN` 来协商接下来到底使用 `http/1.1` 还是 `http/2`
- 两者的区别：
	- `NPN` 是服务端发送所支持的 `HTTP` 协议列表，由客户端选择；而 `ALPN` 是客户端发送所支持的 `HTTP` 协议列表，由服务端选择；
	- `NPN` 的协商结果是在 `Change Cipher Spec` 之后加密发送给服务端；而 `ALPN` 的协商结果是通过 `Server Hello` 明文发给客户端； 
- 如果 `openssl` 仅仅支持 `NPN` 的时候，调用 `SSL_CTX_set_next_protos_advertised_cb`，否则调用 `SSL_CTX_set_alpn_select_cb`
- `SSL_CTX_set_next_protos_advertised_cb` 函数中注册了 `swSSL_npn_advertised` 函数，该函数返回了 `SW_SSL_HTTP2_NPN_ADVERTISE  SW_SSL_NPN_ADVERTISE`
- `SSL_CTX_set_alpn_select_cb` 函数中注册了 `swSSL_alpn_advertised` 函数，该函数会继续调用 `SSL_select_next_proto` 来和客户端进行协商。


```c
void swSSL_server_http_advise(SSL_CTX* ssl_context, swSSL_config *cfg)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    SSL_CTX_set_alpn_select_cb(ssl_context, swSSL_alpn_advertised, cfg);
#endif

#ifdef TLSEXT_TYPE_next_proto_neg
    SSL_CTX_set_next_protos_advertised_cb(ssl_context, swSSL_npn_advertised, cfg);
#endif

    if (cfg->http)
    {
        SSL_CTX_set_session_id_context(ssl_context, (const unsigned char *) "HTTP", strlen("HTTP"));
        SSL_CTX_set_session_cache_mode(ssl_context, SSL_SESS_CACHE_SERVER);
        SSL_CTX_sess_set_cache_size(ssl_context, 1);
    }
}

#define SW_SSL_NPN_ADVERTISE             "\x08http/1.1"
#define SW_SSL_HTTP2_NPN_ADVERTISE       "\x02h2"

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int swSSL_alpn_advertised(SSL *ssl, const uchar **out, uchar *outlen, const uchar *in, uint32_t inlen, void *arg)
{
    unsigned int srvlen;
    unsigned char *srv;

#ifdef SW_USE_HTTP2
    swSSL_config *cfg = arg;
    if (cfg->http_v2)
    {
        srv = (unsigned char *) SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE;
        srvlen = sizeof (SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE) - 1;
    }
    else
#endif
    {
        srv = (unsigned char *) SW_SSL_NPN_ADVERTISE;
        srvlen = sizeof (SW_SSL_NPN_ADVERTISE) - 1;
    }
    if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen, in, inlen) != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif

#ifdef TLSEXT_TYPE_next_proto_neg

static int swSSL_npn_advertised(SSL *ssl, const uchar **out, uint32_t *outlen, void *arg)
{
#ifdef SW_USE_HTTP2
    swSSL_config *cfg = arg;
    if (cfg->http_v2)
    {
        *out = (uchar *) SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE;
        *outlen = sizeof (SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE) - 1;
    }
    else
#endif
    {
        *out = (uchar *) SW_SSL_NPN_ADVERTISE;
        *outlen = sizeof(SW_SSL_NPN_ADVERTISE) - 1;
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif
```

### `session` 会话重用

所有的 `session` 必须都要有 `session ID` 上下文。对于服务端来说，`session` 缓存默认是不能使用的，可以通过调用 `SSL_CTX_set_session_id_context` 函数来进行设置生效。产生 `session ID` 上下文的目的是保证重用的 `session` 的使用目的与 `session` 创建时的使用目的是一致的。比如，在 `SSL web` 服务器中产生的 `session` 不能自动地在 `SSL FTP` 服务中使用。于此同时，我们可以使用 `session ID` 上下文来实现对我们的应用的更加细粒度的控制。比如，认证后的客户端应该与没有进行认证的客户端有着不同的 `session ID` 上下文。上下文的内容我们可以任意选择。正是通过函数 `SSL_CTX_set_session_id_context` 函数来设置上下文的，上下文的数据时第二个参数，第三个参数是数据的长度。

在设置了 `session ID` 上下文后，服务端就开启了 `session缓存`；但是我们的配置还没有完成。`Session` 有一个限定的生存期。在 `OpenSSL` 中的默认值是 300 秒。如果我们需要改变这个生存期，使用函数 `SSL_CTX_set_timeout`。尽管服务端默认地会自动地清除过期的 `session`，我们仍然可以手动地调用`SSL_CTX_flush_sessions` 来进行清理。比如，当我们关闭自动清理过期 `session` 的时候，就需要手动进行了。

一个很重要的函数：`SSL_CTX_set_session_cache_mode`，它允许我们改变对相关缓存的行为。与 `OpenSSL` 中其它的模式设置函数一样，模式使用一些标志的逻辑或来进行设置。其中一个标志是 `SSL_SESS_CACHE_NO_AUTO_CLEAR`，它关闭自动清理过期 `session` 的功能。这样有利于服务端更加高效严谨地进行处理，因为默认的行为可能会有意想不到的延迟；

```
SSL_CTX_set_session_id_context(ssl_context, (const unsigned char *) "HTTP", strlen("HTTP"));
SSL_CTX_set_session_cache_mode(ssl_context, SSL_SESS_CACHE_SERVER);
SSL_CTX_sess_set_cache_size(ssl_context, 1);

```

### 加密套件的使用

加密套件的使用主要是使用 `SSL_CTX_set_cipher_list` 函数，此外如果需要 `RSA` 算法，还需要 `SSL_CTX_set_tmp_rsa_callback` 函数注册 `RSA` 秘钥的生成回调函数 `swSSL_rsa_key_callback`。

在回调函数 `swSSL_rsa_key_callback` 中，首先申请一个大数数据结构 `BN_new`，然后将其设定为 `RSA_F4`，该值表示公钥指数 e，然后利用 `RSA_generate_key_ex` 函数生成秘钥。`RSAPublicKey_dup` 函数和 `RSAPrivateKey_dup` 函数可以提取公钥与私钥。


```c
int swSSL_server_set_cipher(SSL_CTX* ssl_context, swSSL_config *cfg)
{
#ifndef TLS1_2_VERSION
    return SW_OK;
#endif
    SSL_CTX_set_read_ahead(ssl_context, 1);

    if (strlen(cfg->ciphers) > 0)
    {
        if (SSL_CTX_set_cipher_list(ssl_context, cfg->ciphers) == 0)
        {
            swWarn("SSL_CTX_set_cipher_list(\"%s\") failed", cfg->ciphers);
            return SW_ERR;
        }
        if (cfg->prefer_server_ciphers)
        {
            SSL_CTX_set_options(ssl_context, SSL_OP_CIPHER_SERVER_PREFERENCE);
        }
    }

#ifndef OPENSSL_NO_RSA
    SSL_CTX_set_tmp_rsa_callback(ssl_context, swSSL_rsa_key_callback);
#endif

    if (cfg->dhparam && strlen(cfg->dhparam) > 0)
    {
        swSSL_set_dhparam(ssl_context, cfg->dhparam);
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    else
    {
        swSSL_set_default_dhparam(ssl_context);
    }
#endif
    if (cfg->ecdh_curve && strlen(cfg->ecdh_curve) > 0)
    {
        swSSL_set_ecdh_curve(ssl_context);
    }
    return SW_OK;
}

#ifndef OPENSSL_NO_RSA
static RSA* swSSL_rsa_key_callback(SSL *ssl, int is_export, int key_length)
{
    static RSA *rsa_tmp = NULL;
    if (rsa_tmp)
    {
        return rsa_tmp;
    }

    BIGNUM *bn = BN_new();
    if (bn == NULL)
    {
        swWarn("allocation error generating RSA key.");
        return NULL;
    }

    if (!BN_set_word(bn, RSA_F4) || ((rsa_tmp = RSA_new()) == NULL)
            || !RSA_generate_key_ex(rsa_tmp, key_length, bn, NULL))
    {
        if (rsa_tmp)
        {
            RSA_free(rsa_tmp);
        }
        rsa_tmp = NULL;
    }
    BN_free(bn);
    return rsa_tmp;
}
#endif
```

到此，`ssl` 的上下文终于设置完毕，`set` 函数配置完成。

## `OpenSSL` 端口的监听与接收

当监听的端口被触发连接后，`reactor` 事件会调用 `swServer_master_onAccept` 函数，进而调用 `accept` 函数，建立新的连接，生成新的文件描述符 `new_fd`。

此时需要调用 `swSSL_create` 函数将新的连接与 `SSL` 绑定。

在 `swSSL_create` 函数中，`SSL_new` 函数根据 `ssl_context` 创建新的 `SSL` 对象，利用 `SSL_set_fd` 绑定 `SSL`，`SSL_set_accept_state` 函数对 `SSL` 进行连接初始化。

```c
int swServer_master_onAccept(swReactor *reactor, swEvent *event)
{
    ...
    
    new_fd = accept(event->fd, (struct sockaddr *) &client_addr, &client_addrlen);
    
    ...
    
    swConnection *conn = swServer_connection_new(serv, listen_host, new_fd, event->fd, reactor_id);
    
    ...

    if (listen_host->ssl)
        {
            if (swSSL_create(conn, listen_host->ssl_context, 0) < 0)
            {
                bzero(conn, sizeof(swConnection));
                close(new_fd);
                return SW_OK;
            }
        }
        else
        {
            conn->ssl = NULL;
        }
    ...
}

int swSSL_create(swConnection *conn, SSL_CTX* ssl_context, int flags)
{
    SSL *ssl = SSL_new(ssl_context);
    if (ssl == NULL)
    {
        swWarn("SSL_new() failed.");
        return SW_ERR;
    }
    if (!SSL_set_fd(ssl, conn->fd))
    {
        long err = ERR_get_error();
        swWarn("SSL_set_fd() failed. Error: %s[%ld]", ERR_reason_error_string(err), err);
        return SW_ERR;
    }
    if (flags & SW_SSL_CLIENT)
    {
        SSL_set_connect_state(ssl);
    }
    else
    {
        SSL_set_accept_state(ssl);
    }
    conn->ssl = ssl;
    conn->ssl_state = 0;
    return SW_OK;
}

```

## `OpenSSL` 套接字写就绪

套接字写就绪有以下几种情况：

- 套接字在建立连接之后，只设置了监听写就绪，这时对于 `OpenSSL` 来说不需要任何处理，转为监听读就绪即可。


```
static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev)
{
    ...
    
    if (conn->connect_notify)
    {
        conn->connect_notify = 0;
        
        if (conn->ssl)
        {
            goto listen_read_event;
        }
        
        ...
        
        listen_read_event:
        
        return reactor->set(reactor, fd, SW_EVENT_TCP | SW_EVENT_READ);
    }
    else if (conn->close_notify)
    {
        if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
        {
            return swReactorThread_close(reactor, fd);
        }
    
    }
    
    ...
    
    _pop_chunk: while (!swBuffer_empty(conn->out_buffer))
    {
        ...
        
        ret = swConnection_buffer_send(conn);
        
        ...
    
    }
}
```

- 套接字可写入数据时，会调用 `swConnection_buffer_send` 写入数据，进而调用 `swSSL_send`、`SSL_write`。`SSL_write` 发生错误之后，函数会返回 `SSL_ERROR_WANT_READ`、`SSL_ERROR_WANT_WRITE` 等函数，这时需要将 `errno` 设置为 `EAGAIN`，再次调用即可。

```
int swConnection_buffer_send(swConnection *conn)
{
    ...
    
    ret = swConnection_send(conn, chunk->store.ptr + chunk->offset, sendn, 0);
    
    ...

}

static sw_inline ssize_t swConnection_send(swConnection *conn, void *__buf, size_t __n, int __flags)
{
    ...
    
    _send:
    if (conn->ssl)
    {
        retval = swSSL_send(conn, __buf, __n);
    }
    
    if (retval < 0 && errno == EINTR)
    {
        goto _send;
    }
    else
    {
        goto _return;
    }

    _return:
    
    return retval;
    
    ...
}

ssize_t swSSL_send(swConnection *conn, void *__buf, size_t __n)
{
    int n = SSL_write(conn->ssl, __buf, __n);
    if (n < 0)
    {
        int _errno = SSL_get_error(conn->ssl, n);
        switch (_errno)
        {
        case SSL_ERROR_WANT_READ:
            conn->ssl_want_read = 1;
            errno = EAGAIN;
            return SW_ERR;

        case SSL_ERROR_WANT_WRITE:
            conn->ssl_want_write = 1;
            errno = EAGAIN;
            return SW_ERR;

        case SSL_ERROR_SYSCALL:
            return SW_ERR;

        case SSL_ERROR_SSL:
            swSSL_connection_error(conn);
            errno = SW_ERROR_SSL_BAD_CLIENT;
            return SW_ERR;

        default:
            break;
        }
    }
    return n;
}
```

- 套接字已关闭。这时调用 `swReactorThread_close`，进而调用 `swSSL_close`。

    在该函数中，首先要利用 `SSL_in_init` 来判断当前 `SSL` 是否处于初始化握手阶段，如果初始化还未完成，不能调用 `shutdown` 函数，应该使用 `SSL_free` 来销毁 `SSL` 通道。
    
    在调用 `SSL_shutdown` 关闭通道之前，还需要调用 `SSL_set_quiet_shutdown` 设置静默关闭选项，此时关闭通道并不会通知对端连接已经关闭。并利用 `SSL_set_shutdown` 关闭读和写。
    
    如果返回的数据并不是 1，说明关闭通道的时候发生了错误。

```
int swReactorThread_close(swReactor *reactor, int fd)
{
    ...
    
    if (conn->ssl)
    {
        swSSL_close(conn);
    }
    
    ...

}

void swSSL_close(swConnection *conn)
{
    int n, sslerr, err;

    if (SSL_in_init(conn->ssl))
    {
        /*
         * OpenSSL 1.0.2f complains if SSL_shutdown() is called during
         * an SSL handshake, while previous versions always return 0.
         * Avoid calling SSL_shutdown() if handshake wasn't completed.
         */
        SSL_free(conn->ssl);
        conn->ssl = NULL;
        return;
    }

    SSL_set_quiet_shutdown(conn->ssl, 1);
    SSL_set_shutdown(conn->ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);

    n = SSL_shutdown(conn->ssl);

    swTrace("SSL_shutdown: %d", n);

    sslerr = 0;

    /* before 0.9.8m SSL_shutdown() returned 0 instead of -1 on errors */
    if (n != 1 && ERR_peek_error())
    {
        sslerr = SSL_get_error(conn->ssl, n);
        swTrace("SSL_get_error: %d", sslerr);
    }

    if (!(n == 1 || sslerr == 0 || sslerr == SSL_ERROR_ZERO_RETURN))
    {
        err = (sslerr == SSL_ERROR_SYSCALL) ? errno : 0;
        swWarn("SSL_shutdown() failed. Error: %d:%d.", sslerr, err);
    }

    SSL_free(conn->ssl);
    conn->ssl = NULL;
}
```

## `OpenSSL` 套接字读就绪

当 `OpenSSL` 读就绪的时候也是有以下几个情况：

- 连接刚刚建立，由 `swReactorThread_onWrite` 转调过来。此时需要验证 `SSL` 当前状态。


```
static int swReactorThread_onRead(swReactor *reactor, swEvent *event)
{
    if (swReactorThread_verify_ssl_state(reactor, port, event->socket) < 0)
    {
        return swReactorThread_close(reactor, event->fd);
        
        ...
        
        return port->onRead(reactor, port, event);
    }
}
```

- `swReactorThread_verify_ssl_state` 函数用于验证 `SSL` 当前的状态，如果当前状态仅仅是套接字绑定，还没有进行握手(`conn->ssl_state == 0`)，那么就要调用 `swSSL_accept` 函数进行握手，握手之后 `conn->ssl_state = SW_SSL_STATE_READY`。
- 握手之后有三种情况，一是握手成功，此时设置 `ssl_state` 状态，低版本 `ssl` 设定 `SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS` 标志，禁用会话重协商，然后返回 `SW_READY`；二是握手暂时不可用，需要返回 `SW_WAIT`，等待下次读就绪再次握手；三是握手失败，返回 `SW_ERROR`，调用 `swReactorThread_close` 关闭套接字。
- 握手成功之后，要向 `worker` 进程发送连接成功的任务，进而调用 `onConnection` 回调函数。

```
static sw_inline int swReactorThread_verify_ssl_state(swReactor *reactor, swListenPort *port, swConnection *conn)
{
    swServer *serv = reactor->ptr;
    if (conn->ssl_state == 0 && conn->ssl)
    {
        int ret = swSSL_accept(conn);
        if (ret == SW_READY)
        {
            if (port->ssl_option.client_cert_file)
            {
                swDispatchData task;
                ret = swSSL_get_client_certificate(conn->ssl, task.data.data, sizeof(task.data.data));
                if (ret < 0)
                {
                    goto no_client_cert;
                }
                else
                {
                    swFactory *factory = &SwooleG.serv->factory;
                    task.target_worker_id = -1;
                    task.data.info.fd = conn->fd;
                    task.data.info.type = SW_EVENT_CONNECT;
                    task.data.info.from_id = conn->from_id;
                    task.data.info.len = ret;
                    factory->dispatch(factory, &task);
                    goto delay_receive;
                }
            }
            no_client_cert:
            if (SwooleG.serv->onConnect)
            {
                swServer_tcp_notify(SwooleG.serv, conn, SW_EVENT_CONNECT);
            }
            delay_receive:
            if (serv->enable_delay_receive)
            {
                conn->listen_wait = 1;
                return reactor->del(reactor, conn->fd);
            }
            return SW_OK;
        }
        else if (ret == SW_WAIT)
        {
            return SW_OK;
        }
        else
        {
            return SW_ERR;
        }
    }
    return SW_OK;
}

int swSSL_accept(swConnection *conn)
{
    int n = SSL_do_handshake(conn->ssl);
    /**
     * The TLS/SSL handshake was successfully completed
     */
    if (n == 1)
    {
        conn->ssl_state = SW_SSL_STATE_READY;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
        if (conn->ssl->s3)
        {
            conn->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }
#endif
#endif
        return SW_READY;
    }
    /**
     * The TLS/SSL handshake was not successful but was shutdown.
     */
    else if (n == 0)
    {
        return SW_ERROR;
    }

    long err = SSL_get_error(conn->ssl, n);
    if (err == SSL_ERROR_WANT_READ)
    {
        return SW_WAIT;
    }
    else if (err == SSL_ERROR_WANT_WRITE)
    {
        return SW_WAIT;
    }
    else if (err == SSL_ERROR_SSL)
    {
        swWarn("bad SSL client[%s:%d].", swConnection_get_ip(conn), swConnection_get_port(conn));
        return SW_ERROR;
    }
    //EOF was observed
    else if (err == SSL_ERROR_SYSCALL && n == 0)
    {
        return SW_ERROR;
    }
    swWarn("SSL_do_handshake() failed. Error: %s[%ld|%d].", strerror(errno), err, errno);
    return SW_ERROR;
}

```

- 握手成功之后，如果设置了双向加密，还要调用 `swSSL_get_client_certificate` 函数获取客户端的证书文件，然后将证书文件发送给 `worker` 进程。
- `swSSL_get_client_certificate` 函数中首先利用 `SSL_get_peer_certificate` 来获取客户端的证书，然后利用 `PEM_write_bio_X509` 将证书与 `BIO` 对象绑定，最后利用 `BIO_read` 函数将证书写到内存中。

```
int swSSL_get_client_certificate(SSL *ssl, char *buffer, size_t length)
{
    long len;
    BIO *bio;
    X509 *cert;

    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
    {
        return SW_ERR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        swWarn("BIO_new() failed.");
        X509_free(cert);
        return SW_ERR;
    }

    if (PEM_write_bio_X509(bio, cert) == 0)
    {
        swWarn("PEM_write_bio_X509() failed.");
        goto failed;
    }

    len = BIO_pending(bio);
    if (len < 0 && len > length)
    {
        swWarn("certificate length[%ld] is too big.", len);
        goto failed;
    }

    int n = BIO_read(bio, buffer, len);

    BIO_free(bio);
    X509_free(cert);

    return n;

    failed:

    BIO_free(bio);
    X509_free(cert);

    return SW_ERR;
}
```

在 `worker` 进程，接到了 `SW_EVENT_CONNECT` 事件之后，会把证书文件存储在 `ssl_client_cert.str` 中。当连接关闭时，会释放 `ssl_client_cert.str` 内存。值得注意的是，此时验证连接有效的函数是 `swServer_connection_verify_no_ssl`。此函数不会验证 `SSL` 此时的状态，只会验证连接与 `session` 的有效性。

```
int swWorker_onTask(swFactory *factory, swEventData *task)
{
    ...
    
    switch (task->info.type)
    {
        ...
        
        case SW_EVENT_CLOSE:
 #ifdef SW_USE_OPENSSL
        conn = swServer_connection_verify_no_ssl(serv, task->info.fd);
        if (conn && conn->ssl_client_cert.length > 0)
        {
            sw_free(conn->ssl_client_cert.str);
            bzero(&conn->ssl_client_cert, sizeof(conn->ssl_client_cert.str));
        }
#endif
        factory->end(factory, task->info.fd);
        break;

    case SW_EVENT_CONNECT:
 #ifdef SW_USE_OPENSSL
        //SSL client certificate
        if (task->info.len > 0)
        {
            conn = swServer_connection_verify_no_ssl(serv, task->info.fd);
            conn->ssl_client_cert.str = sw_strndup(task->data, task->info.len);
            conn->ssl_client_cert.size = conn->ssl_client_cert.length = task->info.len;
        }
#endif
        if (serv->onConnect)
        {
            serv->onConnect(serv, &task->info);
        }
        break;
        
        ...
    }
}

static sw_inline swConnection *swServer_connection_verify_no_ssl(swServer *serv, uint32_t session_id)
{
    swSession *session = swServer_get_session(serv, session_id);
    int fd = session->fd;
    swConnection *conn = swServer_connection_get(serv, fd);
    if (!conn || conn->active == 0)
    {
        return NULL;
    }
    if (session->id != session_id || conn->session_id != session_id)
    {
        return NULL;
    }
    return conn;
}

```

- 当连接建立之后，就要通过 `SSL` 加密隧道读取数据，最基础简单的接受函数是 `swPort_onRead_raw` 函数，该函数会最终调用 `swSSL_recv` 函数，与 `SSL_write` 类似，`SSL_read` 会自动从 `ssl` 中读取加密数据，并将解密后的数据存储起来，等待发送给 `worker` 进程，进行具体的逻辑。


```
static int swPort_onRead_raw(swReactor *reactor, swListenPort *port, swEvent *event)
{
    n = swConnection_recv(conn, task.data.data, SW_BUFFER_SIZE, 0);
}

static sw_inline ssize_t swConnection_recv(swConnection *conn, void *__buf, size_t __n, int __flags)
{
    _recv:
    if (conn->ssl)
    {
        ssize_t ret = 0;
        size_t n_received = 0;

        while (n_received < __n)
        {
            ret = swSSL_recv(conn, ((char*)__buf) + n_received, __n - n_received);
            if (__flags & MSG_WAITALL)
            {
                if (ret <= 0)
                {
                    retval = ret;
                    goto _return;
                }
                else
                {
                    n_received += ret;
                }
            }
            else
            {
                retval = ret;
                goto _return;
            }
        }

        retval = n_received;
    }

    if (retval < 0 && errno == EINTR)
    {
        goto _recv;
    }
    else
    {
        goto _return;
    }
    
    _return:
    
    return retval;
}

ssize_t swSSL_recv(swConnection *conn, void *__buf, size_t __n)
{
    int n = SSL_read(conn->ssl, __buf, __n);
    if (n < 0)
    {
        int _errno = SSL_get_error(conn->ssl, n);
        switch (_errno)
        {
        case SSL_ERROR_WANT_READ:
            conn->ssl_want_read = 1;
            errno = EAGAIN;
            return SW_ERR;

        case SSL_ERROR_WANT_WRITE:
            conn->ssl_want_write = 1;
            errno = EAGAIN;
            return SW_ERR;

        case SSL_ERROR_SYSCALL:
            return SW_ERR;

        case SSL_ERROR_SSL:
            swSSL_connection_error(conn);
            errno = SW_ERROR_SSL_BAD_CLIENT;
            return SW_ERR;

        default:
            break;
        }
    }
    return n;
}

```

相应的，`worker` 进程在接受到数据之后，要通过 `swServer_connection_verify` 函数验证 `SSL` 连接的状态，如果发送数据的连接状态并不是 `SW_SSL_STATE_READY`，就会抛弃数据。

```
int swWorker_onTask(swFactory *factory, swEventData *task)
{
    ...
    
    switch (task->info.type)
    {
        case SW_EVENT_TCP:
    //ringbuffer shm package
    case SW_EVENT_PACKAGE:
        //discard data
        if (swWorker_discard_data(serv, task) == SW_TRUE)
        {
            break;
        }
        
        ...

    //chunk package
    case SW_EVENT_PACKAGE_START:
    case SW_EVENT_PACKAGE_END:
        //discard data
        if (swWorker_discard_data(serv, task) == SW_TRUE)
        {
            break;
        }
        package = swWorker_get_buffer(serv, task->info.from_id);
        if (task->info.len > 0)
        {
            //merge data to package buffer
            swString_append_ptr(package, task->data, task->info.len);
        }
        //package end
        if (task->info.type == SW_EVENT_PACKAGE_END)
        {
            goto do_task;
        }
        break;
        
        ...
    }
}

static sw_inline int swWorker_discard_data(swServer *serv, swEventData *task)
{
    swConnection *conn = swServer_connection_verify(serv, session_id);
    
    ...

}

static sw_inline swConnection *swServer_connection_verify(swServer *serv, int session_id)
{
    swConnection *conn = swServer_connection_verify_no_ssl(serv, session_id);
#ifdef SW_USE_OPENSSL
    if (!conn)
    {
        return NULL;
    }
    if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
    {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SSL_NOT_READY, "SSL not ready");
        return NULL;
    }
#endif
    return conn;

}
```