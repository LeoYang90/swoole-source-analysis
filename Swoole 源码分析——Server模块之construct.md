# Swoole 源码分析——Server模块之初始化

## 前言

本节主要介绍 `server` 模块进行初始化的代码，关于初始化过程中，各个属性的意义，可以参考官方文档：

[SERVER 配置选项](https://wiki.swoole.com/wiki/page/274.html)

关于初始化过程中，用于监听的 `socket` 绑定问题，可以参考：

[UNP 学习笔记——基本 TCP 套接字编程](https://laravel-china.org/articles/13852/unp-learning-notes-basic-tcp-socket-programming)

[UNP 学习笔记——套接字选项](https://laravel-china.org/articles/14026/unp-learning-notes-socket-options)

## 构造 `server` 对象

构造 `server` 对象最重要的是两件事：`swServer_init` 初始化 `server`、为 `server` 添加端口：

```
PHP_METHOD(swoole_server, __construct)
{
    zend_size_t host_len = 0;
    char *serv_host;
    long sock_type = SW_SOCK_TCP;
    long serv_port = 0;
    long serv_mode = SW_MODE_PROCESS;

    swServer *serv = sw_malloc(sizeof (swServer));
    swServer_init(serv);

    serv->factory_mode = serv_mode;

    if (serv_port == 0 && strcasecmp(serv_host, "SYSTEMD") == 0)
    {
        if (swserver_add_systemd_socket(serv) <= 0)
        {
            swoole_php_fatal_error(E_ERROR, "failed to add systemd socket.");
            return;
        }
    }
    else
    {
        swListenPort *port = swServer_add_port(serv, sock_type, serv_host, serv_port);
    }
}

```

![](http://owql68l6p.bkt.clouddn.com/construct-3.png)

## `swServer_init` 函数

- `swServer_init` 函数主要为 `serv` 对象赋值初值，如果想要更改 `serv` 对象各个属性，可以调用 `set` 函数
- `serv->gs` 是全局共享内存

```
void swServer_init(swServer *serv)
{
    swoole_init();
    bzero(serv, sizeof(swServer));

    serv->factory_mode = SW_MODE_BASE;

    serv->reactor_num = SW_REACTOR_NUM > SW_REACTOR_MAX_THREAD ? SW_REACTOR_MAX_THREAD : SW_REACTOR_NUM;

    serv->dispatch_mode = SW_DISPATCH_FDMOD;

    serv->worker_num = SW_CPU_NUM;
    serv->max_connection = SwooleG.max_sockets < SW_SESSION_LIST_SIZE ? SwooleG.max_sockets : SW_SESSION_LIST_SIZE;

    serv->max_request = 0;
    serv->max_wait_time = SW_WORKER_MAX_WAIT_TIME;

    //http server
    serv->http_parse_post = 1;
    serv->upload_tmp_dir = sw_strdup("/tmp");

    //heartbeat check
    serv->heartbeat_idle_time = SW_HEARTBEAT_IDLE;
    serv->heartbeat_check_interval = SW_HEARTBEAT_CHECK;

    serv->buffer_input_size = SW_BUFFER_INPUT_SIZE;
    serv->buffer_output_size = SW_BUFFER_OUTPUT_SIZE;

    serv->task_ipc_mode = SW_TASK_IPC_UNIXSOCK;

    /**
     * alloc shared memory
     */
    serv->stats = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerStats));
    if (serv->stats == NULL)
    {
        swError("[Master] Fatal Error: failed to allocate memory for swServer->stats.");
    }
    serv->gs = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerGS));
    if (serv->gs == NULL)
    {
        swError("[Master] Fatal Error: failed to allocate memory for swServer->gs.");
    }

    SwooleG.serv = serv;
}

```

### `swoole_init` 函数

- `swoole_init` 函数用于初始化全局变量 `SwooleG` 的各个属性
- `SwooleGS` 是全局的共享内存
- `SwooleTG` 是线程特有数据，每个线程都有自己独特的数据

```
extern swServerG SwooleG;              //Local Global Variable
extern SwooleGS_t *SwooleGS;           //Share Memory Global Variable
extern __thread swThreadG SwooleTG;   //Thread Global Variable

typedef struct
{
    swLock lock;
    swLock lock_2;
} SwooleGS_t;

void swoole_init(void)
{
    struct rlimit rlmt;
    if (SwooleG.running)
    {
        return;
    }

    bzero(&SwooleG, sizeof(SwooleG));
    bzero(&SwooleWG, sizeof(SwooleWG));
    bzero(sw_error, SW_ERROR_MSG_SIZE);

    SwooleG.running = 1;
    SwooleG.enable_coroutine = 1;
    sw_errno = 0;

    SwooleG.log_fd = STDOUT_FILENO;
    SwooleG.cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
    SwooleG.pagesize = getpagesize();
    SwooleG.pid = getpid();
    SwooleG.socket_buffer_size = SW_SOCKET_BUFFER_SIZE;

#ifdef SW_DEBUG
    SwooleG.log_level = 0;
#else
    SwooleG.log_level = SW_LOG_INFO;
#endif

    //get system uname
    uname(&SwooleG.uname);

    //random seed
    srandom(time(NULL));

    //init global shared memory
    SwooleG.memory_pool = swMemoryGlobal_new(SW_GLOBAL_MEMORY_PAGESIZE, 1);
    if (SwooleG.memory_pool == NULL)
    {
        printf("[Master] Fatal Error: global memory allocation failure.");
        exit(1);
    }
    SwooleGS = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(SwooleGS_t));
    if (SwooleGS == NULL)
    {
        printf("[Master] Fatal Error: failed to allocate memory for SwooleGS.");
        exit(2);
    }

    //init global lock
    swMutex_create(&SwooleGS->lock, 1);
    swMutex_create(&SwooleGS->lock_2, 1);
    swMutex_create(&SwooleG.lock, 0);

    if (getrlimit(RLIMIT_NOFILE, &rlmt) < 0)
    {
        swWarn("getrlimit() failed. Error: %s[%d]", strerror(errno), errno);
        SwooleG.max_sockets = 1024;
    }
    else
    {
        SwooleG.max_sockets = (uint32_t) rlmt.rlim_cur;
    }

    SwooleTG.buffer_stack = swString_new(8192);
    if (SwooleTG.buffer_stack == NULL)
    {
        exit(3);
    }

    if (!SwooleG.task_tmpdir)
    {
        SwooleG.task_tmpdir = sw_strndup(SW_TASK_TMP_FILE, sizeof(SW_TASK_TMP_FILE));
        SwooleG.task_tmpdir_len = sizeof(SW_TASK_TMP_FILE);
    }

    char *tmp_dir = swoole_dirname(SwooleG.task_tmpdir);
    //create tmp dir
    if (access(tmp_dir, R_OK) < 0 && swoole_mkdir_recursive(tmp_dir) < 0)
    {
        swWarn("create task tmp dir(%s) failed.", tmp_dir);
    }
    if (tmp_dir)
    {
        sw_free(tmp_dir);
    }

    //init signalfd
#ifdef HAVE_SIGNALFD
    swSignalfd_init();
    SwooleG.use_signalfd = 1;
    SwooleG.enable_signalfd = 1;
#endif
    //timerfd
#ifdef HAVE_TIMERFD
    SwooleG.use_timerfd = 1;
#endif

    SwooleG.use_timer_pipe = 1;
}

```

## `swServer_add_port` 函数

- `swServer_add_port` 函数为服务端添加监听的端口
- 首先需要检测 `listen_port_num` 已监听的端口不能大于 `SW_MAX_LISTEN_PORT`(默认为 60000)
- 如果 `socket` 的类型不是 `unix sock`，那么端口号必须大于等于 0，小于 65535
- `host` 主域名长度也不能大于 `SW_HOST_MAXSIZE`(104)
- 然后从共享内存池中申请一个 `swListenPort` 类型的对象，然后调用 `swPort_init` 对端口对象进行初始化
- 利用函数 `swSocket_create` 创建一个 `socket` 对象，并返回其文件描述符
- 调用 `swSocket_bind` 函数将 `socket` 绑定到对应的主域与端口上来
- 如果协议是数据报(`UDP`)，而不是数据流时，需要设置 `socket` 的发送缓存与接收缓存为 `socket_buffer_size`
- 设置 `socket` 为非阻塞、`O_CLOEXEC`(`exec` 之后文件描述符自动关闭)
- 根据协议类型设置 `have_udp_sock`、`have_tcp_sock`、`udp_socket_ipv4/udp_socket_ipv6` 等等属性
- 递增 `listen_port_num` ，向单链表 `listen_list` 中添加 `swListenPort` 对象

```
enum swSocket_type
{
    SW_SOCK_TCP          =  1,
    SW_SOCK_UDP          =  2,
    SW_SOCK_TCP6         =  3,
    SW_SOCK_UDP6         =  4,
    SW_SOCK_UNIX_DGRAM   =  5,  //unix sock dgram
    SW_SOCK_UNIX_STREAM  =  6,  //unix sock stream
};

swListenPort* swServer_add_port(swServer *serv, int type, char *host, int port)
{
    if (serv->listen_port_num >= SW_MAX_LISTEN_PORT)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_TOO_MANY_LISTEN_PORT, "allows up to %d ports to listen", SW_MAX_LISTEN_PORT);
        return NULL;
    }
    if (!(type == SW_SOCK_UNIX_DGRAM || type == SW_SOCK_UNIX_STREAM) && (port < 0 || port > 65535))
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_SERVER_INVALID_LISTEN_PORT, "invalid port [%d]", port);
        return NULL;
    }
    if (strlen(host) + 1  > SW_HOST_MAXSIZE)
    {
        swoole_error_log(SW_LOG_ERROR, SW_ERROR_NAME_TOO_LONG, "address '%s' exceeds %d characters limit", host, SW_HOST_MAXSIZE - 1);
        return NULL;
    }

    swListenPort *ls = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenPort));
    if (ls == NULL)
    {
        swError("alloc failed");
        return NULL;
    }

    swPort_init(ls);
    ls->type = type;
    ls->port = port;
    strncpy(ls->host, host, strlen(host) + 1);

    if (type & SW_SOCK_SSL)
    {
        type = type & (~SW_SOCK_SSL);
        if (swSocket_is_stream(type))
        {
            ls->type = type;
            ls->ssl = 1;
#ifdef SW_USE_OPENSSL
            ls->ssl_config.prefer_server_ciphers = 1;
            ls->ssl_config.session_tickets = 0;
            ls->ssl_config.stapling = 1;
            ls->ssl_config.stapling_verify = 1;
            ls->ssl_config.ciphers = sw_strdup(SW_SSL_CIPHER_LIST);
            ls->ssl_config.ecdh_curve = sw_strdup(SW_SSL_ECDH_CURVE);
#endif
        }
    }

    //create server socket
    int sock = swSocket_create(ls->type);
    if (sock < 0)
    {
        swSysError("create socket failed.");
        return NULL;
    }
    //bind address and port
    if (swSocket_bind(sock, ls->type, ls->host, &ls->port) < 0)
    {
        close(sock);
        return NULL;
    }
    //dgram socket, setting socket buffer size
    if (swSocket_is_dgram(ls->type))
    {
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &ls->socket_buffer_size, sizeof(int));
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &ls->socket_buffer_size, sizeof(int));
    }
    //O_NONBLOCK & O_CLOEXEC
    swoole_fcntl_set_option(sock, 1, 1);
    ls->sock = sock;

    if (swSocket_is_dgram(ls->type))
    {
        serv->have_udp_sock = 1;
        serv->dgram_port_num++;
        if (ls->type == SW_SOCK_UDP)
        {
            serv->udp_socket_ipv4 = sock;
        }
        else if (ls->type == SW_SOCK_UDP6)
        {
            serv->udp_socket_ipv6 = sock;
        }
    }
    else
    {
        serv->have_tcp_sock = 1;
    }

    LL_APPEND(serv->listen_list, ls);
    serv->listen_port_num++;
    return ls;
}

```

### `swPort_init` 函数

- `swPort_init` 函数用于初始化 `swListenPort` 对象
- `backlog`、`tcp_keepcount`、`tcp_keepidle` 等等都是相应 `socket` 的属性
- 在外网通信时，有些客户端发送数据的速度较慢，每次只能发送一小段数据。这样 `onReceive` 到的数据就不是一个完整的包。 还有些客户端是逐字节发送数据的，如果每次回调 `onReceive` 会拖慢整个系统。[Length_Check 和 EOF_Check 的使用](https://wiki.swoole.com/wiki/page/57.html)。`package_length_type`、`package_eof` 等等就是相关参数的具体参数。

```
#define SW_DATA_EOF                "\r\n\r\n"

void swPort_init(swListenPort *port)
{
    port->sock = 0;
    port->ssl = 0;

    //listen backlog
    port->backlog = SW_BACKLOG;
    //tcp keepalive
    port->tcp_keepcount = SW_TCP_KEEPCOUNT;
    port->tcp_keepinterval = SW_TCP_KEEPINTERVAL;
    port->tcp_keepidle = SW_TCP_KEEPIDLE;
    port->open_tcp_nopush = 1;

    port->protocol.package_length_type = 'N';
    port->protocol.package_length_size = 4;
    port->protocol.package_body_offset = 4;
    port->protocol.package_max_length = SW_BUFFER_INPUT_SIZE;

    port->socket_buffer_size = SwooleG.socket_buffer_size;

    char eof[] = SW_DATA_EOF;
    port->protocol.package_eof_len = sizeof(SW_DATA_EOF) - 1;
    memcpy(port->protocol.package_eof, eof, port->protocol.package_eof_len);
}

```

- c：有符号、1字节
- C：无符号、1字节
- s ：有符号、主机字节序、2字节
- S：无符号、主机字节序、2字节
- n：无符号、网络字节序、2字节
- N：无符号、网络字节序、4字节
- l：有符号、主机字节序、4字节（小写L）
- L：无符号、主机字节序、4字节（大写L）
- v：无符号、小端字节序、2字节
- V：无符号、小端字节序、4字节

### `swSocket_create` 创建 `socket`

`swSocket_create` 函数会根据 `type` 的类型来调用 `socket` 系统调用

```
int swSocket_create(int type)
{
    int _domain;
    int _type;

    switch (type)
    {
    case SW_SOCK_TCP:
        _domain = PF_INET;
        _type = SOCK_STREAM;
        break;
    case SW_SOCK_TCP6:
        _domain = PF_INET6;
        _type = SOCK_STREAM;
        break;
    case SW_SOCK_UDP:
        _domain = PF_INET;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UDP6:
        _domain = PF_INET6;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UNIX_DGRAM:
        _domain = PF_UNIX;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UNIX_STREAM:
        _domain = PF_UNIX;
        _type = SOCK_STREAM;
        break;
    default:
        swWarn("unknown socket type [%d]", type);
        return SW_ERR;
    }
    return socket(_domain, _type, 0);
}

```

### `swSocket_bind` 绑定端口

- `SO_REUSEADDR` 允许启动一个监听服务器并捆绑众所周知端口，即使以前建立的该端口用作它们的本地端口的连接仍存在。
	- 如果不对TCP的套接字选项进行任何限制时，如果启动两个进程，第二个进程就会在调用bind函数的时候出错（Address already in use）。
   - 如果在调用bind之前我们设置了SO_REUSEADDR，但是不在第二个进程启动前close这个套接字，那么第二个进程仍然会在调用bind函数的时候出错（Address already in use）。
   - 如果在调用bind之前我们设置了SO_REUSEADDR，并接收了一个客户端连接，并且在第二个进程启动前关闭了bind的套接字，这个时候第一个进程只拥有一个套接字（与客户端的连接），那么第二个进程则可以bind成功，符合预期。
- 相对 `SO_REUSEADDR` 来说，`SO_REUSEPORT` 没有那么多的限制条件，允许两个毫无血缘关系的进程使用相同的 `IP` 地址同时监听同一个端口，并且不会出现[惊群效应](https://blog.csdn.net/daiyudong2020/article/details/50417400)
- 对于 `UNIX SOCKET`，需要设置 `sun_family` 与 `sun_path`
- 对于 `IPV4`，需要设置 `sin_family`、`sin_port`、`sin_addr`;对于 `IPV6`，需要设置 `sin6_family`、`sin6_port`、`sin6_addr`，然后调用 `bind` 函数;
- 如果 `port` 为0，说明服务器绑定的是任意端口，`bind` 函数会将系统所选择的端口返回给 `sockaddr` 对象

```
int swSocket_bind(int sock, int type, char *host, int *port)
{
    int ret;

    struct sockaddr_in addr_in4;
    struct sockaddr_in6 addr_in6;
    struct sockaddr_un addr_un;
    socklen_t len;

    //SO_REUSEADDR option
    int option = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int)) < 0)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "setsockopt(%d, SO_REUSEADDR) failed.", sock);
    }
    //reuse port
#ifdef HAVE_REUSEPORT
    if (SwooleG.reuse_port)
    {
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(int)) < 0)
        {
            swSysError("setsockopt(SO_REUSEPORT) failed.");
            SwooleG.reuse_port = 0;
        }
    }
#endif
    //unix socket
    if (type == SW_SOCK_UNIX_DGRAM || type == SW_SOCK_UNIX_STREAM)
    {
        bzero(&addr_un, sizeof(addr_un));
        unlink(host);
        addr_un.sun_family = AF_UNIX;
        strncpy(addr_un.sun_path, host, sizeof(addr_un.sun_path) - 1);
        ret = bind(sock, (struct sockaddr*) &addr_un, sizeof(addr_un));
    }
    //IPv6
    else if (type > SW_SOCK_UDP)
    {
        bzero(&addr_in6, sizeof(addr_in6));
        inet_pton(AF_INET6, host, &(addr_in6.sin6_addr));
        addr_in6.sin6_port = htons(*port);
        addr_in6.sin6_family = AF_INET6;
        ret = bind(sock, (struct sockaddr *) &addr_in6, sizeof(addr_in6));
        if (ret == 0 && *port == 0)
        {
            len = sizeof(addr_in6);
            if (getsockname(sock, (struct sockaddr *) &addr_in6, &len) != -1)
            {
                *port = ntohs(addr_in6.sin6_port);
            }
        }
    }
    //IPv4
    else
    {
        bzero(&addr_in4, sizeof(addr_in4));
        inet_pton(AF_INET, host, &(addr_in4.sin_addr));
        addr_in4.sin_port = htons(*port);
        addr_in4.sin_family = AF_INET;
        ret = bind(sock, (struct sockaddr *) &addr_in4, sizeof(addr_in4));
        if (ret == 0 && *port == 0)
        {
            len = sizeof(addr_in4);
            if (getsockname(sock, (struct sockaddr *) &addr_in4, &len) != -1)
            {
                *port = ntohs(addr_in4.sin_port);
            }
        }
    }
    //bind failed
    if (ret < 0)
    {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_SYSTEM_CALL_FAIL, "bind(%s:%d) failed. Error: %s [%d]", host, *port, strerror(errno), errno);
        return SW_ERR;
    }

    return ret;
}

```

### `swoole_fcntl_set_option` 函数为文件描述符设置选项

- 此函数主要是利用 `fcntl` 函数为文件描述符设置阻塞/非阻塞、`CLOEXEC` 等属性。

```
void swoole_fcntl_set_option(int sock, int nonblock, int cloexec)
{
    int opts, ret;

    if (nonblock >= 0)
    {
        do
        {
            opts = fcntl(sock, F_GETFL);
        }
        while (opts < 0 && errno == EINTR);

        if (opts < 0)
        {
            swSysError("fcntl(%d, GETFL) failed.", sock);
        }

        if (nonblock)
        {
            opts = opts | O_NONBLOCK;
        }
        else
        {
            opts = opts & ~O_NONBLOCK;
        }

        do
        {
            ret = fcntl(sock, F_SETFL, opts);
        }
        while (ret < 0 && errno == EINTR);

        if (ret < 0)
        {
            swSysError("fcntl(%d, SETFL, opts) failed.", sock);
        }
    }

#ifdef FD_CLOEXEC
    if (cloexec >= 0)
    {
        do
        {
            opts = fcntl(sock, F_GETFD);
        }
        while (opts < 0 && errno == EINTR);

        if (opts < 0)
        {
            swSysError("fcntl(%d, GETFL) failed.", sock);
        }

        if (cloexec)
        {
            opts = opts | FD_CLOEXEC;
        }
        else
        {
            opts = opts & ~FD_CLOEXEC;
        }

        do
        {
            ret = fcntl(sock, F_SETFD, opts);
        }
        while (ret < 0 && errno == EINTR);

        if (ret < 0)
        {
            swSysError("fcntl(%d, SETFD, opts) failed.", sock);
        }
    }
#endif
}


```