# Swoole 源码分析——进程管理 Swoole_Process

## 前言

`swoole-1.7.2` 增加了一个进程管理模块，用来替代 `PHP` 的 `pcntl` 扩展。

PHP自带的pcntl，存在很多不足，如

- `pcntl` 没有提供进程间通信的功能
- `pcntl` 不支持重定向标准输入和输出
- `pcntl` 只提供了 `fork` 这样原始的接口，容易使用错误
- `swoole_process` 提供了比 `pcntl` 更强大的功能，更易用的 `API`，使 `PHP` 在多进程编程方面更加轻松。

## `swoole_process::__construct` 创建子进程

在进程初始化的时候，首先要判断当前的环境：

- 非 `CLI` 模式下不能使用
- 在 `server master` 进程下并且已经启动了 `server` 后是不能创建进程的，因为此时 `master` 进程已经创建了 多个 `reator` 线程，`fork` 后会将多线程也复制下来。
- 同样的道理，使用了异步的 `AIO` 的进程使用了线程池，`fork` 会出现非常复杂的带线程 `fork` 问题。

如果当前环境可以创建进程，那么需要初始化以下属性：

- `process->id`：如果是普通的客户端进程，或者是 `master` 进程未启动 `server` 的状态， `php_swoole_worker_round_id` 就是创建的 `process` 进程数量，此时只需要递增即可；如果 `server` 已启动，那么 `php_swoole_worker_round_id` 还要加上所有 `worker` 进程的数量。 `php_swoole_worker_round_id` 递增就是 `process->id`。
- 设置重定向，让进程的输入输出与主进程管道相关联
- `swPipeUnsock_create` 函数新建管道

```
static PHP_METHOD(swoole_process, __construct)
{
    zend_bool redirect_stdin_and_stdout = 0;
    long pipe_type = 2;
    zval *callback;

    //only cli env
    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "swoole_process only can be used in PHP CLI mode.");
        RETURN_FALSE;
    }

    if (SwooleG.serv && SwooleG.serv->gs->start == 1 && swIsMaster())
    {
        swoole_php_fatal_error(E_ERROR, "swoole_process can't be used in master process.");
        RETURN_FALSE;
    }

    if (SwooleAIO.init)
    {
        swoole_php_fatal_error(E_ERROR, "unable to create process with async-io threads.");
        RETURN_FALSE;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|bl", &callback, &redirect_stdin_and_stdout, &pipe_type) == FAILURE)
    {
        RETURN_FALSE;
    }

    char *func_name = NULL;
    if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "function '%s' is not callable", func_name);
        efree(func_name);
        RETURN_FALSE;
    }
    efree(func_name);

    swWorker *process = emalloc(sizeof(swWorker));
    bzero(process, sizeof(swWorker));

    int base = 1;
    if (SwooleG.serv && SwooleG.serv->gs->start)
    {
        base = SwooleG.serv->worker_num + SwooleG.serv->task_worker_num + SwooleG.serv->user_worker_num;
    }
    if (php_swoole_worker_round_id == 0)
    {
        php_swoole_worker_round_id = base;
    }
    process->id = php_swoole_worker_round_id++;

    if (redirect_stdin_and_stdout)
    {
        process->redirect_stdin = 1;
        process->redirect_stdout = 1;
        process->redirect_stderr = 1;
        /**
         * Forced to use stream pipe
         */
        pipe_type = 1;
    }

    if (pipe_type > 0)
    {
        swPipe *_pipe = emalloc(sizeof(swPipe));
        int socket_type = pipe_type == 1 ? SOCK_STREAM : SOCK_DGRAM;
        if (swPipeUnsock_create(_pipe, 1, socket_type) < 0)
        {
            RETURN_FALSE;
        }

        process->pipe_object = _pipe;
        process->pipe_master = _pipe->getFd(_pipe, SW_PIPE_MASTER);
        process->pipe_worker = _pipe->getFd(_pipe, SW_PIPE_WORKER);
        process->pipe = process->pipe_master;

        zend_update_property_long(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("pipe"), process->pipe_master TSRMLS_CC);
    }

    swoole_set_object(getThis(), process);
    zend_update_property(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("callback"), callback TSRMLS_CC);
}

```

## `swoole_process->start` 启动进程

`swoole_process->start` 函数用于 `fork` 一个新进程，并且调用 `php_swoole_process_start`

```
static PHP_METHOD(swoole_process, start)
{
    swWorker *process = swoole_get_object(getThis());

    if (process->pid > 0 && kill(process->pid, 0) == 0)
    {
        swoole_php_fatal_error(E_WARNING, "process has already been started.");
        RETURN_FALSE;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        swoole_php_fatal_error(E_WARNING, "fork() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    else if (pid > 0)
    {
        process->pid = pid;
        process->child_process = 0;
        zend_update_property_long(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("pid"), process->pid TSRMLS_CC);
        RETURN_LONG(pid);
    }
    else
    {
        process->child_process = 1;
        SW_CHECK_RETURN(php_swoole_process_start(process, getThis() TSRMLS_CC));
    }
    RETURN_TRUE;
}
```
`php_swoole_process_start` 函数用于设定重定向和清理主进程残留的一些功能：

- 将 `STDIN_FILENO` 输入、`STDOUT_FILENO` 输出、`STDERR_FILENO` 错误输出与 `pipe_worker` 相绑定，实现重定向功能。
- 如果存在 `SwooleG.main_reactor`，删除并释放相关内存。
- 清空主进程残留的定时器与信号。
- 设定 `process_type` 为 0
- 执行 `_construct` 回调函数
- 如果在回调函数中调用了异步系统，启动 `php_swoole_event_wait` 函数进行事件循环。

```
int php_swoole_process_start(swWorker *process, zval *object TSRMLS_DC)
{
    process->pipe = process->pipe_worker;
    process->pid = getpid();

    if (process->redirect_stdin)
    {
        if (dup2(process->pipe, STDIN_FILENO) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "dup2() failed. Error: %s[%d]", strerror(errno), errno);
        }
    }

    if (process->redirect_stdout)
    {
        if (dup2(process->pipe, STDOUT_FILENO) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "dup2() failed. Error: %s[%d]", strerror(errno), errno);
        }
    }

    if (process->redirect_stderr)
    {
        if (dup2(process->pipe, STDERR_FILENO) < 0)
        {
            swoole_php_fatal_error(E_WARNING, "dup2() failed. Error: %s[%d]", strerror(errno), errno);
        }
    }

    /**
     * Close EventLoop
     */
    if (SwooleG.main_reactor)
    {
        SwooleG.main_reactor->free(SwooleG.main_reactor);
        SwooleG.main_reactor = NULL;
        swTraceLog(SW_TRACE_PHP, "destroy reactor");
    }

    bzero(&SwooleWG, sizeof(SwooleWG));
    SwooleG.pid = process->pid;
    if (SwooleG.process_type != SW_PROCESS_USERWORKER)
    {
        SwooleG.process_type = 0;
    }
    SwooleWG.id = process->id;

    if (SwooleG.timer.fd)
    {
        swTimer_free(&SwooleG.timer);
        bzero(&SwooleG.timer, sizeof(SwooleG.timer));
    }

    swSignal_clear();

    zend_update_property_long(swoole_process_class_entry_ptr, object, ZEND_STRL("pid"), process->pid TSRMLS_CC);
    zend_update_property_long(swoole_process_class_entry_ptr, object, ZEND_STRL("pipe"), process->pipe_worker TSRMLS_CC);

    zval *zcallback = sw_zend_read_property(swoole_process_class_entry_ptr, object, ZEND_STRL("callback"), 0 TSRMLS_CC);
    zval **args[1];

    if (zcallback == NULL || ZVAL_IS_NULL(zcallback))
    {
        swoole_php_fatal_error(E_ERROR, "no callback.");
        return SW_ERR;
    }

    zval *retval = NULL;
    args[0] = &object;
    sw_zval_add_ref(&object);

    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_ERROR, "callback function error");
        return SW_ERR;
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    if (SwooleG.main_reactor)
    {
        php_swoole_event_wait();
    }
    SwooleG.running = 0;

    zend_bailout();
    return SW_OK;
}

```

## `swoole_process->write`/ `swoole_process->read`

主进程与子进程之间进行通信可以使用 `write` 与 `read`，如果使用了 `swoole_event`，会自动将管道转为非阻塞模式，由 `reactor` 进行事件循环读写，否则就会采用阻塞式读写。

```
static PHP_METHOD(swoole_process, write)
{
    char *data = NULL;
    zend_size_t data_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (data_len < 1)
    {
        swoole_php_fatal_error(E_WARNING, "the data to send is empty.");
        RETURN_FALSE;
    }

    swWorker *process = swoole_get_object(getThis());
    if (process->pipe == 0)
    {
        swoole_php_fatal_error(E_WARNING, "no pipe, can not write into pipe.");
        RETURN_FALSE;
    }

    int ret;

    //async write
    if (SwooleG.main_reactor)
    {
        swConnection *_socket = swReactor_get(SwooleG.main_reactor, process->pipe);
        if (_socket && _socket->nonblock)
        {
            ret = SwooleG.main_reactor->write(SwooleG.main_reactor, process->pipe, data, (size_t) data_len);
        }
        else
        {
            goto _blocking_read;
        }
    }
    else
    {
        _blocking_read: ret = swSocket_write_blocking(process->pipe, data, data_len);
    }

    if (ret < 0)
    {
        swoole_php_error(E_WARNING, "write() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    ZVAL_LONG(return_value, ret);
}

static PHP_METHOD(swoole_process, read)
{
    long buf_size = 8192;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &buf_size) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (buf_size > 65536)
    {
        buf_size = 65536;
    }

    swWorker *process = swoole_get_object(getThis());

    if (process->pipe == 0)
    {
        swoole_php_fatal_error(E_WARNING, "no pipe, can not read from pipe.");
        RETURN_FALSE;
    }

    char *buf = emalloc(buf_size + 1);
    int ret = read(process->pipe, buf, buf_size);;
    if (ret < 0)
    {
        efree(buf);
        if (errno != EINTR)
        {
            swoole_php_error(E_WARNING, "read() failed. Error: %s[%d]", strerror(errno), errno);
        }
        RETURN_FALSE;
    }
    buf[ret] = 0;
    SW_ZVAL_STRINGL(return_value, buf, ret, 0);
    efree(buf);
}
```

## `swoole_process::signal` 设置信号处理函数

为异步的程序添加信号处理函数。首先程序会检查当前的进程环境与注册的信号，不符合条件的直接返回，例如：`swoole_server` 中不能设置 `SIGTERM` 和 `SIGALAM` 信号，这两个信号是 `swoole` 需要保留的，用户不能进行修改。

如果此前该信号已存在信号处理函数，该函数会覆盖以前的回调函数，之前的逻辑会再次执行一次，之后就会被销毁。


```
static PHP_METHOD(swoole_process, signal)
{
    zval *callback = NULL;
    long signo = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz", &signo, &callback) == FAILURE)
    {
        return;
    }

    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "cannot use swoole_process::signal here.");
        RETURN_FALSE;
    }

    if (SwooleG.serv && SwooleG.serv->gs->start)
    {
        if ((swIsWorker() || swIsTaskWorker()) && signo == SIGTERM)
        {
            swoole_php_fatal_error(E_WARNING, "unable to register SIGTERM in worker/task process.");
            RETURN_FALSE;
        }
        else if (swIsManager() && (signo == SIGTERM || signo == SIGUSR1 || signo == SIGUSR2 || signo == SIGALRM))
        {
            swoole_php_fatal_error(E_WARNING, "unable to register SIGTERM/SIGUSR1/SIGUSR2/SIGALRM in manager process.");
            RETURN_FALSE;
        }
        else if (swIsMaster() && (signo == SIGTERM || signo == SIGUSR1 || signo == SIGUSR2 || signo == SIGALRM || signo == SIGCHLD))
        {
            swoole_php_fatal_error(E_WARNING, "unable to register SIGTERM/SIGUSR1/SIGUSR2/SIGALRM/SIGCHLD in manager process.");
            RETURN_FALSE;
        }
    }

    php_swoole_check_reactor();
    swSignalHander handler;

    if (callback == NULL || ZVAL_IS_NULL(callback))
    {
        callback = signal_callback[signo];
        if (callback)
        {
            swSignal_add(signo, NULL);
            SwooleG.main_reactor->defer(SwooleG.main_reactor, free_signal_callback, callback);
            signal_callback[signo] = NULL;
            RETURN_TRUE;
        }
        else
        {
            swoole_php_error(E_WARNING, "no callback.");
            RETURN_FALSE;
        }
    }
    else if (Z_TYPE_P(callback) == IS_LONG && Z_LVAL_P(callback) == (long) SIG_IGN)
    {
        handler = NULL;
    }
    else
    {
        char *func_name;
        if (!sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC))
        {
            swoole_php_error(E_WARNING, "function '%s' is not callable", func_name);
            efree(func_name);
            RETURN_FALSE;
        }
        efree(func_name);

        callback = sw_zval_dup(callback);
        sw_zval_add_ref(&callback);

        handler = php_swoole_onSignal;
    }

    /**
     * for swSignalfd_setup
     */
    SwooleG.main_reactor->check_signalfd = 1;

    //free the old callback
    if (signal_callback[signo])
    {
        SwooleG.main_reactor->defer(SwooleG.main_reactor, free_signal_callback, signal_callback[signo]);
    }
    signal_callback[signo] = callback;

    /**
     * use user settings
     */
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swSignal_add(signo, handler);

    RETURN_TRUE;
}

```

## `swoole_process::alarm` 进程定时器

对比 `Swoole\Timer` 来说，`swoole_process::alarm` 并不是一个非常好的选择，`swoole_process::alarm` 更加类似于真是的进程 `alarm` 定时器，`alarm` 只允许设定一个 `alarm` 信号，而 `Swoole\Timer` 由于实现了一个定时任务最小堆，可以在不同的时间间隔执行不同的任务。因此为了区分两者，`swoole` 规定并不允许两者同时存在。

`swoole_process::alarm` 函数需要与 `swoole_process::signal` 相结合，因为其内部调用 `setitimer`，会周期发送 `alarm` 信号，需要在 `swoole_process::signal` 函数中设置 `alarm` 信号的回调函数。

```
static PHP_METHOD(swoole_process, alarm)
{
    long usec = 0;
    long type = ITIMER_REAL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &usec, &type) == FAILURE)
    {
        return;
    }

    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "cannot use swoole_process::alarm here.");
        RETURN_FALSE;
    }

    if (SwooleG.timer.fd != 0)
    {
        swoole_php_fatal_error(E_WARNING, "cannot use both 'timer' and 'alarm' at the same time.");
        RETURN_FALSE;
    }

    struct timeval now;
    if (gettimeofday(&now, NULL) < 0)
    {
        swoole_php_error(E_WARNING, "gettimeofday() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }

    struct itimerval timer_set;
    bzero(&timer_set, sizeof(timer_set));

    if (usec > 0)
    {
        long _sec = usec / 1000000;
        long _usec = usec - (_sec * 1000000);

        timer_set.it_interval.tv_sec = _sec;
        timer_set.it_interval.tv_usec = _usec;

        timer_set.it_value.tv_sec = _sec;
        timer_set.it_value.tv_usec = _usec;

        if (timer_set.it_value.tv_usec > 1e6)
        {
            timer_set.it_value.tv_usec = timer_set.it_value.tv_usec - 1e6;
            timer_set.it_value.tv_sec += 1;
        }
    }

    if (setitimer(type, &timer_set, NULL) < 0)
    {
        swoole_php_error(E_WARNING, "setitimer() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

```

## `swoole_process->useQueue` 消息队列

`useQueue` 会利用 `swMsgQueue_create` 创建 `process->queue`。

```
static PHP_METHOD(swoole_process, useQueue)
{
    long msgkey = 0;
    long mode = 2;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ll", &msgkey, &mode) == FAILURE)
    {
        RETURN_FALSE;
    }

    swWorker *process = swoole_get_object(getThis());

    if (msgkey <= 0)
    {
        msgkey = ftok(sw_zend_get_executed_filename(), 1);
    }

    swMsgQueue *queue = emalloc(sizeof(swMsgQueue));
    if (swMsgQueue_create(queue, 1, msgkey, 0) < 0)
    {
        RETURN_FALSE;
    }
    if (mode & MSGQUEUE_NOWAIT)
    {
        swMsgQueue_set_blocking(queue, 0);
        mode = mode & (~MSGQUEUE_NOWAIT);
    }
    process->queue = queue;
    process->ipc_mode = mode;
    zend_update_property_long(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("msgQueueId"), queue->msg_id TSRMLS_CC);
    zend_update_property_long(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("msgQueueKey"), msgkey TSRMLS_CC);
    RETURN_TRUE;
}
```

## `swoole_process->push`/`swoole_process->pop` 消息通信

推送和消费消息就是利用 `swMsgQueue_push/swMsgQueue_pop` 函数。

```
static PHP_METHOD(swoole_process, push)
{
    char *data;
    zend_size_t length;

    struct
    {
        long type;
        char data[SW_MSGMAX];
    } message;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &length) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "the data to push is empty.");
        RETURN_FALSE;
    }
    else if (length >= sizeof(message.data))
    {
        swoole_php_fatal_error(E_WARNING, "the data to push is too big.");
        RETURN_FALSE;
    }

    swWorker *process = swoole_get_object(getThis());

    if (!process->queue)
    {
        swoole_php_fatal_error(E_WARNING, "no msgqueue, can not use push()");
        RETURN_FALSE;
    }

    message.type = process->id;
    memcpy(message.data, data, length);

    if (swMsgQueue_push(process->queue, (swQueue_data *)&message, length) < 0)
    {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, pop)
{
    long maxsize = SW_MSGMAX;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &maxsize) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (maxsize > SW_MSGMAX || maxsize <= 0)
    {
        maxsize = SW_MSGMAX;
    }

    swWorker *process = swoole_get_object(getThis());
    if (!process->queue)
    {
        swoole_php_fatal_error(E_WARNING, "no msgqueue, can not use pop()");
        RETURN_FALSE;
    }

    struct
    {
        long type;
        char data[SW_MSGMAX];
    } message;

    if (process->ipc_mode == 2)
    {
        message.type = 0;
    }
    else
    {
        message.type = process->id;
    }

    int n = swMsgQueue_pop(process->queue, (swQueue_data *) &message, maxsize);
    if (n < 0)
    {
        RETURN_FALSE;
    }
    SW_RETURN_STRINGL(message.data, n, 1);
}
```

## `swoole_process::kill`/`swoole_process::wait`

向进程发送信号 `kill` 与回收子进程 `wait` 逻辑比较简单，就是调用对应的函数。值得注意的是 `kill` 之后的错误如果是 `ESRCH`，代表着相应的进程不存在。

```
static PHP_METHOD(swoole_process, kill)
{
    long pid;
    long sig = SIGTERM;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &pid, &sig) == FAILURE)
    {
        RETURN_FALSE;
    }

    int ret = kill((int) pid, (int) sig);
    if (ret < 0)
    {
        if (!(sig == 0 && errno == ESRCH))
        {
            swoole_php_error(E_WARNING, "kill(%d, %d) failed. Error: %s[%d]", (int) pid, (int) sig, strerror(errno), errno);
        }
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, wait)
{
    int status;
    zend_bool blocking = 1;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &blocking) == FAILURE)
    {
        RETURN_FALSE;
    }

    int options = 0;
    if (!blocking)
    {
        options |= WNOHANG;
    }

    pid_t pid = swWaitpid(-1, &status, options);
    if (pid > 0)
    {
        array_init(return_value);
        add_assoc_long(return_value, "pid", pid);
        add_assoc_long(return_value, "code", WEXITSTATUS(status));
        add_assoc_long(return_value, "signal", WTERMSIG(status));
    }
    else
    {
        RETURN_FALSE;
    }
}

static sw_inline int swWaitpid(pid_t __pid, int *__stat_loc, int __options)
{
    int ret;
    do
    {
        ret = waitpid(__pid, __stat_loc, __options);
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    } while(1);
    return ret;
}
```