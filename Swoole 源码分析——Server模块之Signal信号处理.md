# Swoole 源码分析——Server模块之Signal信号处理

## 前言

信号处理是网络库不可或缺的一部分，不论是 `ALARM`、`SIGTERM`、`SIGUSR1`、`SIGUSR2`、`SIGPIPE` 等信号对程序的控制，还是 `reactor`、`read`、`write` 等操作被信号中断的处理，都关系着整个框架程序的正常运行。

## `Signal` 数据结构

`Signal` 模块的数据结构很简单，就是一个 `swSignal` 类型的数组，数组大小是 128。`swSignal` 中存放着信号的回调函数 `callback`，信号 `signo`，是否启用 `active`。

```
typedef void (*swSignalHander)(int);
#define SW_SIGNO_MAX      128

typedef struct
{
    swSignalHander callback;
    uint16_t signo;
    uint16_t active;
} swSignal;

static swSignal signals[SW_SIGNO_MAX];
```

## `Signal` 函数

### `swSignal_none` 屏蔽所有信号

如果当前的线程不想要被信号中断，那么就可以使用 `swSignal_none` 函数屏蔽所有的信号，这样该进程所有的函数都不会被信号中断，编写函数的时候就不用考虑被信号打断的情况。

值得注意的是处理的信号 `SIGKILL` 和 `SIGSTOP` 无法被阻塞。

```
void swSignal_none(void)
{
    sigset_t mask;
    sigfillset(&mask);
    int ret = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    if (ret < 0)
    {
        swWarn("pthread_sigmask() failed. Error: %s[%d]", strerror(ret), ret);
    }
}

```

### `swSignal_add` 添加信号

添加信号就是向 `signals` 数组添加一个新的信号元素，然后调用 `swSignal_set` 函数进行信号处理函数的注册。如果使用的是 `signalfd`，那么使用的是 `swSignalfd_set` 函数。

```
void swSignal_add(int signo, swSignalHander func)
{
#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_set(signo, func);
    }
    else
#endif
    {
        {
            signals[signo].callback = func;
            signals[signo].active = 1;
            signals[signo].signo = signo;
            swSignal_set(signo, swSignal_async_handler, 1, 0);
        }
    }
}

```

### `swSignal_set` 设置信号处理函数

`swSignal_set` 函数主要是调用 `sigaction` 为整个进程设置信号处理函数。如果设置 `func` 为 `-1`，信号处理函数是系统默认，如果 `func` 是 `null`，就会忽略该信号。如果 `mask` 为 1，那么在处理该信号的时候会阻塞所有信号，如果 `mask` 为 0，那么在处理该信号的时候就不会阻塞任何信号。

```
swSignalHander swSignal_set(int sig, swSignalHander func, int restart, int mask)
{
    //ignore
    if (func == NULL)
    {
        func = SIG_IGN;
    }
    //clear
    else if ((long) func == -1)
    {
        func = SIG_DFL;
    }

    struct sigaction act, oact;
    act.sa_handler = func;
    if (mask)
    {
        sigfillset(&act.sa_mask);
    }
    else
    {
        sigemptyset(&act.sa_mask);
    }
    act.sa_flags = 0;
    if (sigaction(sig, &act, &oact) < 0)
    {
        return NULL;
    }
    return oact.sa_handler;
}
```

### `swSignal_async_handler` 信号处理函数

`Signal` 模块所有的信号处理函数都是 `swSignal_async_handler`，该函数会调用 `signals` 数组中信号元素的回调函数。对于进程中存在 `reactor`（例如主线程或者 `worker` 进程），只需设置 `main_reactor->singal_no`，等待 `reactor` 回调即可（一般是 `swReactor_error` 函数和 `swReactor_onFinish` 函数）。对于没有 `reactor` 的进程，例如 `manager` 进程，会直接调用回调函数。

值得注意的是，这种异步信号处理函数代码一定要简单，一定要是信号安全函数，例如本例中只设置 `SwooleG.main_reactor->singal_no`，等待着返回主流程后再具体执行回调函数；而没有 `main_reactor` 的进程，就要着重注意回调函数是否是信号安全函数。因此从这方面来说，`signalfd` 有着天然的优势，它是文件描述符，由 `epoll` 统一管理，回调函数并不需要异步信号安全。

```
static void swSignal_async_handler(int signo)
{
    if (SwooleG.main_reactor)
    {
        SwooleG.main_reactor->singal_no = signo;
    }
    else
    {
        //discard signal
        if (_lock)
        {
            return;
        }
        _lock = 1;
        swSignal_callback(signo);
        _lock = 0;
    }
}

void swSignal_callback(int signo)
{
    if (signo >= SW_SIGNO_MAX)
    {
        swWarn("signal[%d] numberis invalid.", signo);
        return;
    }
    swSignalHander callback = signals[signo].callback;
    if (!callback)
    {
        swWarn("signal[%d] callback is null.", signo);
        return;
    }
    callback(signo);
}

```


### `swSignal_clear` 清除所有信号

清除信号就是遍历 `signals` 数组，将所有的有效信号元素的信号处理函数设置为系统默认。如果使用的是 `signalfd`，那么调用 `swSignalfd_clear` 函数。

```
void swSignal_clear(void)
{
#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_clear();
    }
    else
#endif
    {
        int i;
        for (i = 0; i < SW_SIGNO_MAX; i++)
        {
            if (signals[i].active)
            {
                {
                    swSignal_set(signals[i].signo, (swSignalHander) -1, 1, 0);
                }
            }
        }
    }
    bzero(&signals, sizeof(signals));
}

```


### `swSignalfd_init`—`signalfd` 信号初始化

使用 `signalfd` 之前需要将 `signalfd_mask`、`signals` 重置。

```
static sigset_t signalfd_mask;
static int signal_fd = 0;

void swSignalfd_init()
{
    sigemptyset(&signalfd_mask);
    bzero(&signals, sizeof(signals));
}
```

### `swSignalfd_setup`——`signalfd` 信号启用

`signalfd` 信号启用需要两个步骤，调用 `signalfd` 函数创建信号描述符，`reactor->add` 添加到 `reactor` 事件循环中。

```
int swSignalfd_setup(swReactor *reactor)
{
    if (signal_fd == 0)
    {
        signal_fd = signalfd(-1, &signalfd_mask, SFD_NONBLOCK | SFD_CLOEXEC);
        if (signal_fd < 0)
        {
            swWarn("signalfd() failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
        SwooleG.signal_fd = signal_fd;
        if (sigprocmask(SIG_BLOCK, &signalfd_mask, NULL) == -1)
        {
            swWarn("sigprocmask() failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
        reactor->setHandle(reactor, SW_FD_SIGNAL, swSignalfd_onSignal);
        reactor->add(reactor, signal_fd, SW_FD_SIGNAL);
        return SW_OK;
    }
    else
    {
        swWarn("signalfd has been created");
        return SW_ERR;
    }
}

```

### `swSignalfd_set`——`signalfd` 信号处理函数的设置

使用 `signalfd` 函数对 `signal_fd` 设置信号处理函数的时候，要先将对应的信号进行屏蔽 `sigprocmask`，否则很可能会额外执行系统的默认信号处理函数。

```
static void swSignalfd_set(int signo, swSignalHander callback)
{
    if (callback == NULL && signals[signo].active)
    {
        sigdelset(&signalfd_mask, signo);
        bzero(&signals[signo], sizeof(swSignal));
    }
    else
    {
        sigaddset(&signalfd_mask, signo);
        signals[signo].callback = callback;
        signals[signo].signo = signo;
        signals[signo].active = 1;
    }
    if (signal_fd > 0)
    {
        sigprocmask(SIG_BLOCK, &signalfd_mask, NULL);
        signalfd(signal_fd, &signalfd_mask, SFD_NONBLOCK | SFD_CLOEXEC);
    }
}

```

### `swSignalfd_onSignal`——`signalfd` 信号处理函数

`swSignalfd_onSignal` 函数由 `reactor` 事件循环直接调用。

```
static int swSignalfd_onSignal(swReactor *reactor, swEvent *event)
{
    int n;
    struct signalfd_siginfo siginfo;
    n = read(event->fd, &siginfo, sizeof(siginfo));
    if (n < 0)
    {
        swWarn("read from signalfd failed. Error: %s[%d]", strerror(errno), errno);
        return SW_OK;
    }
    if (siginfo.ssi_signo >=  SW_SIGNO_MAX)
    {
        swWarn("unknown signal[%d].", siginfo.ssi_signo);
        return SW_OK;
    }
    if (signals[siginfo.ssi_signo].active)
    {
        if (signals[siginfo.ssi_signo].callback)
        {
            signals[siginfo.ssi_signo].callback(siginfo.ssi_signo);
        }
        else
        {
            swWarn("signal[%d] callback is null.", siginfo.ssi_signo);
        }
    }

    return SW_OK;
}

```

### `swSignalfd_clear`——`signalfd` 信号处理函数的清除


```
static void swSignalfd_clear()
{
    if (signal_fd)
    {
        if (sigprocmask(SIG_UNBLOCK, &signalfd_mask, NULL) < 0)
        {
            swSysError("sigprocmask(SIG_UNBLOCK) failed.");
        }
        close(signal_fd);
        bzero(&signalfd_mask, sizeof(signalfd_mask));
    }
    signal_fd = 0;
}

```

## `Signal` 信号的应用

### `master` 线程信号
 
在调用 `swoole_server->start` 函数之后，`master` 主进程开始创建 `manager` 进程与 `reactor` 线程。在创建 `manager` 进程和 `reactor` 线程之间，`master` 主线程开始进行信号处理函数的设置。

可以看到，`master` 进程的信号处理函数是 `swServer_signal_hanlder`，并设置忽略了 `SIGPIPE`、`SIGHUP` 函数。
    
- `SIGPIPE` 一般发生于对端连接已关闭，服务端仍然在发送数据的情况，如果没有忽略该信号，很可能主进程会异常终止。
- `SIGHUP` 信号一般发生于终端关闭时，该信号被发送到 `session` 首进程，也就是 `master` 主进程。如果不忽略该信号，关闭终端的时候，主进程会默认异常退出。
  
  > SIGHUP会在以下3种情况下被发送给相应的进程：
  
  > 1、终端关闭时，该信号被发送到session首进程以及作为job提交的进程（即用 & 符号提交的进程）
  
  > 2、session首进程退出时，该信号被发送到该session中的前台进程组中的每一个进程
  
  > 3、若父进程退出导致进程组成为孤儿进程组，且该进程组中有进程处于停止状态（收到SIGSTOP或SIGTSTP信号），该信号会被发送到该进程组中的每一个进程。


```
int swServer_start(swServer *serv)
{
    ...
    if (factory->start(factory) < 0)//创建 manager 进程
    {
        return SW_ERR;
    }
    //signal Init
    swServer_signal_init(serv);
    
    ret = swServer_start_proxy(serv);
    ...
}

void swServer_signal_init(swServer *serv)
{
    swSignal_add(SIGPIPE, NULL);
    swSignal_add(SIGHUP, NULL);
    if (serv->factory_mode != SW_MODE_BASE)
    {
        swSignal_add(SIGCHLD, swServer_signal_hanlder);
    }
    swSignal_add(SIGUSR1, swServer_signal_hanlder);
    swSignal_add(SIGUSR2, swServer_signal_hanlder);
    swSignal_add(SIGTERM, swServer_signal_hanlder);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swServer_signal_hanlder);
#endif
    swSignal_add(SIGALRM, swSystemTimer_signal_handler);
    //for test
    swSignal_add(SIGVTALRM, swServer_signal_hanlder);
    swServer_set_minfd(SwooleG.serv, SwooleG.signal_fd);
}
```

`swServer_signal_hanlder` 函数中是对其他信号函数的处理，

- `SIGTERM` 是终止信号，用于终止 `master` 线程的 `reactor` 线程。
- `SIGALRM` 是闹钟信号，我们在上一篇中已经详细介绍过。
- `SIGCHLD` 是子进程退出信号，如果调用 `waitpid` 之后，得到的是 `manager` 进程的进程 `id`，说明 `manager` 进程无故退出。
- `SIGVTALRM` 信号也是闹钟信号，是 `setitimer` 函数以 `ITIMER_VIRTUAL` 进程在用户态下花费的时间进行闹钟设置的时候触发，`swoole` 里均以 `ITIMER_REAL` 系统真实的时间来计算，因此理论上并不会有此信号，
- `SIGUSR1`、`SIGUSR2` 是 `manager` 进程默认重启 `worker` 进程的信号，只重启 `task` 进程使用 `SIGUSR2` 信号，重启所有 `worker` 进程使用 `SIGUSR1`，该信号也是 `swoole_server->reload` 函数发送给 `manager` 的信号。
- `SIGRTMIN` 信号被用于实现重新打开日志文件。在服务器程序运行期间日志文件被 `mv` 移动或 `unlink` 删除后，日志信息将无法正常写入，这时可以向 `Server` 发送 `SIGRTMIN` 信号

```
static void swServer_signal_hanlder(int sig)
{
    swTraceLog(SW_TRACE_SERVER, "signal[%d] triggered.", sig);

    swServer *serv = SwooleG.serv;
    int status;
    pid_t pid;
    switch (sig)
    {
    case SIGTERM:
        if (SwooleG.main_reactor)
        {
            SwooleG.main_reactor->running = 0;
        }
        else
        {
            SwooleG.running = 0;
        }
        swNotice("Server is shutdown now.");
        break;
    case SIGALRM:
        swSystemTimer_signal_handler(SIGALRM);
        break;
    case SIGCHLD:
        if (!SwooleG.running)
        {
            break;
        }
        if (SwooleG.serv->factory_mode == SW_MODE_SINGLE)
        {
            break;
        }
        pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0 && pid == serv->gs->manager_pid)
        {
            swWarn("Fatal Error: manager process exit. status=%d, signal=%d.", WEXITSTATUS(status), WTERMSIG(status));
        }
        break;
        /**
         * for test
         */
    case SIGVTALRM:
        swWarn("SIGVTALRM coming");
        break;
        /**
         * proxy the restart signal
         */
    case SIGUSR1:
    case SIGUSR2:
        if (SwooleG.serv->factory_mode == SW_MODE_SINGLE)
        {
            if (serv->gs->event_workers.reloading)
            {
                break;
            }
            serv->gs->event_workers.reloading = 1;
            serv->gs->event_workers.reload_init = 0;
        }
        else
        {
            kill(serv->gs->manager_pid, sig);
        }
        break;
    default:
#ifdef SIGRTMIN
        if (sig == SIGRTMIN)
        {
            int i;
            swWorker *worker;
            for (i = 0; i < SwooleG.serv->worker_num + serv->task_worker_num + SwooleG.serv->user_worker_num; i++)
            {
                worker = swServer_get_worker(SwooleG.serv, i);
                kill(worker->pid, SIGRTMIN);
            }
            if (SwooleG.serv->factory_mode == SW_MODE_PROCESS)
            {
                kill(serv->gs->manager_pid, SIGRTMIN);
            }
            swServer_reopen_log_file(SwooleG.serv);
        }
#endif
        break;
    }
}

```

`master` 线程在 `reactor` 事件循环中负责接受客户端的请求，在 `reactor` 事件循环中 `epoll_wait` 函数可能会被信号中断，这时程序会首先调用 `swSignal_async_handler` 设置 `reactor->singal_no`，然后返回 `n < 0`，执行 `swSignal_callback` 对应的信号处理函数。

```
static int swServer_start_proxy(swServer *serv)
{

    main_reactor->setHandle(main_reactor, SW_FD_LISTEN, swServer_master_onAccept);
    ...
    
    return main_reactor->wait(main_reactor, NULL);
}

static int swReactorEpoll_wait(swReactor *reactor, struct timeval *timeo)
{
    ...
    while (reactor->running > 0)
    {
        n = epoll_wait(epoll_fd, events, max_event_num, msec);
        if (n < 0)
        {
            if (swReactor_error(reactor) < 0)
            {
                swWarn("[Reactor#%d] epoll_wait failed. Error: %s[%d]", reactor_id, strerror(errno), errno);
                return SW_ERR;
            }
            else
            {
                continue;
            }
        }
        
        ...
        
        handle = swReactor_getHandle(reactor, SW_EVENT_READ, event.type);
        ret = handle(reactor, &event);
                
        ...
        
        
        if (reactor->onFinish != NULL)
        {
            reactor->onFinish(reactor);
        }
    }
    ...
}

static sw_inline int swReactor_error(swReactor *reactor)
{
    switch (errno)
    {
    case EINTR:
        if (reactor->singal_no)
        {
            swSignal_callback(reactor->singal_no);
            reactor->singal_no = 0;
        }
        return SW_OK;
    }
    return SW_ERR;
}
```

而在 `reactor` 事件循环中，`reactor` 中读写就绪的回调函数中仍然可能被信号中断，例如 `accept` 函数，即使 采用非阻塞也有可能被信号中断，这个时候需要忽略这种错误，继续进行 `accept` 直到 `EAGAIN` 错误。事件循环结束前会调用 `onFinish` 函数，该函数会检查 `reactor->singal_no` 并执行相应的信号处理函数。

```
int swServer_master_onAccept(swReactor *reactor, swEvent *event)
{
    ...
    for (i = 0; i < SW_ACCEPT_MAX_COUNT; i++) 
    {
        new_fd = accept(event->fd, (struct sockaddr *) &client_addr, &client_addrlen);
    
	    if (new_fd < 0)
	    {
	        switch (errno)
	        {
	        case EAGAIN:
	            return SW_OK;
	        case EINTR:
	            continue;
	        ...
	    }
    }
    ...
}

static void swReactor_onFinish(swReactor *reactor)
{
    //check signal
    if (reactor-singal_no)
    {
        swSignal_callback(reactor->singal_no);
        reactor->singal_no = 0;
    }
    swReactor_onTimeout_and_Finish(reactor);
}
```

### `reactor` 线程信号

对于 `reactor` 线程来说，承担了大量 `socket` 流量消息的收发，因此 `reactor` 不应该频繁的被信号中断影响 `reactor` 事件循环的效率。因此，在初始化截断，程序就调用 `swSignal_none` 阻塞了所有的信号，所有的信号处理都由 `master` 主线程来处理。当然 `SIGTERM`、`SIGSTOP` 等信号无法屏蔽。

```
static int swReactorThread_loop(swThreadParam *param)
{
   ...
   
   swSignal_none();
   
   ...

}
```

### `manager` 进程中信号的应用

`manager` 进程大部分信号的处理与 `master` 线程类似，唯一不同的是多了 `SIGID` 信号的处理，该信号是由 `worker` 进程发送给 `manager` 进程通知重启服务时使用的。

当发生信号时，`wait` 函数将会被中断，返回的 `pid` 小于 0，此时检查被中断的信号并相应进行操作，

```
static int swManager_loop(swFactory *factory)
{
   ...
   
    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGTERM, swManager_signal_handle);
    swSignal_add(SIGUSR1, swManager_signal_handle);
    swSignal_add(SIGUSR2, swManager_signal_handle);
    swSignal_add(SIGIO, swManager_signal_handle);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swManager_signal_handle);
    
    if (serv->manager_alarm > 0)
    {
        alarm(serv->manager_alarm);
        swSignal_add(SIGALRM, swManager_signal_handle);
    }
    
    SwooleG.main_reactor = NULL;
    
    ...

    while (SwooleG.running > 0)
    {
        _wait: pid = wait(&status);
        
        if (ManagerProcess.read_message) {...}
     
        if (pid < 0) 
        {
            if (ManagerProcess.alarm == 1) {}
        
            if (ManagerProcess.reloading == 0) 
            {
                error: if (errno != EINTR)
                {
                    swSysError("wait() failed.");
                }
                continue;
            }
            else if (ManagerProcess.reload_all_worker == 1) {...}
            else if (ManagerProcess.reload_task_worker == 1) {...}
            else
            {
                goto error;
            }
        }
    }
    
    swSignal_none();
}

static void swManager_signal_handle(int sig)
{
    switch (sig)
    {
    case SIGTERM:
        SwooleG.running = 0;
        break;
        /**
         * reload all workers
         */
    case SIGUSR1:
        if (ManagerProcess.reloading == 0)
        {
            ManagerProcess.reloading = 1;
            ManagerProcess.reload_all_worker = 1;
        }
        break;
        /**
         * only reload task workers
         */
    case SIGUSR2:
        if (ManagerProcess.reloading == 0)
        {
            ManagerProcess.reloading = 1;
            ManagerProcess.reload_task_worker = 1;
        }
        break;
    case SIGIO:
        ManagerProcess.read_message = 1;
        break;
    case SIGALRM:
        ManagerProcess.alarm = 1;
        break;
    default:
#ifdef SIGRTMIN
        if (sig == SIGRTMIN)
        {
            swServer_reopen_log_file(SwooleG.serv);
        }
#endif
        break;
    }
}
```

### `worker` 进程信号

与 `master` 进程类似，也要忽略 `SIGHUP`、`SIGPIPE` 信号，不同的是忽略了 `SIGUSR1`、`SIGUSR2` 信号。对于 `SIGTERM` 信号，`worker` 进程采取了异步关闭的措施，并不会强硬终止进程，而是要等到 `reactor` 事件循环完毕。

```
void swWorker_signal_init(void)
{
    swSignal_clear();
    /**
     * use user settings
     */
    SwooleG.use_signalfd = SwooleG.enable_signalfd;

    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGPIPE, NULL);
    swSignal_add(SIGUSR1, NULL);
    swSignal_add(SIGUSR2, NULL);
    //swSignal_add(SIGINT, swWorker_signal_handler);
    swSignal_add(SIGTERM, swWorker_signal_handler);
    swSignal_add(SIGALRM, swSystemTimer_signal_handler);
    //for test
    swSignal_add(SIGVTALRM, swWorker_signal_handler);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swWorker_signal_handler);
#endif
}

void swWorker_signal_handler(int signo)
{
    switch (signo)
    {
    case SIGTERM:
        /**
         * Event worker
         */
        if (SwooleG.main_reactor)
        {
            swWorker_stop();
        }
        /**
         * Task worker
         */
        else
        {
            SwooleG.running = 0;
        }
        break;
    case SIGALRM:
        swSystemTimer_signal_handler(SIGALRM);
        break;
    /**
     * for test
     */
    case SIGVTALRM:
        swWarn("SIGVTALRM coming");
        break;
    case SIGUSR1:
        break;
    case SIGUSR2:
        break;
    default:
#ifdef SIGRTMIN
        if (signo == SIGRTMIN)
        {
            swServer_reopen_log_file(SwooleG.serv);
        }
#endif
        break;
    }
}
```


### `task` 进程信号

`task` 进程不同于 `worker` 进程，使用的并不是 `reactor` + 非阻塞文件描述符，而是阻塞式描述符，并没有 `reactor` 来告知消息的到来。因此 `task` 进程的循环是阻塞在各个函数当中的。只有文件描述符可读，或者信号到来，才会从阻塞中返回。

当 `swMsgQueue_pop`、`accept`、`read` 等函数被信号中断后，信号处理函数会被执行，之后会返回 `n < 0`，这个时候由于信号处理函数已经被执行，因此只需要 `continue` 即可。对于闹钟信号，信号到来，还需要调用 `swTimer_select` 来筛选已经到时间的任务。

```
static void swTaskWorker_signal_init(void)
{
    swSignal_set(SIGHUP, NULL, 1, 0);
    swSignal_set(SIGPIPE, NULL, 1, 0);
    swSignal_set(SIGUSR1, swWorker_signal_handler, 1, 0);
    swSignal_set(SIGUSR2, NULL, 1, 0);
    swSignal_set(SIGTERM, swWorker_signal_handler, 1, 0);
    swSignal_set(SIGALRM, swSystemTimer_signal_handler, 1, 0);
#ifdef SIGRTMIN
    swSignal_set(SIGRTMIN, swWorker_signal_handler, 1, 0);
#endif
}

static int swProcessPool_worker_loop(swProcessPool *pool, swWorker *worker)
{
   ...
   
   while (SwooleG.running > 0 && task_n > 0)
   {
       if (pool->use_msgqueue)
        {
            n = swMsgQueue_pop(pool->queue, (swQueue_data *) &out, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] msgrcv() failed.", worker->id);
                break;
            }
        }
        else if (pool->use_socket)
        {
            int fd = accept(pool->stream->socket, NULL, NULL);
            if (fd < 0)
            {
                if (errno == EAGAIN || errno == EINTR)
                {
                    continue;
                }
                else
                {
                    swSysError("accept(%d) failed.", pool->stream->socket);
                    break;
                }
            }

            n = swStream_recv_blocking(fd, (void*) &out.buf, sizeof(out.buf));
            if (n == SW_CLOSE)
            {
                close(fd);
                continue;
            }
            pool->stream->last_connection = fd;
        }
        else
        {
            n = read(worker->pipe_worker, &out.buf, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] read(%d) failed.", worker->id, worker->pipe_worker);
            }
        }

        /**
         * timer
         */
        if (n < 0)
        {
            if (errno == EINTR && SwooleG.signal_alarm)
            {
                alarm_handler: SwooleG.signal_alarm = 0;
                swTimer_select(&SwooleG.timer);
            }
            continue;
        }

        /**
         * do task
         */
        worker->status = SW_WORKER_BUSY;
        worker->request_time = time(NULL);
        ret = pool->onTask(pool, &out.buf);
        worker->status = SW_WORKER_IDLE;
        worker->request_time = 0;
        worker->traced = 0;

        if (pool->use_socket && pool->stream->last_connection > 0)
        {
            int _end = 0;
            swSocket_write_blocking(pool->stream->last_connection, (void *) &_end, sizeof(_end));
            close(pool->stream->last_connection);
            pool->stream->last_connection = 0;
        }

        /**
         * timer
         */
        if (SwooleG.signal_alarm)
        {
            goto alarm_handler;
        }

        if (ret >= 0 && !worker_task_always)
        {
            task_n--;
        }
   
   }

}
```