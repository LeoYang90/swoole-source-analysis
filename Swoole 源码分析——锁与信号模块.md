# Swoole 源码分析——锁与信号模块

## 前言

对于多进程多线程的应用程序来说，保证数据正确的同步与更新离不开锁和信号，`swoole` 中的锁与信号基本采用 `pthread` 系列函数实现。`UNIX` 中的锁类型有很多种：互斥锁、自旋锁、文件锁、读写锁、原子锁，本节就会讲解 `swoole` 中各种锁的定义与使用。

[APUE 学习笔记——线程与锁](https://laravel-china.org/articles/13789/apue-learning-notes-thread)

[APUE 学习笔记——高级 IO与文件锁](https://laravel-china.org/articles/13815/apue-learning-notes-advanced-io)

## 数据结构

- `swoole` 中无论哪种锁，其数据结构都是 `swLock`，这个数据结构内部有一个联合体 `object`，这个联合体可以是 互斥锁、自旋锁、文件锁、读写锁、原子锁，`type` 可以指代这个锁的类型，具体可选项是 `SW_LOCKS` 这个枚举类型
- 该结构体还定义了几个函数指针，这几个函数类似于各个锁需要实现的接口，值得注意的是 `lock_rd` 和 `trylock_rd`两个函数是专门为了 `swFileLock` 和 `swRWLock` 设计的，其他锁没有这两个函数。

```
typedef struct _swLock
{
	int type;
    union
    {
        swMutex mutex;
#ifdef HAVE_RWLOCK
        swRWLock rwlock;
#endif
#ifdef HAVE_SPINLOCK
        swSpinLock spinlock;
#endif
        swFileLock filelock;
        swSem sem;
        swAtomicLock atomlock;
    } object;

    int (*lock_rd)(struct _swLock *);
    int (*lock)(struct _swLock *);
    int (*unlock)(struct _swLock *);
    int (*trylock_rd)(struct _swLock *);
    int (*trylock)(struct _swLock *);
    int (*free)(struct _swLock *);
} swLock;

enum SW_LOCKS
{
    SW_RWLOCK = 1,
#define SW_RWLOCK SW_RWLOCK
    SW_FILELOCK = 2,
#define SW_FILELOCK SW_FILELOCK
    SW_MUTEX = 3,
#define SW_MUTEX SW_MUTEX
    SW_SEM = 4,
#define SW_SEM SW_SEM
    SW_SPINLOCK = 5,
#define SW_SPINLOCK SW_SPINLOCK
    SW_ATOMLOCK = 6,
#define SW_ATOMLOCK SW_ATOMLOCK
};

```

## 互斥锁

互斥锁是最常用的进程/线程锁，`swMutex` 的基础是 `pthread_mutex` 系列函数, 因此该数据结构只有两个成员变量：`_lock`、`attr`：

```
typedef struct _swMutex
{
    pthread_mutex_t _lock;
    pthread_mutexattr_t attr;
} swMutex;
```

### 互斥锁的创建

互斥锁的创建就是 `pthread_mutex` 互斥锁的初始化，首先初始化互斥锁的属性 `pthread_mutexattr_t attr`，设定互斥锁是否要进程共享，之后设置各个关于锁的函数：

```
int swMutex_create(swLock *lock, int use_in_process)
{
    int ret;
    bzero(lock, sizeof(swLock));
    lock->type = SW_MUTEX;
    pthread_mutexattr_init(&lock->object.mutex.attr);
    if (use_in_process == 1)
    {
        pthread_mutexattr_setpshared(&lock->object.mutex.attr, PTHREAD_PROCESS_SHARED);
    }
    if ((ret = pthread_mutex_init(&lock->object.mutex._lock, &lock->object.mutex.attr)) < 0)
    {
        return SW_ERR;
    }
    lock->lock = swMutex_lock;
    lock->unlock = swMutex_unlock;
    lock->trylock = swMutex_trylock;
    lock->free = swMutex_free;
    return SW_OK;
}

```

### 互斥锁函数

互斥锁的函数就是调用相应的 `pthread_mutex` 系列函数：

```
static int swMutex_lock(swLock *lock)
{
    return pthread_mutex_lock(&lock->object.mutex._lock);
}

static int swMutex_unlock(swLock *lock)
{
    return pthread_mutex_unlock(&lock->object.mutex._lock);
}

static int swMutex_trylock(swLock *lock)
{
    return pthread_mutex_trylock(&lock->object.mutex._lock);
}

static int swMutex_free(swLock *lock)
{
    pthread_mutexattr_destroy(&lock->object.mutex.attr);
    return pthread_mutex_destroy(&lock->object.mutex._lock);
}

int swMutex_lockwait(swLock *lock, int timeout_msec)
{
    struct timespec timeo;
    timeo.tv_sec = timeout_msec / 1000;
    timeo.tv_nsec = (timeout_msec - timeo.tv_sec * 1000) * 1000 * 1000;
    return pthread_mutex_timedlock(&lock->object.mutex._lock, &timeo);
}

```

## 读写锁

对于读多写少的情况，读写锁可以显著的提高程序效率，`swRWLock` 的基础是 `pthread_rwlock` 系列函数：

```
typedef struct _swRWLock
{
    pthread_rwlock_t _lock;
    pthread_rwlockattr_t attr;

} swRWLock;

```

### 读写锁的创建

读写锁的创建过程和互斥锁类似：

```
int swRWLock_create(swLock *lock, int use_in_process)
{
    int ret;
    bzero(lock, sizeof(swLock));
    lock->type = SW_RWLOCK;
    pthread_rwlockattr_init(&lock->object.rwlock.attr);
    if (use_in_process == 1)
    {
        pthread_rwlockattr_setpshared(&lock->object.rwlock.attr, PTHREAD_PROCESS_SHARED);
    }
    if ((ret = pthread_rwlock_init(&lock->object.rwlock._lock, &lock->object.rwlock.attr)) < 0)
    {
        return SW_ERR;
    }
    lock->lock_rd = swRWLock_lock_rd;
    lock->lock = swRWLock_lock_rw;
    lock->unlock = swRWLock_unlock;
    lock->trylock = swRWLock_trylock_rw;
    lock->trylock_rd = swRWLock_trylock_rd;
    lock->free = swRWLock_free;
    return SW_OK;
}

```
### 读写锁函数

```

static int swRWLock_lock_rd(swLock *lock)
{
    return pthread_rwlock_rdlock(&lock->object.rwlock._lock);
}

static int swRWLock_lock_rw(swLock *lock)
{
    return pthread_rwlock_wrlock(&lock->object.rwlock._lock);
}

static int swRWLock_unlock(swLock *lock)
{
    return pthread_rwlock_unlock(&lock->object.rwlock._lock);
}

static int swRWLock_trylock_rd(swLock *lock)
{
    return pthread_rwlock_tryrdlock(&lock->object.rwlock._lock);
}

static int swRWLock_trylock_rw(swLock *lock)
{
    return pthread_rwlock_trywrlock(&lock->object.rwlock._lock);
}

static int swRWLock_free(swLock *lock)
{
    return pthread_rwlock_destroy(&lock->object.rwlock._lock);
}

```

## 文件锁

文件锁是对多进程、多线程同一时间写相同文件这一场景设定的锁，底层函数是 `fcntl`：

```
typedef struct _swFileLock
{
    struct flock lock_t;
    int fd;
} swFileLock;

```

### 文件锁的创建

```
int swFileLock_create(swLock *lock, int fd)
{
    bzero(lock, sizeof(swLock));
    lock->type = SW_FILELOCK;
    lock->object.filelock.fd = fd;
    lock->lock_rd = swFileLock_lock_rd;
    lock->lock = swFileLock_lock_rw;
    lock->trylock_rd = swFileLock_trylock_rd;
    lock->trylock = swFileLock_trylock_rw;
    lock->unlock = swFileLock_unlock;
    lock->free = swFileLock_free;
    return 0;
}

```

### 文件锁函数

```
static int swFileLock_lock_rd(swLock *lock)
{
    lock->object.filelock.lock_t.l_type = F_RDLCK;
    return fcntl(lock->object.filelock.fd, F_SETLKW, &lock->object.filelock);
}

static int swFileLock_lock_rw(swLock *lock)
{
    lock->object.filelock.lock_t.l_type = F_WRLCK;
    return fcntl(lock->object.filelock.fd, F_SETLKW, &lock->object.filelock);
}

static int swFileLock_unlock(swLock *lock)
{
    lock->object.filelock.lock_t.l_type = F_UNLCK;
    return fcntl(lock->object.filelock.fd, F_SETLKW, &lock->object.filelock);
}

static int swFileLock_trylock_rw(swLock *lock)
{
    lock->object.filelock.lock_t.l_type = F_WRLCK;
    return fcntl(lock->object.filelock.fd, F_SETLK, &lock->object.filelock);
}

static int swFileLock_trylock_rd(swLock *lock)
{
    lock->object.filelock.lock_t.l_type = F_RDLCK;
    return fcntl(lock->object.filelock.fd, F_SETLK, &lock->object.filelock);
}

static int swFileLock_free(swLock *lock)
{
    return close(lock->object.filelock.fd);
}

```

## 自旋锁

自旋锁类似于互斥锁，不同的是自旋锁在加锁失败的时候，并不会沉入内核，而是空转，这样的锁效率更高，但是会空耗 CPU
 资源：

```
typedef struct _swSpinLock
{
    pthread_spinlock_t lock_t;
} swSpinLock;

```

### 自旋锁的创建

```
int swSpinLock_create(swLock *lock, int use_in_process)
{
    int ret;
    bzero(lock, sizeof(swLock));
    lock->type = SW_SPINLOCK;
    if ((ret = pthread_spin_init(&lock->object.spinlock.lock_t, use_in_process)) < 0)
    {
        return -1;
    }
    lock->lock = swSpinLock_lock;
    lock->unlock = swSpinLock_unlock;
    lock->trylock = swSpinLock_trylock;
    lock->free = swSpinLock_free;
    return 0;
}

```

### 自旋锁函数

```
static int swSpinLock_lock(swLock *lock)
{
    return pthread_spin_lock(&lock->object.spinlock.lock_t);
}

static int swSpinLock_unlock(swLock *lock)
{
    return pthread_spin_unlock(&lock->object.spinlock.lock_t);
}

static int swSpinLock_trylock(swLock *lock)
{
    return pthread_spin_trylock(&lock->object.spinlock.lock_t);
}

static int swSpinLock_free(swLock *lock)
{
    return pthread_spin_destroy(&lock->object.spinlock.lock_t);
}

```

## 原子锁

不同于以上几种锁，`swoole` 的原子锁并不是 `pthread` 系列的锁，而是自定义实现的。

```
typedef volatile uint32_t                 sw_atomic_uint32_t;
typedef sw_atomic_uint32_t                sw_atomic_t;

typedef struct _swAtomicLock
{
    sw_atomic_t lock_t;
    uint32_t spin;
} swAtomicLock;

```

### 原子锁的创建

```
int swAtomicLock_create(swLock *lock, int spin)
{
    bzero(lock, sizeof(swLock));
    lock->type = SW_ATOMLOCK;
    lock->object.atomlock.spin = spin;
    lock->lock = swAtomicLock_lock;
    lock->unlock = swAtomicLock_unlock;
    lock->trylock = swAtomicLock_trylock;
    return SW_OK;
}

```

### 原子锁的加锁

```
static int swAtomicLock_lock(swLock *lock)
{
    sw_spinlock(&lock->object.atomlock.lock_t);
    return SW_OK;
}

```

原子锁的加锁逻辑函数 `sw_spinlock` 非常复杂，具体步骤如下：

- 如果原子锁没有被锁，那么调用原子函数 `sw_atomic_cmp_set`(`__sync_bool_compare_and_swap `) 进行加锁
- 若原子锁已经被加锁，如果是单核，那么就调用 `sched_yield` 函数让出执行权，因为这说明自旋锁已经被其他进程加锁，但是却被强占睡眠，我们需要让出控制权让那个唯一的 `cpu` 把那个进程跑下去，注意这时绝对不能进行自选，否则就是死锁。
- 如果是多核，就要不断空转的尝试加锁，防止睡眠，加锁的尝试间隔时间会指数增加，例如第一次 1 个时钟周期，第二次 2 时钟周期，第三次 4 时钟周期...
- 间隔时间内执行的函数 `sw_atomic_cpu_pause` 使用的是内嵌的汇编代码，目的在让 `cpu` 空转，禁止线程或进程被其他线程强占导致睡眠，恢复上下文浪费时间。
- 如果超过了 `SW_SPINLOCK_LOOP_N` 次数，还没有能够获取的到锁，那么也要让出控制权，这时很有可能被锁保护的代码有阻塞行为

```
#define sw_atomic_cmp_set(lock, old, set) __sync_bool_compare_and_swap(lock, old, set)
#define sw_atomic_cpu_pause()             __asm__ __volatile__ ("pause")
#define swYield()              sched_yield() //or usleep(1)

static sw_inline void sw_spinlock(sw_atomic_t *lock)
{
    uint32_t i, n;
    while (1)
    {
        if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
        {
            return;
        }
        if (SW_CPU_NUM > 1)
        {
            for (n = 1; n < SW_SPINLOCK_LOOP_N; n <<= 1)
            {
                for (i = 0; i < n; i++)
                {
                    sw_atomic_cpu_pause();
                }

                if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
                {
                    return;
                }
            }
        }
        swYield();
    }
}

```

### 原子锁的函数

```
static int swAtomicLock_unlock(swLock *lock)
{
    return lock->object.atomlock.lock_t = 0;
}

static int swAtomicLock_trylock(swLock *lock)
{
    sw_atomic_t *atomic = &lock->object.atomlock.lock_t;
    return (*(atomic) == 0 && sw_atomic_cmp_set(atomic, 0, 1));
}

```

## 信号量

信号量也是数据同步的一种重要方式，其数据结构为：

```
typedef struct _swSem
{
    key_t key;
    int semid;
} swSem;

```

### 信号量的创建

- 信号量的初始化首先需要调用 `semget` 创建一个新的信号量
- `semctl` 会将信号量初始化为 0

```
int swSem_create(swLock *lock, key_t key)
{
    int ret;
    lock->type = SW_SEM;
    if ((ret = semget(key, 1, IPC_CREAT | 0666)) < 0)
    {
        return SW_ERR;
    }

    if (semctl(ret, 0, SETVAL, 1) == -1)
    {
        swWarn("semctl(SETVAL) failed");
        return SW_ERR;
    }
    lock->object.sem.semid = ret;

    lock->lock = swSem_lock;
    lock->unlock = swSem_unlock;
    lock->free = swSem_free;

    return SW_OK;
}

```

### 信号量的 V 操作

```
static int swSem_unlock(swLock *lock)
{
    struct sembuf sem;
    sem.sem_flg = SEM_UNDO;
    sem.sem_num = 0;
    sem.sem_op = 1;
    return semop(lock->object.sem.semid, &sem, 1);
}

```

### 信号量的 P 操作

```
static int swSem_lock(swLock *lock)
{
    struct sembuf sem;
    sem.sem_flg = SEM_UNDO;
    sem.sem_num = 0;
    sem.sem_op = -1;
    return semop(lock->object.sem.semid, &sem, 1);
}

```

### 信号量的销毁

- `IPC_RMID` 用于销毁信号量

```
static int swSem_free(swLock *lock)
{
    return semctl(lock->object.sem.semid, 0, IPC_RMID);
}

```

## 条件变量

- 条件变量并没有作为 `swLock` 的一员，而是自成一体
- 条件变量不仅需要 `pthread_cond_t`，还需要互斥量 `swLock`

```
typedef struct _swCond
{
    swLock _lock;
    pthread_cond_t _cond;

    int (*wait)(struct _swCond *object);
    int (*timewait)(struct _swCond *object, long, long);
    int (*notify)(struct _swCond *object);
    int (*broadcast)(struct _swCond *object);
    void (*free)(struct _swCond *object);
    int (*lock)(struct _swCond *object);
    int (*unlock)(struct _swCond *object);
} swCond;

```	

### 条件变量的创建

```
int swCond_create(swCond *cond)
{
    if (pthread_cond_init(&cond->_cond, NULL) < 0)
    {
        swWarn("pthread_cond_init fail. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }
    if (swMutex_create(&cond->_lock, 0) < 0)
    {
        return SW_ERR;
    }

    cond->notify = swCond_notify;
    cond->broadcast = swCond_broadcast;
    cond->timewait = swCond_timewait;
    cond->wait = swCond_wait;
    cond->lock = swCond_lock;
    cond->unlock = swCond_unlock;
    cond->free = swCond_free;

    return SW_OK;
}

```

### 条件变量的函数

- 值得注意的是，条件变量的函数使用一定要结合 `swCond_lock`、`swCond_unlock` 等函数

```
static int swCond_notify(swCond *cond)
{
    return pthread_cond_signal(&cond->_cond);
}

static int swCond_broadcast(swCond *cond)
{
    return pthread_cond_broadcast(&cond->_cond);
}

static int swCond_timewait(swCond *cond, long sec, long nsec)
{
    struct timespec timeo;

    timeo.tv_sec = sec;
    timeo.tv_nsec = nsec;

    return pthread_cond_timedwait(&cond->_cond, &cond->_lock.object.mutex._lock, &timeo);
}

static int swCond_wait(swCond *cond)
{
    return pthread_cond_wait(&cond->_cond, &cond->_lock.object.mutex._lock);
}

static int swCond_lock(swCond *cond)
{
    return cond->_lock.lock(&cond->_lock);
}

static int swCond_unlock(swCond *cond)
{
    return cond->_lock.unlock(&cond->_lock);
}

static void swCond_free(swCond *cond)
{
    pthread_cond_destroy(&cond->_cond);
    cond->_lock.free(&cond->_lock);
}

```