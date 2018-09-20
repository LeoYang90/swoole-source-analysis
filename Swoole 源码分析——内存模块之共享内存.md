# Swoole 源码分析——内存模块之共享内存

## 前言

我们知道，由于 `PHP` 没有多线程模型，所以 `swoole` 更多的使用多进程模型，因此代码相对来说更加简洁，减少了各种线程锁的阻塞与同步，但是也带来了新的问题：数据同步。相比多线程之前可以直接共享进程的内存，进程之间数据的相互同步依赖于共享内存。本文将会讲解 `swoole` 中共享内存的源码。

前置知识：

- `mmap` 函数的使用: [APUE 学习笔记——高级 IO](https://laravel-china.org/articles/13815/apue-learning-notes-advanced-io)
- 共享内存： [APUE 学习笔记——进程间通信](https://laravel-china.org/articles/13822/apue-learning-notes-interprocess-communication)

## 共享内存数据结构

```c
typedef struct _swShareMemory_mmap
{
    size_t size;
    char mapfile[SW_SHM_MMAP_FILE_LEN];
    int tmpfd;
    int key;
    int shmid;
    void *mem;
} swShareMemory;

```

- 注意 `mem` 是一个 `void` 类型的指针，用于存放共享内存的首地址。这个成员变量相当于面向对象中的 `this` 指针，通过它就可以访问到 `swShareMemory` 的各个成员。

- `size` 代表共享内存的大小(不包括 `swShareMemory` 结构体大小)， `mapfile[]` 代表共享内存使用的内存映射文件的文件名， `tmpfd` 为内存映射文件的描述符。`key` 代表使用 `System V` 的 `shm` 系列函数创建的共享内存的 `key` 值， `shmid` 为 `shm` 系列函数创建的共享内存的 `id`（类似于fd），这两个由于不是 `POSIX` 标准定义的 `api`，用途有限。

## 共享内存的申请与创建

`swoole` 在申请共享内存时常常调用的函数是 `sw_shm_malloc`，这个函数可以为进程匿名申请一大块连续的共享内存：

```c
void* sw_shm_malloc(size_t size)
{
    swShareMemory object;
    void *mem;
    size += sizeof(swShareMemory);
    mem = swShareMemory_mmap_create(&object, size, NULL);
    if (mem == NULL)
    {
        return NULL;
    }
    else
    {
        memcpy(mem, &object, sizeof(swShareMemory));
        return mem + sizeof(swShareMemory);
    }
}
```

- 从 `sw_shm_malloc` 函数可以看出，虽然我们申请的是 `size`，但是实际申请的内存是要略大的，因为还要加上 `swShareMemory` 这个结构体。当函数返回时，也不会直接返回申请的内存首地址，而是复制了 `object` 各个成员变量的值后，在申请的首地址上加上 `swShareMemory` 的大小。

```c
void *swShareMemory_mmap_create(swShareMemory *object, size_t size, char *mapfile)
{
    void *mem;
    int tmpfd = -1;
    int flag = MAP_SHARED;
    bzero(object, sizeof(swShareMemory));

#ifdef MAP_ANONYMOUS
    flag |= MAP_ANONYMOUS;
#else
    if (mapfile == NULL)
    {
        mapfile = "/dev/zero";
    }
    if ((tmpfd = open(mapfile, O_RDWR)) < 0)
    {
        return NULL;
    }
    strncpy(object->mapfile, mapfile, SW_SHM_MMAP_FILE_LEN);
    object->tmpfd = tmpfd;
#endif

#if defined(SW_USE_HUGEPAGE) && defined(MAP_HUGETLB)
    if (size > 2 * 1024 * 1024)
    {
        flag |= MAP_HUGETLB;
    }
#endif

    mem = mmap(NULL, size, PROT_READ | PROT_WRITE, flag, tmpfd, 0);
#ifdef MAP_FAILED
    if (mem == MAP_FAILED)
#else
    if (!mem)
#endif
    {
        swWarn("mmap(%ld) failed. Error: %s[%d]", size, strerror(errno), errno);
        return NULL;
    }
    else
    {
        object->size = size;
        object->mem = mem;
        return mem;
    }
}

```

- 由于 `swoole` 的各个进程都是由 `master` 进程所建立，也就是各个进程之间存在亲戚关系， 因此`swShareMemory_mmap_create` 函数直接以 `匿名映射` 、（`/dev/zero` 设备） 的方式利用 `mmap` 建立共享内存，并没有 `open` 具体的共享内存文件，或者调用 `shm_open` 打开 `POSIX IPC` 名字。

- 值得注意的是 `MAP_HUGETLB`，这个是 `linux` 内核 `2.6.32` 引入的一个 `flags`，用于使用大页面分配共享内存。大页是相对传统 `4K` 小页而言的，一般来说常见的体系架构都会提供2种大页大小，比如常见的 `2M` 大页和 `1G` 大页。使用大页可以减少页表项数量，从而减少 `TLB Miss` 的概率，提升系统访存性能。当然有利必有弊，使用大页降低了内存管理的粒度和灵活性，如果程序并不是对内存的使用量特别大，使用大页还可能造成内存的浪费。

## 共享内存的 `calloc`

`calloc` 与 `malloc` 大同小异，无非多了一个 `num` 参数

```c
void* sw_shm_calloc(size_t num, size_t _size)
{
    swShareMemory object;
    void *mem;
    void *ret_mem;
    int size = sizeof(swShareMemory) + (num * _size);
    mem = swShareMemory_mmap_create(&object, size, NULL);
    if (mem == NULL)
    {
        return NULL;
    }
    else
    {
        memcpy(mem, &object, sizeof(swShareMemory));
        ret_mem = mem + sizeof(swShareMemory);
        bzero(ret_mem, size - sizeof(swShareMemory));
        return ret_mem;
    }
}

```

## 共享内存的 `realloc`

`realloc` 函数用于修改已申请的内存大小，逻辑非常简单，先申请新的内存，进行复制后，再释放旧的内存：

```c
void* sw_shm_realloc(void *ptr, size_t new_size)
{
    swShareMemory *object = ptr - sizeof(swShareMemory);
    void *new_ptr;
    new_ptr = sw_shm_malloc(new_size);
    if (new_ptr == NULL)
    {
        return NULL;
    }
    else
    {
        memcpy(new_ptr, ptr, object->size);
        sw_shm_free(ptr);
        return new_ptr;
    }
}

```

## 修改共享内存的权限

在内存映射完成后，由标记读、写、执行权限的 `PROT_READ`、`PROT_WRITE` 和 `PROT_EXEC` 等权限仍可以被 `mprotect` 系统调用所修改。

```c
int sw_shm_protect(void *addr, int flags)
{
    swShareMemory *object = (swShareMemory *) (addr - sizeof(swShareMemory));
    return mprotect(object, object->size, flags);
}

```
## 共享内存的释放

```c
void sw_shm_free(void *ptr)
{
    swShareMemory *object = ptr - sizeof(swShareMemory);
    swShareMemory_mmap_free(object);
}

int swShareMemory_mmap_free(swShareMemory *object)
{
    return munmap(object->mem, object->size);
}

```
