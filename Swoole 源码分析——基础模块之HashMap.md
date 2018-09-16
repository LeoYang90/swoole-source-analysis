# Swoole 源码分析——基础模块之HashMap

## `HashMap` 的数据结构

- `HashMap` 的数据结构很简单，就是一个根节点、一个迭代器还有一个析构函数
- `HashMap` 比较复杂的地方在于其节点 `swHashMap_node` 的 `UT_hash_handle` 数据成员，该数据成员是 `C` 语言 `hash` 库 `uthash`，`HashMap` 大部分功能依赖于这个 `uthash`。
- `swHashMap_node` 中 `key_int` 是键值的长度，`key_str` 是具体的键值，`data` 是 `value` 数据

```
typedef void (*swHashMap_dtor)(void *data);

typedef struct
{
    struct swHashMap_node *root;
    struct swHashMap_node *iterator;
    swHashMap_dtor dtor;
} swHashMap;

typedef struct swHashMap_node
{
    uint64_t key_int;
    char *key_str;
    void *data;
    UT_hash_handle hh;
} swHashMap_node;

```

## `HashMap` 

由于 `HashMap` 是在底层 `uthash` 哈希表的基础上构建的，如果想要详细了解其原理大家可以先看看下一节内容后再阅读本小节。

### `HashMap` 的初始化

- `HashMap` 的初始化主要是对底层 `uthash` 哈希表进行内存的分配、初始化
- `uthash` 哈希表的初始化包括 `tbl`、`buckets` 的初始化，成员变量的具体意义可以参考下一节内容

```
swHashMap* swHashMap_new(uint32_t bucket_num, swHashMap_dtor dtor)
{
    swHashMap *hmap = sw_malloc(sizeof(swHashMap));
    if (!hmap)
    {
        swWarn("malloc[1] failed.");
        return NULL;
    }
    swHashMap_node *root = sw_malloc(sizeof(swHashMap_node));
    if (!root)
    {
        swWarn("malloc[2] failed.");
        sw_free(hmap);
        return NULL;
    }

    bzero(hmap, sizeof(swHashMap));
    hmap->root = root;

    bzero(root, sizeof(swHashMap_node));

    root->hh.tbl = (UT_hash_table*) sw_malloc(sizeof(UT_hash_table));
    if (!(root->hh.tbl))
    {
        swWarn("malloc for table failed.");
        sw_free(hmap);
        return NULL;
    }

    memset(root->hh.tbl, 0, sizeof(UT_hash_table));
    root->hh.tbl->tail = &(root->hh);
    root->hh.tbl->num_buckets = SW_HASHMAP_INIT_BUCKET_N;
    root->hh.tbl->log2_num_buckets = HASH_INITIAL_NUM_BUCKETS_LOG2;
    root->hh.tbl->hho = (char*) (&root->hh) - (char*) root;
    root->hh.tbl->buckets = (UT_hash_bucket*) sw_malloc(SW_HASHMAP_INIT_BUCKET_N * sizeof(struct UT_hash_bucket));
    if (!root->hh.tbl->buckets)
    {
        swWarn("malloc for buckets failed.");
        sw_free(hmap);
        return NULL;
    }
    memset(root->hh.tbl->buckets, 0, SW_HASHMAP_INIT_BUCKET_N * sizeof(struct UT_hash_bucket));
    root->hh.tbl->signature = HASH_SIGNATURE;

    hmap->dtor = dtor;

    return hmap;
}

```

### `HashMap` 的新元素添加

- 首先需要新建一个 `swHashMap_node`，为 `key_str`、`key_int` 与 `data`
- 将新建的 `swHashMap_node` 添加到哈希表中
- 为 `UT_hash_handler` 的 `prev`、`next`、`key`、`keylen`、`hashv`、`tbl` 成员变量赋值，将新的 `UT_hash_handler` 放入双向链表的尾部，更新 `tbl` 的 `tail` 成员
- 利用 `HASH_ADD_TO_BKT` 函数将 `UT_hash_handler` 插入到哈希桶中

```
int swHashMap_add(swHashMap* hmap, char *key, uint16_t key_len, void *data)
{
    swHashMap_node *node = (swHashMap_node*) sw_malloc(sizeof(swHashMap_node));
    if (node == NULL)
    {
        swWarn("malloc failed.");
        return SW_ERR;
    }
    bzero(node, sizeof(swHashMap_node));
    swHashMap_node *root = hmap->root;
    node->key_str = sw_strndup(key, key_len);
    node->key_int = key_len;
    node->data = data;
    return swHashMap_node_add(root, node);
}

static sw_inline int swHashMap_node_add(swHashMap_node *root, swHashMap_node *add)
{
    unsigned _ha_bkt;
    add->hh.next = NULL;
    add->hh.key = add->key_str;
    add->hh.keylen = add->key_int;

    root->hh.tbl->tail->next = add;
    add->hh.prev = ELMT_FROM_HH(root->hh.tbl, root->hh.tbl->tail);
    root->hh.tbl->tail = &(add->hh);

    root->hh.tbl->num_items++;
    add->hh.tbl = root->hh.tbl;
    add->hh.hashv = swoole_hash_jenkins(add->key_str, add->key_int);
    _ha_bkt = add->hh.hashv & (root->hh.tbl->num_buckets - 1);

    HASH_ADD_TO_BKT(root->hh.tbl->buckets[_ha_bkt], &add->hh);

    return SW_OK;
}
```

### `swHashMap_add_int` 添加 int 类型元素 

- `swHashMap_add_int` 直接调用 `HASH_ADD_INT` 更新整个哈希表，比起 `swHashMap_add` 函数，没有了复杂的 `uthash` 数据结构的更新

```
int swHashMap_add_int(swHashMap *hmap, uint64_t key, void *data)
{
    swHashMap_node *node = (swHashMap_node*) sw_malloc(sizeof(swHashMap_node));
    swHashMap_node *root = hmap->root;
    if (node == NULL)
    {
        swWarn("malloc failed");
        return SW_ERR;
    }
    node->key_int = key;
    node->data = data;
    node->key_str = NULL;
    HASH_ADD_INT(root, key_int, node);
    return SW_OK;
}

```

### `swHashMap_find` 查找元素

- 首先先通过哈希键计算哈希值，找出哈希桶的索引
- `HASH_FIND_IN_BKT` 会根据哈希桶来查找具体的元素

```
void* swHashMap_find(swHashMap* hmap, char *key, uint16_t key_len)
{
    swHashMap_node *root = hmap->root;
    swHashMap_node *ret = swHashMap_node_find(root, key, key_len);
    if (ret == NULL)
    {
        return NULL;
    }
    return ret->data;
}

static sw_inline swHashMap_node *swHashMap_node_find(swHashMap_node *root, char *key_str, uint16_t key_len)
{
    swHashMap_node *out;
    unsigned bucket, hash;
    out = NULL;
    if (root)
    {
        hash = swoole_hash_jenkins(key_str, key_len);
        bucket = hash & (root->hh.tbl->num_buckets - 1);
        HASH_FIND_IN_BKT(root->hh.tbl, hh, (root)->hh.tbl->buckets[bucket], key_str, key_len, out);
    }
    return out;
}

```

### `swHashMap_find_int` 函数

- `swHashMap_find_int` 函数直接调用 `HASH_FIND_INT` 查找

```
void* swHashMap_find_int(swHashMap* hmap, uint64_t key)
{
    swHashMap_node *ret = NULL;
    swHashMap_node *root = hmap->root;
    HASH_FIND_INT(root, &key, ret);
    if (ret == NULL)
    {
        return NULL;
    }
    return ret->data;
}

```

### `swHashMap_each` 遍历

- `swHashMap_each` 利用迭代器不断获取下一个元素

```
void* swHashMap_each(swHashMap* hmap, char **key)
{
    swHashMap_node *node = swHashMap_node_each(hmap);
    if (node)
    {
        *key = node->key_str;
        return node->data;
    }
    else
    {
        return NULL;
    }
}

static sw_inline swHashMap_node* swHashMap_node_each(swHashMap* hmap)
{
    swHashMap_node *iterator = hmap->iterator;
    swHashMap_node *tmp;

    if (hmap->root->hh.tbl->num_items == 0)
    {
        return NULL;
    }
    if (iterator == NULL)
    {
        iterator = hmap->root;
    }
    tmp = iterator->hh.next;
    if (tmp)
    {
        hmap->iterator = tmp;
        return tmp;
    }
    else
    {
        hmap->iterator = NULL;
        return NULL;
    }
}

```

### `swHashMap_count` 函数

```
uint32_t swHashMap_count(swHashMap* hmap)
{
    if (hmap == NULL)
    {
        return 0;
    }
    return HASH_COUNT(hmap->root);
}

```

### `swHashMap_del` 删除元素

- 删除元素首先需要 `swHashMap_node_delete` 函数来重构哈希表，然后调用 `swHashMap_node_free` 释放内存

```
int swHashMap_del(swHashMap* hmap, char *key, uint16_t key_len)
{
    swHashMap_node *root = hmap->root;
    swHashMap_node *node = swHashMap_node_find(root, key, key_len);
    if (node == NULL)
    {
        return SW_ERR;
    }
    swHashMap_node_delete(root, node);
    swHashMap_node_free(hmap, node);
    return SW_OK;
}

static sw_inline void swHashMap_node_free(swHashMap *hmap, swHashMap_node *node)
{
    swHashMap_node_dtor(hmap, node);
    sw_free(node->key_str);
    sw_free(node);
}
```
- 删除重构哈希表流程较为复杂，步骤和 `HASH_DELETE` 函数逻辑一致，详细可以看下一节

```
static int swHashMap_node_delete(swHashMap_node *root, swHashMap_node *del_node)
{
    unsigned bucket;
    struct UT_hash_handle *_hd_hh_del;

    if ((del_node->hh.prev == NULL) && (del_node->hh.next == NULL))
    {
        sw_free(root->hh.tbl->buckets);
        sw_free(root->hh.tbl);
    }
    else
    {
        _hd_hh_del = &(del_node->hh);
        if (del_node == ELMT_FROM_HH(root->hh.tbl, root->hh.tbl->tail))
        {
            root->hh.tbl->tail = (UT_hash_handle*) ((ptrdiff_t) (del_node->hh.prev) + root->hh.tbl->hho);
        }
        if (del_node->hh.prev)
        {
            ((UT_hash_handle*) ((ptrdiff_t) (del_node->hh.prev) + root->hh.tbl->hho))->next = del_node->hh.next;
        }
        else
        {
            DECLTYPE_ASSIGN(root, del_node->hh.next);
        }
        if (_hd_hh_del->next)
        {
            ((UT_hash_handle*) ((ptrdiff_t) _hd_hh_del->next + root->hh.tbl->hho))->prev = _hd_hh_del->prev;
        }
        HASH_TO_BKT(_hd_hh_del->hashv, root->hh.tbl->num_buckets, bucket);
        HASH_DEL_IN_BKT(hh, root->hh.tbl->buckets[bucket], _hd_hh_del);
        root->hh.tbl->num_items--;
    }
    return SW_OK;
}

```

### `swHashMap_del_int` 函数

- `swHashMap_del_int` 函数没有复杂逻辑，直接调用了 `HASH_DEL` 这个第三方库

```
int swHashMap_del_int(swHashMap *hmap, uint64_t key)
{
    swHashMap_node *ret = NULL;
    swHashMap_node *root = hmap->root;

    HASH_FIND_INT(root, &key, ret);
    if (ret == NULL)
    {
        return SW_ERR;
    }
    HASH_DEL(root, ret);
    swHashMap_node_free(hmap, ret);
    return SW_OK;
}

```

### `swHashMap_free` 销毁哈希表

- 销毁哈希表需要循环所有的哈希节点元素，逐个删除
- `HASH_ITER` 用于循环所有的哈希节点元素

```
void swHashMap_free(swHashMap* hmap)
{
    swHashMap_node *find, *tmp = NULL;
    swHashMap_node *root = hmap->root;
    HASH_ITER(hh, root, find, tmp)
    {
        if (find == root) continue;
        swHashMap_node_delete(root, find);
        swHashMap_node_free(hmap, find);
    }

    sw_free(hmap->root->hh.tbl->buckets);
    sw_free(hmap->root->hh.tbl);
    sw_free(hmap->root);

    sw_free(hmap);
}

```

## `uthash` 哈希表

`uthash` 是使用开链法实现的哈希表，其代码均是宏函数编写，首先我们先看看这个哈希表的数据结构：

- `uthash` 由三种数据结构构成：`UT_hash_table`、`UT_hash_bucket`、`UT_hash_handle`

![](http://owql68l6p.bkt.clouddn.com/20180724110205636.png)

### `UT_hash_table`
- `UT_hash_table` 是整个哈希表的核心，`UT_hash_bucket` 是根据哈希值排列的数组，`UT_hash_handle` 是开链法中哈希冲突的链表

![](http://owql68l6p.bkt.clouddn.com/GqDDq.jpg)

- 从上图可以清楚的看出来 `UT_hash_table` 的数据结构：

    - `buckets` 是哈希桶数组的首地址；`num_buckets` 是哈希桶的数量；`log2_num_buckets` 是 `log2(num_buckets)` 的值
    - `tail` 是哈希链表的最后那个元素地址;`num_items` 是哈希链表的元素个数
    - `hho`：成员变量 `UT_hash_handle` 相对于用户结构体首部的位置
    - `ideal_chain_maxlen` ：在理想情况下，即所有的元素刚好平坦到每个 `buckets` 指向的链表中，任何两个链表的数目相差不超过1时，一个链表中能够容纳的元素数目，实际上就等于 `num_items / num_buckets + (num_items % num_buckets == 0 ? 0 : 1)`；
    - `nonideal_items` ：实际上 `buckets` 的数目超过 `ideal_chain_maxlen` 的链表数；
    - `noexpand`：当这个值为1时，永远不会对 `buckets` 的大小进行扩充
    - `ineff_expands`：当某个 `buckets` 的链表过长时，需要对 `buckets` 指向的数组的大小进行扩充，然后对整个链表重新分配各自的哈希桶；扩张后如果 `nonideal_items` 仍然大于 `num_items` 的一半时，也就是说明当前哈希表严重不平衡，哈希冲突很严重，这个时候说明当前的键值有问题，或者哈希算法有问题，并不是扩充 `buckets` 数组能够解决的。这个时候，就会递增 `ineff_expands` 的值，当 `ineff_expands` 大于 1 的时候，就会设置 `noexpand` 设置为 1，永远不会扩充 `buckets` 的大小。
    - `bloom_bv`：指向一个 `uint8_t` 类型的数组，用来标记 `buckets` 中每个链表是否为空，可以优化查找的速度，因为这个数组中每个元素是一个字节，所以每个元素可以标记8个链表，例如要判断 `bucket[1]->hh_head` 是否为空，只要判断`(bloom_bv[0] & 2)` 是否为0即可;
    - `bloom_nbits`：`bloom_bv` 指向的数组大小为 (1 << `bloom_nbits`)。

```
typedef struct UT_hash_table {
   UT_hash_bucket *buckets;
   unsigned num_buckets, log2_num_buckets;
   unsigned num_items;
   struct UT_hash_handle *tail;
   ptrdiff_t hho; 

   unsigned ideal_chain_maxlen;

   unsigned nonideal_items;

   unsigned ineff_expands, noexpand;

   uint32_t signature; /* used only to test bloom exists in external analysis */
   
   #ifdef HASH_BLOOM
   uint32_t bloom_sig; /* used only to test bloom exists in external analysis */
   uint8_t *bloom_bv;
   char bloom_nbits;
#endif

} UT_hash_table;

```
### `UT_hash_handle`

- `UT_hash_handle` 是存储数据的真正地方，也是哈希表的最小结构单元，如下图，不同于一般的开链法，只有在哈希冲突的时候才会将两个元素用链表连接起来，`uthash` 哈希表将所有 `UT_hash_handle` 元素构成了两种双向链表
	- `prev`、`next` 构成的双向链表将所有 `UT_hash_handle` 元素都连接到了一起，这个是为了能够快速的访问所有的数据，
	- `hh_prev`、`hh_next`将所有哈希冲突的、哈希值相同的元素归并到了一起
- `key`、`keylen` 是存储的键值与长度，`hashv` 是键值的哈希值
- `tbl` 是上一小节的 `UT_hash_table`	

```
typedef struct UT_hash_handle {
   struct UT_hash_table *tbl;
   void *prev;                       /* prev element in app order      */
   void *next;                       /* next element in app order      */
   struct UT_hash_handle *hh_prev;   /* previous hh in bucket order    */
   struct UT_hash_handle *hh_next;   /* next hh in bucket order        */
   void *key;                        /* ptr to enclosing struct's key  */
   unsigned keylen;                  /* enclosing struct's key len     */
   unsigned hashv;                   /* result of hash-fcn(key)        */
} UT_hash_handle;


```

![](http://owql68l6p.bkt.clouddn.com/0_1328239340pSPd.gif)

### `UT_hash_bucket`

- 哈希桶是哈希表非常重要的成员，位于同一个哈希桶内的 `UT_hash_handle` 元素拥有相同的哈希值 `hashv`，不过这种概率很小。
- 由于 `buckets` 指向的数组可能比较小（初始值为32，这个值一定是2的指数次方），所以会先对 `UT_hash_handle` 元素 中的 `hashv` 进行一次按位与操作 `(idx = (hashv & (num_buckets-1)))`，然后被插入到 `buckets[idx]->hh_head` 指向的双向链表中
- `count`: `hh_head` 指向的链表中的元素数目；
- `expand_mult`：当 `count` 的值大于 `(expand_mult+1)*10` 时，则对 `buckets` 指向的数组的大小进行扩充；在扩充之后 `expand_mult` 被设定为 `count / ideal_chain_maxlen`。



```
typedef struct UT_hash_bucket {
   struct UT_hash_handle *hh_head;
   unsigned count;
   
   unsigned expand_mult;

} UT_hash_bucket;

```


### `ELMT_FROM_HH` 函数

我们之前说 `UT_hash_handle` 元素构成了两套双向链表，`prev`、`next` 构成了其中一套，但是确切地说 `prev`、`next` 指向的地址并不是 `UT_hash_handle` 的地址，而是它的上一层。例如我们之前说的：

```
typedef struct swHashMap_node
{
    uint64_t key_int;
    char *key_str;
    void *data;
    UT_hash_handle hh;
} swHashMap_node;

```
`prev`、`next` 指向的地址实际是 `swHashMap_node` 的地址，这个 `swHashMap_node` 与 `UT_hash_handle` 之间还有用户自定义的 `header` 数据，这个数据的大小就是 `UT_hash_table` 的 `hho` 成员变量的值。

`ELMT_FROM_HH` 就是通过 `UT_hash_handle` 的地址反算 `swHashMap_node` 地址的函数：


```
#define ELMT_FROM_HH(tbl,hhp) ((void*)(((char*)(hhp)) - ((tbl)->hho)))

```

### `HASH_TO_BKT` 函数

- `HASH_TO_BKT` 函数根据哈希值计算哈希桶的索引值，因为哈希值会很大，必然要转为哈希桶数组的 `index`

```
#define HASH_TO_BKT( hashv, num_bkts, bkt )                                      \
do {                                                                             \
  bkt = ((hashv) & ((num_bkts) - 1));                                            \
} while(0)

```

### `HASH_MAKE_TABLE` 函数

- `HASH_MAKE_TABLE` 函数用于创建 `UT_hash_table`

```
#define HASH_MAKE_TABLE(hh,head)                                                 \
do {                                                                             \
  (head)->hh.tbl = (UT_hash_table*)uthash_malloc(                                \
                  sizeof(UT_hash_table));                                        \
  if (!((head)->hh.tbl))  { uthash_fatal( "out of memory"); }                    \
  memset((head)->hh.tbl, 0, sizeof(UT_hash_table));                              \
  (head)->hh.tbl->tail = &((head)->hh);                                          \
  (head)->hh.tbl->num_buckets = HASH_INITIAL_NUM_BUCKETS;                        \
  (head)->hh.tbl->log2_num_buckets = HASH_INITIAL_NUM_BUCKETS_LOG2;              \
  (head)->hh.tbl->hho = (char*)(&(head)->hh) - (char*)(head);                    \
  (head)->hh.tbl->buckets = (UT_hash_bucket*)uthash_malloc(                      \
          HASH_INITIAL_NUM_BUCKETS*sizeof(struct UT_hash_bucket));               \
  if (! (head)->hh.tbl->buckets) { uthash_fatal( "out of memory"); }             \
  memset((head)->hh.tbl->buckets, 0,                                             \
          HASH_INITIAL_NUM_BUCKETS*sizeof(struct UT_hash_bucket));               \
  HASH_BLOOM_MAKE((head)->hh.tbl);                                               \
  (head)->hh.tbl->signature = HASH_SIGNATURE;                                    \
} while(0)

```

### `HASH_ADD_TO_BKT` 函数

- `HASH_ADD_TO_BKT` 函数用于向 `UT_hash_bucket` 中添加新的 `UT_hash_handle` 元素
- `head` 是通过哈希已经计算好的哈希桶，`addhh` 是要新添加的 `UT_hash_handle` 元素
- 新添加的元素会替换哈希桶的 `hh_head`
- 如果当前哈希桶中的 `UT_hash_handle` 元素数量过多，就会考虑扩充 `UT_hash_bucket` 的数量，并且重新分配

```
/* add an item to a bucket  */
#define HASH_ADD_TO_BKT(head,addhh)                                              \
do {                                                                             \
 head.count++;                                                                   \
 (addhh)->hh_next = head.hh_head;                                                \
 (addhh)->hh_prev = NULL;                                                        \
 if (head.hh_head) { (head).hh_head->hh_prev = (addhh); }                        \
 (head).hh_head=addhh;                                                           \
 if (head.count >= ((head.expand_mult+1) * HASH_BKT_CAPACITY_THRESH)             \
     && (addhh)->tbl->noexpand != 1) {                                           \
       HASH_EXPAND_BUCKETS((addhh)->tbl);                                        \
 }                                                                               \
} while(0)

```

### `HASH_EXPAND_BUCKETS` 函数

- `HASH_EXPAND_BUCKETS` 函数用于扩充哈希桶的数量
- 每次扩充都会增长一倍，并且重新计算 `ideal_chain_maxlen`
- 遍历所有的 `UT_hash_handle` 元素，并且根据他们的 `hashv` 重新计算它们归属的哈希桶的索引，并将其放入新的哈希桶中
- 更新 `UT_hash_table` 的 `num_buckets`、`log2_num_buckets`
- 重新计算	`nonideal_items` 值，如果大于元素的一半，说明哈希冲突仍然严重，哈希桶的扩容并不能解决问题，那么就将 `ineff_expands` 递增，必要的时候禁止哈希桶的扩容

```
#define HASH_EXPAND_BUCKETS(tbl)                                                 \
do {                                                                             \
    unsigned _he_bkt;                                                            \
    unsigned _he_bkt_i;                                                          \
    struct UT_hash_handle *_he_thh, *_he_hh_nxt;                                 \
    UT_hash_bucket *_he_new_buckets, *_he_newbkt;                                \
    _he_new_buckets = (UT_hash_bucket*)uthash_malloc(                            \
             2 * tbl->num_buckets * sizeof(struct UT_hash_bucket));              \
    if (!_he_new_buckets) { uthash_fatal( "out of memory"); }                    \
    memset(_he_new_buckets, 0,                                                   \
            2 * tbl->num_buckets * sizeof(struct UT_hash_bucket));               \
    tbl->ideal_chain_maxlen =                                                    \
       (tbl->num_items >> (tbl->log2_num_buckets+1)) +                           \
       ((tbl->num_items & ((tbl->num_buckets*2)-1)) ? 1 : 0);                    \
    tbl->nonideal_items = 0;                                                     \
    for(_he_bkt_i = 0; _he_bkt_i < tbl->num_buckets; _he_bkt_i++)                \
    {                                                                            \
        _he_thh = tbl->buckets[ _he_bkt_i ].hh_head;                             \
        while (_he_thh) {                                                        \
           _he_hh_nxt = _he_thh->hh_next;                                        \
           HASH_TO_BKT( _he_thh->hashv, tbl->num_buckets*2, _he_bkt);            \
           _he_newbkt = &(_he_new_buckets[ _he_bkt ]);                           \
           if (++(_he_newbkt->count) > tbl->ideal_chain_maxlen) {                \
             tbl->nonideal_items++;                                              \
             _he_newbkt->expand_mult = _he_newbkt->count /                       \
                                        tbl->ideal_chain_maxlen;                 \
           }                                                                     \
           _he_thh->hh_prev = NULL;                                              \
           _he_thh->hh_next = _he_newbkt->hh_head;                               \
           if (_he_newbkt->hh_head) _he_newbkt->hh_head->hh_prev =               \
                _he_thh;                                                         \
           _he_newbkt->hh_head = _he_thh;                                        \
           _he_thh = _he_hh_nxt;                                                 \
        }                                                                        \
    }                                                                            \
    uthash_free( tbl->buckets, tbl->num_buckets*sizeof(struct UT_hash_bucket) ); \
    tbl->num_buckets *= 2;                                                       \
    tbl->log2_num_buckets++;                                                     \
    tbl->buckets = _he_new_buckets;                                              \
    tbl->ineff_expands = (tbl->nonideal_items > (tbl->num_items >> 1)) ?         \
        (tbl->ineff_expands+1) : 0;                                              \
    if (tbl->ineff_expands > 1) {                                                \
        tbl->noexpand=1;                                                         \
        uthash_noexpand_fyi(tbl);                                                \
    }                                                                            \
    uthash_expand_fyi(tbl);                                                      \
} while(0)

```

### `HASH_ADD_INT` 函数

 - `HASH_ADD_INT` 函数是 `HASH_ADD_TO_BKT` 的 `int` 特例
 - 首先判断当前哈希表是否存在，如果不存在，那么就用 `HASH_MAKE_TABLE` 创建一个哈希表
 - 如果哈希表存在，那么就将 `UT_hash_handle` 放入双向链表表尾
 - 利用 `HASH_FCN` 计算哈希值，并利用 `HASH_ADD_TO_BKT` 将其放入对应的哈希桶中
 - `HASH_BLOOM_ADD` 函数为 `bloom_bv` 设置位，用于快速判断当前 `hashv` 值存在元素

```
#define HASH_ADD_INT(head,intfield,add)                                          \
    HASH_ADD(hh,head,intfield,sizeof(int),add)
    
#define HASH_ADD(hh,head,fieldname,keylen_in,add)                                \
    HASH_ADD_KEYPTR(hh,head,&((add)->fieldname),keylen_in,add)
    
#define HASH_BLOOM_ADD(tbl,hashv)                                                \
  HASH_BLOOM_BITSET((tbl)->bloom_bv, (hashv & (uint32_t)((1ULL << (tbl)->bloom_nbits) - 1)))
  
#define HASH_BLOOM_BITSET(bv,idx) (bv[(idx)/8] |= (1U << ((idx)%8)))
        
#define HASH_ADD_KEYPTR(hh,head,keyptr,keylen_in,add)                            \
do {                                                                             \
 unsigned _ha_bkt;                                                               \
 (add)->hh.next = NULL;                                                          \
 (add)->hh.key = (char*)(keyptr);                                                \
 (add)->hh.keylen = (unsigned)(keylen_in);                                       \
 if (!(head)) {                                                                  \
    head = (add);                                                                \
    (head)->hh.prev = NULL;                                                      \
    HASH_MAKE_TABLE(hh,head);                                                    \
 } else {                                                                        \
    (head)->hh.tbl->tail->next = (add);                                          \
    (add)->hh.prev = ELMT_FROM_HH((head)->hh.tbl, (head)->hh.tbl->tail);         \
    (head)->hh.tbl->tail = &((add)->hh);                                         \
 }                                                                               \
 (head)->hh.tbl->num_items++;                                                    \
 (add)->hh.tbl = (head)->hh.tbl;                                                 \
 HASH_FCN(keyptr,keylen_in, (head)->hh.tbl->num_buckets,                         \
         (add)->hh.hashv, _ha_bkt);                                              \
 HASH_ADD_TO_BKT((head)->hh.tbl->buckets[_ha_bkt],&(add)->hh);                   \
 HASH_BLOOM_ADD((head)->hh.tbl,(add)->hh.hashv);                                 \
 HASH_EMIT_KEY(hh,head,keyptr,keylen_in);                                        \
 HASH_FSCK(hh,head);                                                             \
} while(0)        

```

### `HASH_FIND_IN_BKT` 函数

- `HASH_FIND_IN_BKT` 用于根据 `keyptr` 在 `head` 哈希桶中寻找 `UT_hash_handle`
- `DECLTYPE_ASSIGN` 用于转化 `out` 为用户自定义的数据类型（也就是 `swHashMap_node`） 
- 不断循环 `hh_next`、`hh_pre` 组成的双向链表，找出与 `keyptr` 相同的元素


```
#define HASH_KEYCMP(a,b,len) memcmp(a,b,len) 

#define DECLTYPE(x) (__typeof(x))
#endif

#define DECLTYPE_ASSIGN(dst,src)                                                 \
do {                                                                             \
  (dst) = DECLTYPE(dst)(src);                                                    \
} while(0)
#endif

#define HASH_FIND_IN_BKT(tbl,hh,head,keyptr,keylen_in,out)                       \
do {                                                                             \
 if (head.hh_head) DECLTYPE_ASSIGN(out,ELMT_FROM_HH(tbl,head.hh_head));          \
 else out=NULL;                                                                  \
 while (out) {                                                                   \
    if ((out)->hh.keylen == keylen_in) {                                           \
        if ((HASH_KEYCMP((out)->hh.key,keyptr,keylen_in)) == 0) break;             \
    }                                                                            \
    if ((out)->hh.hh_next) DECLTYPE_ASSIGN(out,ELMT_FROM_HH(tbl,(out)->hh.hh_next)); \
    else out = NULL;                                                             \
 }                                                                               \
} while(0)

```

### `HASH_FIND_INT` 函数

- `HASH_FIND_INT` 函数是上一个函数的特殊化，专门查找 `int` 类型的键值
- `HASH_FCN` 实际上是 `Jenkins` 哈希算法，用于计算哈希值
- `HASH_BLOOM_TEST` 用于快速判断哈希桶内到底有没有元素，如果没有那么没有必要进行下去

```
#define HASH_FIND_INT(head,findint,out)                                          \
    HASH_FIND(hh,head,findint,sizeof(int),out)
    
#define HASH_FCN HASH_JEN
#endif

#define HASH_BLOOM_BITTEST(bv,idx) (bv[(idx)/8] & (1U << ((idx)%8)))

#define HASH_BLOOM_TEST(tbl,hashv)                                               \
  HASH_BLOOM_BITTEST((tbl)->bloom_bv, (hashv & (uint32_t)((1ULL << (tbl)->bloom_nbits) - 1)))
    
#define HASH_FIND(hh,head,keyptr,keylen,out)                                     \
do {                                                                             \
  unsigned _hf_bkt,_hf_hashv;                                                    \
  out=NULL;                                                                      \
  if (head) {                                                                    \
     HASH_FCN(keyptr,keylen, (head)->hh.tbl->num_buckets, _hf_hashv, _hf_bkt);   \
     if (HASH_BLOOM_TEST((head)->hh.tbl, _hf_hashv)) {                           \
       HASH_FIND_IN_BKT((head)->hh.tbl, hh, (head)->hh.tbl->buckets[ _hf_bkt ],  \
                        keyptr,keylen,out);                                      \
     }                                                                           \
  }                                                                              \
} while (0)


```

### `HASH_COUNT` 函数

- `HASH_COUNT` 函数用于计算所有元素的数量

```
#define HASH_COUNT(head) HASH_CNT(hh,head) 
#define HASH_CNT(hh,head) ((head)?((head)->hh.tbl->num_items):0)

```

### `HASH_DEL_IN_BKT` 函数

- `HASH_DEL_IN_BKT` 函数用于删除已知的哈希桶的某一个链表元素

```
#define HASH_DEL_IN_BKT(hh,head,hh_del)                                          \
    (head).count--;                                                              \
    if ((head).hh_head == hh_del) {                                              \
      (head).hh_head = hh_del->hh_next;                                          \
    }                                                                            \
    if (hh_del->hh_prev) {                                                       \
        hh_del->hh_prev->hh_next = hh_del->hh_next;                              \
    }                                                                            \
    if (hh_del->hh_next) {                                                       \
        hh_del->hh_next->hh_prev = hh_del->hh_prev;                              \
    }   

```

### `HASH_DEL` 函数

- `HASH_DEL` 函数也是删除哈希表中的元素，但是不同于上一个小节 `HASH_DEL_IN_BKT` 函数，这个函数不需要知道元素落在了哪个哈希桶中
- `HASH_DEL` 函数如果发现当前要删除的是哈希表唯一的元素，这个函数还好进一步删除整个哈希表，这一特性与 `HASH_ADD` 对应
- `HASH_DEL` 函数不仅更新了哈希桶的链表结构，还更新了 `UT_hash_handle` 双向链表结构和 `UT_hash_table` 的 `tail` 成员变量
- `HASH_DEL` 函数最后利用了 `HASH_DEL_IN_BKT` 函数更新哈希桶的链表数据

```
#define HASH_DEL(head,delptr)                                                    \
    HASH_DELETE(hh,head,delptr)
    
#define HASH_DELETE(hh,head,delptr)                                              \
do {                                                                             \
    unsigned _hd_bkt;                                                            \
    struct UT_hash_handle *_hd_hh_del;                                           \
    if ( ((delptr)->hh.prev == NULL) && ((delptr)->hh.next == NULL) )  {         \
        uthash_free((head)->hh.tbl->buckets,                                     \
                    (head)->hh.tbl->num_buckets*sizeof(struct UT_hash_bucket) ); \
        HASH_BLOOM_FREE((head)->hh.tbl);                                         \
        uthash_free((head)->hh.tbl, sizeof(UT_hash_table));                      \
        head = NULL;                                                             \
    } else {                                                                     \
        _hd_hh_del = &((delptr)->hh);                                            \
        if ((delptr) == ELMT_FROM_HH((head)->hh.tbl,(head)->hh.tbl->tail)) {     \
            (head)->hh.tbl->tail =                                               \
                (UT_hash_handle*)((ptrdiff_t)((delptr)->hh.prev) +               \
                (head)->hh.tbl->hho);                                            \
        }                                                                        \
        if ((delptr)->hh.prev) {                                                 \
            ((UT_hash_handle*)((ptrdiff_t)((delptr)->hh.prev) +                  \
                    (head)->hh.tbl->hho))->next = (delptr)->hh.next;             \
        } else {                                                                 \
            DECLTYPE_ASSIGN(head,(delptr)->hh.next);                             \
        }                                                                        \
        if (_hd_hh_del->next) {                                                  \
            ((UT_hash_handle*)((ptrdiff_t)_hd_hh_del->next +                     \
                    (head)->hh.tbl->hho))->prev =                                \
                    _hd_hh_del->prev;                                            \
        }                                                                        \
        HASH_TO_BKT( _hd_hh_del->hashv, (head)->hh.tbl->num_buckets, _hd_bkt);   \
        HASH_DEL_IN_BKT(hh,(head)->hh.tbl->buckets[_hd_bkt], _hd_hh_del);        \
        (head)->hh.tbl->num_items--;                                             \
    }                                                                            \
    HASH_FSCK(hh,head);                                                          \
} while (0)

```

### `HASH_ITER` 函数

- `HASH_ITER` 函数用于循环所有的哈希表的元素

```
#define HASH_ITER(hh,head,el,tmp)                                                \
for((el)=(head),(tmp)=DECLTYPE(el)((head)?(head)->hh.next:NULL);                 \
   el; (el)=(tmp),(tmp)=DECLTYPE(el)((tmp)?(tmp)->hh.next:NULL))
#endif

```


## 哈希算法

- `swoole_hash_php` 算法

```
static inline uint64_t swoole_hash_php(char *key, uint32_t len)
{
    register ulong_t hash = 5381;
    /* variant with the hash unrolled eight times */
    for (; len >= 8; len -= 8)
    {
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
        hash = ((hash << 5) + hash) + *key++;
    }

    switch (len)
    {
        case 7: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 6: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 5: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 4: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 3: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 2: hash = ((hash << 5) + hash) + *key++; /* fallthrough... */
        /* no break */
        case 1: hash = ((hash << 5) + hash) + *key++; break;
        case 0: break;
        default: break;
    }
    return hash;
}
```

- `swoole_hash_austin` 算法

```
static inline uint32_t swoole_hash_austin(char *key, unsigned int keylen)
{
    unsigned int h, k;
    h = 0 ^ keylen;

    while (keylen >= 4)
    {
        k  = key[0];
        k |= key[1] << 8;
        k |= key[2] << 16;
        k |= key[3] << 24;

        k *= 0x5bd1e995;
        k ^= k >> 24;
        k *= 0x5bd1e995;

        h *= 0x5bd1e995;
        h ^= k;

        key += 4;
        keylen -= 4;
    }

    switch (keylen)
    {
    case 3:
        h ^= key[2] << 16;
        /* no break */
    case 2:
        h ^= key[1] << 8;
        /* no break */
    case 1:
        h ^= key[0];
        h *= 0x5bd1e995;
    }

    h ^= h >> 13;
    h *= 0x5bd1e995;
    h ^= h >> 15;

    return h;
}
``` 