# Swoole 源码分析——基础模块之 Heap 堆

## 前言

`heap` 堆是 `swoole` 实现定时器最重要的数据结构，定时器将各个定时任务按照其下一次执行的时间构建最小堆，快速进行插入与删除。

## `heap` 数据结构

`heap` 中 `num` 是现有数据堆的数量，`size` 是数据堆的大小，`type` 用于确定数据堆是最大堆还是最小堆，`nodes` 是数据堆的节点。`swHeap_node` 中 `priority` 是数据堆的权重，也是数据堆排序的依据，`position` 是其在数据堆中的位置。

```c
typedef struct swHeap_node
{
    uint64_t priority;
    uint32_t position;
    void *data;
} swHeap_node;

typedef struct _swHeap
{
    uint32_t num;
    uint32_t size;
    uint8_t type;
    swHeap_node **nodes;
} swHeap;

```

![](http://owql68l6p.bkt.clouddn.com/WX20180911-211701@2x.png)


## `heap` 数据堆


### `swHeap_new` 创建数据堆

创建一个数据堆就是初始化 `swHeap` 的各个属性。

```c
swHeap *swHeap_new(size_t n, uint8_t type)
{
    swHeap *heap = sw_malloc(sizeof(swHeap));
    if (!heap)
    {
        return NULL;
    }
    if (!(heap->nodes = sw_malloc((n + 1) * sizeof(void *))))
    {
        sw_free(heap);
        return NULL;
    }
    heap->num = 1;
    heap->size = (n + 1);
    heap->type = type;
    return heap;
}

```


### `swHeap_push` 数据入堆

数据入堆首先要检查 `heap` 的 `size` 是否已经足够，如果不够那么需要扩容。

`swHeap_bubble_up` 函数负责将数据节点提升到数据堆中相应的位置。方法很简单，新的数据节点不断的和父节点进行对比，符合条件就进行替换，不符合条件就停止，结束。

```c
swHeap_node* swHeap_push(swHeap *heap, uint64_t priority, void *data)
{
    void *tmp;
    uint32_t i;
    uint32_t newsize;

    if (heap->num >= heap->size)
    {
        newsize = heap->size * 2;
        if (!(tmp = sw_realloc(heap->nodes, sizeof(void *) * newsize)))
        {
            return NULL;
        }
        heap->nodes = tmp;
        heap->size = newsize;
    }

    swHeap_node *node = sw_malloc(sizeof(swHeap_node));
    if (!node)
    {
        return NULL;
    }
    node->priority = priority;
    node->data = data;
    i = heap->num++;
    heap->nodes[i] = node;
    swHeap_bubble_up(heap, i);
    return node;
}

#define left(i)   ((i) << 1)
#define right(i)  (((i) << 1) + 1)
#define parent(i) ((i) >> 1)

static void swHeap_bubble_up(swHeap *heap, uint32_t i)
{
    swHeap_node *moving_node = heap->nodes[i];
    uint32_t parent_i;

    for (parent_i = parent(i);
            (i > 1) && swHeap_compare(heap->type, heap->nodes[parent_i]->priority, moving_node->priority);
            i = parent_i, parent_i = parent(i))
    {
        heap->nodes[i] = heap->nodes[parent_i];
        heap->nodes[i]->position = i;
    }

    heap->nodes[i] = moving_node;
    moving_node->position = i;
}

static sw_inline int swHeap_compare(uint8_t type, uint64_t a, uint64_t b)
{
    if (type == SW_MIN_HEAP)
    {
        return a > b;
    }
    else
    {
        return a < b;
    }
}
```


### `swHeap_change_priority` 改变数据的权重

改变了数据节点的权重之后，需要重新进行堆排序，将数据节点向上提升，或者将数据向下调整。向下调整方法也很简单，不断的和两个子节点进行比较，调整该数据节点和子节点的顺序。


```c
void swHeap_change_priority(swHeap *heap, uint64_t new_priority, void* ptr)
{
    swHeap_node *node = ptr;
    uint32_t pos = node->position;
    uint64_t old_pri = node->priority;

    node->priority = new_priority;
    if (swHeap_compare(heap->type, old_pri, new_priority))
    {
        swHeap_bubble_up(heap, pos);
    }
    else
    {
        swHeap_percolate_down(heap, pos);
    }
}

static void swHeap_percolate_down(swHeap *heap, uint32_t i)
{
    uint32_t child_i;
    swHeap_node *moving_node = heap->nodes[i];

    while ((child_i = swHeap_maxchild(heap, i))
            && swHeap_compare(heap->type, moving_node->priority, heap->nodes[child_i]->priority))
    {
        heap->nodes[i] = heap->nodes[child_i];
        heap->nodes[i]->position = i;
        i = child_i;
    }

    heap->nodes[i] = moving_node;
    moving_node->position = i;
}

static uint32_t swHeap_maxchild(swHeap *heap, uint32_t i)
{
    uint32_t child_i = left(i);
    if (child_i >= heap->num)
    {
        return 0;
    }
    swHeap_node * child_node = heap->nodes[child_i];
    if ((child_i + 1) < heap->num && swHeap_compare(heap->type, child_node->priority, heap->nodes[child_i + 1]->priority))
    {
        child_i++;
    }
    return child_i;
}
```


### `swHeap_pop` 弹出堆顶元素

弹出堆顶元素后，需要重新调整整个数据堆。方法是将尾部元素和堆顶元素进行交换，然后再对堆顶元素进行排序。

```c
void *swHeap_pop(swHeap *heap)
{
    swHeap_node *head;
    if (!heap || heap->num == 1)
    {
        return NULL;
    }

    head = heap->nodes[1];
    heap->nodes[1] = heap->nodes[--heap->num];
    swHeap_percolate_down(heap, 1);

    void *data = head->data;
    sw_free(head);
    return data;
}


```

### `swHeap_remove` 删除元素

删除堆节点元素和弹出堆顶元素类似，都是先将该元素和尾部元素进行替换，然后再对其进行排序。由于尾部元素不一定比待删除的元素权重高，因此需要先判断其权重，再决定是提升还是降低。


```c
int swHeap_remove(swHeap *heap, swHeap_node *node)
{
    uint32_t pos = node->position;
    heap->nodes[pos] = heap->nodes[--heap->num];

    if (swHeap_compare(heap->type, node->priority, heap->nodes[pos]->priority))
    {
        swHeap_bubble_up(heap, pos);
    }
    else
    {
        swHeap_percolate_down(heap, pos);
    }
    return SW_OK;
}
```