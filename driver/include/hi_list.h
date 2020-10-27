/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: ˫������
 * Author: Hisilicon
 * Create: 2017-07-03
 */
#ifndef __HI_LIST_H__
#define __HI_LIST_H__

#include <hi_types_base.h>

/****************************************************************************/
HI_START_HEADER

/*
 * ��ע�����ļ�������ӿ�����������ʹ��LTOS�ӿ�����ʵ�֡�
 */
typedef struct hi_list {
    struct hi_list *prev;
    struct hi_list *next;
} hi_list;

/*
����������
    ��ʼ��ͷ�ڵ㣬ע��˽ڵ�����ڹ��������û���������ݽڵ�
 */
static inline hi_void hi_list_init(hi_list *list)
{
    list->next = list;
    list->prev = list;
}

/*
����������
    ��node����Ϊlist�ĵ�һ���ڵ�
 */
static inline hi_void hi_list_head_insert(hi_list *node, hi_list *list)
{
    node->next = list->next;
    node->prev = list;
    list->next->prev = node;
    list->next = node;
}

/*
����������
    ��node����Ϊlist�ĵ�һ���ڵ�
 */
__attribute__((always_inline)) static inline hi_void hi_list_head_insert_optimize(hi_list *node, hi_list *list)
{
    node->next = list->next;
    node->prev = list;
    list->next->prev = node;
    list->next = node;
}

/*
����������
    ��node����Ϊlist�����һ���ڵ�
 */
static inline hi_void hi_list_tail_insert(hi_list *node, hi_list *list)
{
    hi_list_head_insert(node, list->prev);
}

/*
����������
    ��node����Ϊlist�����һ���ڵ�
 */
__attribute__((always_inline)) static inline hi_void hi_list_tail_insert_optimize(hi_list *node, hi_list *list)
{
    hi_list_head_insert_optimize(node, list->prev);
}

/*
����������
    ��������ɾ��ĳ���ڵ�
 */
static inline hi_void hi_list_delete(hi_list *node)
{
    if (node->next == HI_NULL || node->prev == HI_NULL) {
        return;
    }

    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->next = (hi_list *)HI_NULL;
    node->prev = (hi_list *)HI_NULL;
}

/*
����������
    ��������ɾ��ĳ���ڵ�
 */
__attribute__((always_inline)) static inline hi_void hi_list_delete_optimize(hi_list *node)
{
    if (node->next == HI_NULL || node->prev == HI_NULL) {
        return;
    }

    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->next = (hi_list *)HI_NULL;
    node->prev = (hi_list *)HI_NULL;
}

/*
����������
    ɾ������ĵ�һ���ڵ㣬���ͷ�����ڴ�
 */
static inline hi_list *hi_list_delete_head(hi_list *list)
{
    hi_list *del_node;

    del_node = list->next;
    if (del_node == list || del_node == HI_NULL) {
        return HI_NULL;
    }

    hi_list_delete(del_node);
    return del_node;
}

/*
����������
    ɾ������ĵ�һ���ڵ㣬���ͷ�����ڴ�
 */
__attribute__((always_inline)) static inline hi_list *hi_list_delete_head_optimize(hi_list *list)
{
    hi_list *del_node;

    del_node = list->next;
    if (del_node == list || del_node == HI_NULL) {
        return HI_NULL;
    }

    hi_list_delete_optimize(del_node);
    return del_node;
}

/*
����������
    ɾ������β���ڵ㣬���ͷ�����ڴ�
 */
static inline hi_list *hi_list_delete_tail(hi_list *list)
{
    hi_list *del_node;

    del_node = list->prev;
    if (del_node == list || del_node == HI_NULL) {
        return HI_NULL;
    }

    hi_list_delete(del_node);
    return del_node;
}

/*
����������
    �ж������Ƿ�Ϊ��
 */
static inline hi_bool hi_is_list_empty(hi_list *list)
{
    if (list->next == HI_NULL || list->prev == HI_NULL) {
        return HI_TRUE;
    }
    return (hi_bool)(list->next == list);
}

__attribute__((always_inline)) static inline hi_bool hi_is_list_empty_optimize(hi_list *list)
{
    if (list->next == HI_NULL || list->prev == HI_NULL) {
        return HI_TRUE;
    }
    return (hi_bool)(list->next == list);
}


/*
����������
    ȥ��ʼ����������ڵ���գ�������Ա�ڵ���β������Ȼ��һ��˫������
 */
static inline hi_void hi_list_del_init(hi_list *list)
{
    list->next->prev = list->prev;
    list->prev->next = list->next;

    list->next = list;
    list->prev = list;
}

/*
����������
    ������2��������1��β��
 */
static inline hi_void hi_list_join_tail(hi_list *list1, hi_list *list2)
{
    list1->prev->next = list2->next;
    list2->next->prev = list1->prev;
    list2->prev->next = list1;
    list1->prev = list2->prev;
}

/*
����������
    ������2��������1��ͷ��
 */
static inline hi_void hi_list_join_head(hi_list *list1, hi_list *list2)
{
    /* list2 is empty. */
    if (list2->next == list2) {
        return;
    }

    list2->prev->next = list1->next;
    list1->next->prev = list2->prev;
    list1->next = list2->next;
    list2->next->prev = list1;
}

/*
 * ����������
    ������2�дӵ�һ��Ԫ�ص�last_nodeԪ��ժ���� ���������1��ͷ��
 */
static inline hi_void hi_list_remove_head(hi_list *list1, hi_list *list2, hi_list *last_node)
{
    /* ��list1��ֵ */
    list1->next = list2->next;
    list1->prev = last_node;

    list2->next = last_node->next;
    ((hi_list *)(last_node->next))->prev = list2;

    last_node->next = list1;
    /* last_nodeΪlist2�е�һ����Ա */
    if (last_node->prev == list2) {
        last_node->prev = list1;
    }
}

#define hi_list_init_macro(_list_name) hi_list _list_name = { (hi_list*)&(_list_name), (hi_list*)&(_list_name) }

/* ��ȡ��һ���ڵ�ָ�� */
#define hi_list_first(object) ((object)->next)

/* ��ȡ���һ���ڵ�ָ�� */
#define hi_list_last(object) ((object)->prev)

/*
 * ����������
    ��ȡ��һ������˫����Ľṹ���ָ���ַ��
 */
#define hi_list_entry(item, type, member) \
    ((type*)((char*)(item) - hi_offset_of_member(type, member)))

/*
 * �����б�
    ͨ��LIST����ÿһ����Ա�ڵ����ڽṹ���ָ����ڵ�ַ��
 */
#define hi_list_for_each_entry(item, list, type, member)   \
    for ((item) = hi_list_entry((list)->next, type, member); \
         &(item)->member != (list);                          \
         (item) = hi_list_entry((item)->member.next, type, member))

/*
 * �����б�
    ͨ��LIST����ÿһ����Ա�ڵ����ڽṹ���ָ����ڵ�ַ��������һ���ڵ��ָ�룬���⵱ǰ�ڵ㴦����ɺ�ɾ���ĳ�����
 */
#define hi_list_for_each_entry_safe(list, item, pnext, type, member) \
    for ((item) = hi_list_entry((list)->next, type, member),           \
         (pnext) = hi_list_entry((item)->member.next, type, member);     \
         &(item)->member != (list);                                    \
         (item) = (pnext), (pnext) = hi_list_entry((item)->member.next, type, member))

#define hi_list_for_each_entry_continue_safe(pitem, list, item, pnext, type, member) \
    for ((item) = hi_list_entry((pitem)->next, type, member),                          \
         (pnext) = hi_list_entry((item)->member.next, type, member);                     \
         &((item)->member) != (list);                                                \
         (item) = (pnext), (pnext) = hi_list_entry((pnext)->member.next, type, member))

/* ˫�����������ʵ�� */
#define hi_list_head(list) \
    hi_list list = { &(list), &(list) }

#define hi_list_for_each(item, list) \
    for ((item) = (list)->next; (item) != (list); (item) = (item)->next)

#define hi_list_for_each_safe(item, pnext, list)                  \
    for ((item) = (list)->next, (pnext) = (item)->next; (item) != (list); (item) = (pnext), (pnext) = (item)->next)

HI_END_HEADER
#endif  /* __HI_STDLIB_H__ */
