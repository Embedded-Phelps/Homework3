/*****************************************************************************
 * Copyright (C) 2018 by Shuting Guo
 *
 * Redistribution, modification or use of this software in source or binary
 * forms is permitted as long as the files maintain this copyright. Users are
 * permitted to modify this and use it to learn about the field of embedded
 * software. Shuting Guo is not liable for any misuse of this material.
 *
*****************************************************************************/
/**
 * @file dlinkedlist.h
 * @brief The header file for my own doubly linked list data structure
 * and the prototypes for the utility operation functions
 *
 * @author Shuting Guo
 * @date 01/30/2018
 * @version 1
 *
 */

#ifndef __DLINKEDLIST_H__
#define __DLINKEDLIST_H__

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>

#define GET_LIST_CONTAINER(ptr, type, member) ({                      \
                const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
                (type *)( (char *)__mptr - offsetof(type,member) );})
/* Doubly link list structures */

typedef struct node
{
  struct node * prev;
  struct node * next;
}dll_node_t;

typedef struct dll_info
{
  uint32_t data;
  dll_node_t node;
}dll_t;

/* Utility functions prototypes for doubly link list operations */

/*
 * @name dll_destroy
 * @brief destroy a double linked list
 * destroy all the nodes in the linked list by freeing the memory
 *
 * @param a pointer to the linked list structure
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_destroy(dll_t ** head);

/*
 * @name dll_insert_at_beginning
 * @brief Insert a node to the beginning of the linked list
 * should add head node if it does not exist.
 *
 * @param a pointer to the linked list head node
 * @param pointer to the data to add
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_insert_at_beginning(dll_t ** head, uint32_t data);

/*
 * @name dll_insert_at_end
 * @brief Insert a node to the end of the linked list
 * should add head node if it does not exist.
 *
 * @param a pointer to the linked list head node
 * @param the data type
 * @param pointer to the data to add
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_insert_at_end(dll_t ** head, uint32_t data);

/*
 * @name dll_insert_at_position
 * @brief Insert a node to a given position of the linked list
 *
 * @param a pointer to the linked list head node
 * @param the data type
 * @param data to add
 * @param position to insert the data
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_insert_at_position(dll_t ** head, uint32_t data, uint32_t pos);

/*
 * @name dll_delete_from_beginning
 * @brief delete a node from the beginning of the linked list
 *
 * @param a pointer to the linked list head node
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_delete_from_beginning(dll_t ** head);

/*
 * @name dll_delete_from_end
 * @brief delete a node from the end of the linked list
 *
 * @param a pointer to the linked list head node
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_delete_from_end(dll_t ** head);

/*
 * @name dll_delete_from_position
 * @brief delete a node from a given position of the linked list
 *
 * @param a pointer to the linked list head node
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_delete_from_position(dll_t ** head, uint32_t pos);

/*
 * @name dll_size
 * @brief determine the number of links in the linked list
 *
 * @param a pointer to the linked list head node
 * @return size of the linked list
 *
 */
size_t dll_size(dll_t ** head);

#endif /* __DLINKEDLIST_H__ */
