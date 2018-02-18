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
 * @file dlinkedlist.c
 * @brief The source file for my own doubly linked list data structure
 * and the definition for the utility operation functions
 *
 * @author Shuting Guo
 * @date 01/30/2018
 * @version 1.0
 *
 */

#include "dlinkedlist.h"

/*
 * @name dll_destroy
 * @brief destroy a double linked list
 * destroy all the nodes in the linked list by freeing the memory
 *
 * @param a pointer to the linked list structure
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_destroy(dll_t ** head)
{
  // Check if the linked list is empty
  if(*head == NULL)
    return *head;

  dll_node_t *temp_node = &(*head)->node;

  // Destroy all the nodes one by one
  while(temp_node->next != NULL)
  {
    temp_node = temp_node->next;
    free(GET_LIST_CONTAINER(temp_node->prev, dll_t, node));
  }
  free(GET_LIST_CONTAINER(temp_node, dll_t, node));
  *head = NULL;
  return *head;
}

/*
 * @name dll_insert_at_beginning
 * @brief Insert a node to the beginning of the linked list
 * should add head node if it does not exist.
 *
 * @param a pointer to the linked list head node
 * @param data to axdd
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_insert_at_beginning(dll_t ** head, uint32_t data)
{
  // Allocate memory for the list struct
  dll_t *ptr = (dll_t *)malloc(sizeof(dll_t));
  // Assign value
  ptr->data = data;
  // The previous node of a head node is always NULL
  ptr->node.prev = NULL;
  // If the list was empty, the next of the head node is NULL
  if(*head==NULL)
    ptr->node.next = NULL;
  // otherwise, the next points to the original head node, and the prev of the original head node points back to the new head node.
  else
  {
    ptr->node.next = &(*head)->node;
    (*head)->node.prev = &ptr->node;
  }
  *head = ptr;
  return *head;
}

/*
 * @name dll_insert_at_end
 * @brief Insert a node to the end of the linked list
 * should add head node if it does not exist.
 *
 * @param a pointer to the linked list head node
 * @param data to add
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_insert_at_end(dll_t ** head, uint32_t data)
{
  // Allocate memory for the list struct
  dll_t * ptr = (dll_t *)malloc(sizeof(dll_t));
  // Assign value
  ptr->data = data;
  // The next node of the last node is always NULL
  ptr->node.next = NULL;
  // If the list was empty, the prev of the last node is NULL
  if(*head == NULL)
  {
    ptr->node.prev = NULL;
    *head = ptr;
  }
  // Otherwise, the prev points to the orinal last node of the list, and the next of the original last node points to the new last node
  else
  {
    dll_node_t * last_node = &(*head)->node;
    while(last_node->next != NULL)
    {
      last_node = last_node->next;
    }
    ptr->node.prev = last_node;
    last_node->next = &ptr->node;
  }
  return *head;
}

/*
 * @name dll_insert_at_position
 * @brief Insert a node to a given position of the linked list
 *
 * @param a pointer to the linked list head node
 * @param data to add
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_insert_at_position(dll_t ** head, uint32_t data, uint32_t pos)
{
  // Allocate memory for the list struct
  dll_t * ptr = (dll_t*)malloc(sizeof(dll_t));
  // Assign value
  ptr->data = data;
  // If the head is NULL, only insert the struct when pos is equal to 0, Otherwise, it does nothing.
  if(*head == NULL)
  {
    if(pos == 0)
    {
      ptr->node.prev = NULL;
      ptr->node.next = NULL;
      *head = ptr;
    }
    else
      free(ptr);
    return *head;
  }
  // Insert at pos 0, or the beginning
  if(pos == 0)
  {
    ptr->node.prev = NULL;
    ptr->node.next = &(*head)->node;
    (*head)->node.prev = &ptr->node;
    (*head) = ptr;
    return *head;
  }
  dll_node_t * temp_node = &(*head)->node;
  pos--;
  while((temp_node->next != NULL) && (pos > 0))
  {
    temp_node = temp_node->next;
    pos--;
  }
  // Insert at a middle position of the list
  if((pos == 0) && (temp_node->next != NULL))
  {
    ptr->node.next = temp_node->next;
    temp_node->next->prev = &ptr->node;
    ptr->node.prev = temp_node;
    temp_node->next = &ptr->node;
  }
  // Insert at the end of the list
  else if((pos == 0) && (temp_node->next == NULL))
  {
    temp_node->next = &ptr->node;
    ptr->node.prev = temp_node;
    ptr->node.next = NULL;
  }
  // Insert position out of range, do nothing
  else
    free(ptr);
  return *head;
}

/*
 * @name dll_delete_from_beginning
 * @brief delete a node from the beginning of the linked list
 *
 * @param a pointer to the linked list head node
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_delete_from_beginning(dll_t ** head)
{
  // Check for NULL
  if(*head == NULL)
    return *head;
  // If there is only one node in the list
  if((*head)->node.next == NULL)
  {
    free(*head);
    *head = NULL;
    return *head;
  }
  // Move head to the next struct in the list
  (*head) = GET_LIST_CONTAINER((*head)->node.next, dll_t, node);
  // Free the orginal head struct
  free(GET_LIST_CONTAINER((*head)->node.prev, dll_t, node));
  // Set the prev of the new head node to be NULL
  (*head)->node.prev = NULL;
  return *head;
}

/*
 * @name dll_delete_from_end
 * @brief delete a node from the end of the linked list
 *
 * @param a pointer to the linked list head node
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_delete_from_end(dll_t ** head)
{
  // Check for NULL
  if(*head == NULL)
    return *head;
  // If there is only one node
  if((*head)->node.next == NULL)
  {
    free(*head);
    *head = NULL;
    return *head;
  }
  // If there is more than one node, find the last node of the list
  dll_node_t * last_node = &(*head)->node;
  while(last_node->next != NULL)
  {
    last_node = last_node->next;
  }
  // Set the next of the node before the last node to be NULL
  last_node->prev->next = NULL;
  // Free the original last struct
  free(GET_LIST_CONTAINER(last_node, dll_t, node));
  return *head;
}

/*
 * @name dll_delete_from_position
 * @brief delete a node from a given position of the linked list
 *
 * @param a pointer to the linked list head node
 * @return a pointer to the head of the linked list
 *
 */
dll_t * dll_delete_from_position(dll_t ** head, uint32_t pos)
{
  // Check for NULL
  if(*head == NULL)
    return *head;
  // If there is only one node in the list
  if((*head)->node.next == NULL)
  {
    // Delete the struct only when pos is equal to 0, or do nothing
    if(pos == 0)
    {
      free(*head);
      *head = NULL;
    }
    return *head;
  }
  // If pos is equal to 0, so to delete the head node
  if(pos == 0)
  {
    (*head) = GET_LIST_CONTAINER((*head)->node.next, dll_t, node);
    free(GET_LIST_CONTAINER((*head)->node.prev, dll_t, node));
    (*head)->node.prev = NULL;
    return *head;
  }
  dll_node_t * temp_node = &(*head)->node;
  while((temp_node->next != NULL) && (pos > 0))
  {
    temp_node = temp_node->next;
    pos--;
  }
  // Delete a middle position of the list
  if((pos == 0) && (temp_node->next != NULL))
  {
    temp_node->prev->next = temp_node->next;
    temp_node->next->prev = temp_node->prev;
    free(GET_LIST_CONTAINER(temp_node, dll_t, node));
  }
  // Delete the end of the list
  else if((pos == 0) && (temp_node->next == NULL))
  {
    temp_node->prev->next = NULL;
    free(GET_LIST_CONTAINER(temp_node, dll_t, node));
  }
  // Delete position out of range, do nothing
  else
    ;
  return *head;
}

/*
 * @name dll_size
 * @brief determine the number of links in the linked list
 *
 * @param a pointer to the linked list head node
 * @return size of the linked list
 *
 */
size_t dll_size(dll_t ** head)
{
  // Check for NULL
  if(*head == NULL)
    return 0;
  size_t num = 1;
  dll_node_t * temp_node = &(*head)->node;
  while(temp_node->next != NULL)
  {
    temp_node = temp_node->next;
    num++;
  }
  return num;

}
