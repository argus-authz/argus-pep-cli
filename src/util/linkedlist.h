/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _PEP_LINKEDLIST_H_
#define _PEP_LINKEDLIST_H_

#ifdef  __cplusplus
extern "C" {
#endif

#include <stddef.h> /* size_t */

/* Return code OK */
#define LLIST_OK 0
/* Return code ERROR */
#define LLIST_ERROR -1

/**
 * ADT Linked list type
 */
typedef struct pep_linkedlist pep_linkedlist_t;

/**
 * Creates an empty linked list.
 *
 * @return a pointer to the new linked list or NULL if an error occurs.
 */
pep_linkedlist_t * pep_llist_create( void );

/**
 * Returns the linked list length.
 *
 * @param linkedlist_t * list pointer to the linked list.
 *
 * @return size_t number of element in the list, @c 0 if empty or an error occurs.
 */
size_t pep_llist_length(const pep_linkedlist_t * list);

/**
 * Adds an element at the end of the linked list.
 *
 * @param linkedlist_t * list pointer to the linked list.
 * @param void * element pointer to the element to add.
 *
 * @return LLIST_OK or LLIST_ERROR if an error occurs.
 */
int pep_llist_add(pep_linkedlist_t * list, void * element);

/**
 * Returns the element at position i [0..n-1] or NULL if index i is out of range.
 *
 * @param linkedlist_t * list pointer to the linked list.
 * @param int index of the element to return.
 *
 * @return void * element pointer to the element
 *         or NULL if an error occurs (index out of range, ...)
 */
void * pep_llist_get(pep_linkedlist_t * list, int i);

/**
 * Removes the element at position i [0..n-1].
 *
 * @param linkedlist_t * list pointer to the linked list.
 * @param int index of the element to remove.
 *
 * @return void * element pointer to the removed element
 *         or NULL if an error occurs (index out of range, ...)
 */
void * pep_llist_remove(pep_linkedlist_t * list, int i);

/**
 * Deletes the linked list.
 * The element contained in the list are NOT released.
 *
 * @param linkedlist_t * list pointer to the linked list.
 *
 * @return LLIST_OK or LLIST_ERROR if an error occurs.
 */
int pep_llist_delete(pep_linkedlist_t * list);

/**
 * Applies the delete function on each element contained in the list. The
 * linked list is not released.
 *
 * @param linkedlist_t * list pointer to the linked list.
 * @param pep_llist_delete_elt_f delete function to apply to each element.
 *
 * @return LLIST_OK or LLIST_ERROR if an error occurs.
 */
typedef void (*pep_llist_delete_elt_f) (void *);
int pep_llist_delete_elements(pep_linkedlist_t * list, pep_llist_delete_elt_f deletef);

#ifdef  __cplusplus
}
#endif

#endif
