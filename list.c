/* 
 * 
 * list.c  - A simple implementation of linked list and some functions
 * 
 * by Joao Guilherme aka plankton__
 * 
 */

#include "list.h"
#include <stdlib.h>

void list_init(List *list, void (*destroy)(void *data)){
	list->size = 0;
	list->destroy = (void *) destroy;
	list->head = NULL;
}

void list_destroy(List *list){
	ListElmt *element;

	foreach(list, element)
		list_rem(list);

	list->destroy = NULL;
}

int  list_ins(List *list, const void *data){
	ListElmt *element;
	element = (ListElmt *) malloc(sizeof(ListElmt));

	if(element == NULL)
		return -1;

	element->data = (void*) data;
	element->next = list->head;
	list->head = element;
	list->size++;

	return 0;
}

int  list_rem(List *list){
	ListElmt *element;

	if(list->size == 0)
		return -1;

	element = list->head->next;
	list->destroy(list->head);
	list->head = element;
	list->size--;

	return 0;
}

