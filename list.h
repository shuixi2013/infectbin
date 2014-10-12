#ifndef LIST_H
#define LIST_H


typedef struct ListElmt_{
	void 		 *data;
	struct ListElmt_ *next;

}ListElmt;

typedef struct List_{
	int size;
	int (*destroy)(void *data);
	ListElmt *head;
}List;

#define foreach(list, element) \
	for(element = list->head; element != NULL; element = element->next)

void list_init(List *list, void (*destroy)(void *data));
void list_destroy(List *list);
int  list_ins(List *list, const void *data);
int  list_rem(List *list);

#endif
