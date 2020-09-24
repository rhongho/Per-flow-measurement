#include <stdio.h>
#include <stdlib.h>


#include "queue.h"

#define QUEUE_POISON1 ((void*)0xCAFEBAB5)



struct queue_root *ALLOC_QUEUE_ROOT()
{
	struct queue_root *root = \
		malloc(sizeof(struct queue_root));
	pthread_mutex_init(&root->head_lock, NULL);
	pthread_mutex_init(&root->tail_lock, NULL);

	root->divider.next = NULL;
	root->head = &root->divider;
	root->tail = &root->divider;
	//root->usage = 0;
	return root;
}


void INIT_QUEUE_HEAD(struct queue_head *head,uint64_t mac_s, uint64_t mac_d, uint32_t is, uint32_t id, uint8_t proto, uint16_t sp, uint16_t dp)
{
	
	head->next = QUEUE_POISON1;
	head->mac_s = mac_s;
	head->mac_d = mac_d;
	head->is = is;
	head->id = id;
	head->proto = proto;
	head->sp = sp;
	head->dp = dp;
}

void queue_put(struct queue_head *new, struct queue_root *root)
{
	new->next = NULL;

	pthread_mutex_lock(&root->tail_lock);
	root->tail->next = new;
	root->tail = new;
	pthread_mutex_unlock(&root->tail_lock);
}


struct queue_head *queue_get(struct queue_root *root)
{
	struct queue_head *head, *next;

	while (1) {
		pthread_mutex_lock(&root->head_lock);
		head = root->head;
		next = head->next;
		if (next == NULL) {
			pthread_mutex_unlock(&root->head_lock);
			return NULL;
			//printf("out: NULL\n");
		}
		root->head = next;
		pthread_mutex_unlock(&root->head_lock);

		if (head == &root->divider) {
			queue_put(head, root);
			continue;
		}
		//root->usage--;
		//printf("out: %lu\n", head->is);
		head->next = QUEUE_POISON1;
		return head;
	}
}
