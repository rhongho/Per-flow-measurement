#ifndef QUEUE_H
#define QUEUE_H
#include <stdint.h>
#include <pthread.h>



typedef struct queue_head {
	uint64_t mac_s;
	uint64_t mac_d;
	uint32_t is;
	uint32_t id;
	uint8_t proto; // Protocol(TCP,UDP etc)
	uint16_t sp; // Source port no.
	uint16_t dp; // Dest. port no.
	struct queue_head *next;
}queue_head;
typedef struct queue_root {
	struct queue_head *head;
	pthread_mutex_t head_lock;

	struct queue_head *tail;
	pthread_mutex_t tail_lock;

	struct queue_head divider;
	//uint32_t usage;
}queue_root;
struct queue_root *ALLOC_QUEUE_ROOT();
//void INIT_QUEUE_HEAD(struct queue_head *head,uint64_t hash_value);
void INIT_QUEUE_HEAD(struct queue_head *head,uint64_t mac_s, uint64_t mac_d, uint32_t is, uint32_t id, uint8_t proto, uint16_t sp, uint16_t dp);

void queue_put(struct queue_head *new, struct queue_root *root);

struct queue_head *queue_get(struct queue_root *root);


#endif // QUEUE_H
