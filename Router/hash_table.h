#include <stdint.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef  struct{
	uint32_t hash_value;
	uint32_t is;
	uint32_t id;
	uint8_t proto;
	uint16_t sp;
	uint16_t dp;
	uint32_t counter;	// 32? 64?
	double est;
} entry_L4;

typedef struct{
	uint32_t hash_value;
	uint32_t is;
	uint32_t id;
	uint32_t counter;	// 32? 64?
	double est;
} entry_L3;

typedef  struct{
	uint32_t hash_value;
	uint64_t mac_s;
	uint64_t mac_d;
	uint32_t counter;	// 32? 64?
	double est;
} entry_L2;


typedef struct {
	uint32_t usage;
	uint32_t size;
	entry_L2** htable;
} Local_Flow_Record_Table_L2;


typedef struct {
	uint32_t usage;
	uint32_t size;
	entry_L3** htable;
} Local_Flow_Record_Table_L3;


typedef struct{
	uint32_t usage;
	uint32_t size;
	entry_L4** htable;
} Local_Flow_Record_Table_L4;

/* Create a new hashtable. */
Local_Flow_Record_Table_L2* ht_create_L2(uint32_t size);

/* Create a hash_value-value pair. */
entry_L2* ht_newpair_L2();

///* Insert a hash_value-value pair into a hash table. */
uint32_t ht_insert_L2(Local_Flow_Record_Table_L2 *hashtable, uint32_t hash_value,  uint64_t mac_s, uint64_t mac_d, double est);


/* Create a new hashtable. */
Local_Flow_Record_Table_L3* ht_create_L3(uint32_t size);

/* Create a hash_value-value pair. */
entry_L3* ht_newpair_L3();

///* Insert a hash_value-value pair into a hash table. */
uint32_t ht_insert_L3(Local_Flow_Record_Table_L3 *hashtable, uint32_t hash_value,  uint32_t is, uint32_t id, double est);



/* Create a new hashtable. */
Local_Flow_Record_Table_L4* ht_create_L4(uint32_t size);

/* Create a hash_value-value pair. */
entry_L4* ht_newpair_L4();

///* Insert a hash_value-value pair into a hash table. */
uint32_t ht_insert_L4(Local_Flow_Record_Table_L4 *hashtable, uint32_t hash_value, uint32_t is, uint32_t id, uint8_t proto, uint16_t sp, uint16_t dp, double est);

int verify_L3(Local_Flow_Record_Table_L3 *hashtable, uint32_t is);

int verify_L4(Local_Flow_Record_Table_L4 *hashtable, uint32_t is, uint32_t id, uint8_t proto, uint16_t sp);
