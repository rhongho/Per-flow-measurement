#include <stdint.h>

typedef struct{
	uint64_t src_mac;
	uint64_t dst_mac;
	uint32_t src_IP;
	uint32_t dst_IP;
	uint8_t Proto;
	uint16_t src_Port;
	uint16_t dst_Port;
	double HH; //Heavy Hitter
	uint32_t action_HH;
	uint32_t SS; //Super Spreader
	uint32_t action_SS;
} Rule_Entry;

typedef struct {
	uint32_t size;
	uint32_t usage;
	Rule_Entry** rule_table;
} Rule_Table;



/* Create a new hashtable. */
Rule_Table* rt_create(uint32_t size);

/* Create a hash_value-value pair. */
Rule_Entry* new_rule();

///* Insert a hash_value-value pair into a hash table. */
void Rule_Insert(Rule_Table *ruletable, uint64_t src_mac, uint64_t dst_mac, uint32_t src_IP, uint32_t dst_IP, uint8_t Proto, uint16_t src_Port, uint16_t dst_Port, double HH, uint32_t action_HH, uint32_t SS, uint32_t action_SS);


int Rule_Matcher(Rule_Table *ruletable, uint64_t src_mac, uint64_t dst_mac, uint32_t src_IP, uint32_t dst_IP, uint8_t Proto, uint16_t src_Port, uint16_t dst_Port, double HH, uint32_t SS);
