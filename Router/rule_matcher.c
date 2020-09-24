#define __STDC_FORMAT_MACROS

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "rule_matcher.h"

/* Create a new rule_table. */


Rule_Table* rt_create(uint32_t size) {
	Rule_Table *table;

	/* Allocate the table itself. */
	if ((table = (Rule_Table*)malloc(sizeof(Rule_Table))) == NULL){
		return NULL;
	}
	table->size = size;
	table->usage = 0;
	/* Allocate pointers to the head nodes. */
	if ((table->rule_table = malloc(sizeof(Rule_Entry *) * size)) == NULL){
		return NULL;
	}
	int i ;
	for (i = 0; i < size; i++) {
		table->rule_table[i] = new_rule();
	}	
	return table;
}


Rule_Entry* new_rule() {
	Rule_Entry* new_entry;
	if ((new_entry = malloc(sizeof(Rule_Entry))) == NULL) {
		return NULL;
	}
	return new_entry;
}


void Rule_Insert(Rule_Table *ruletable, uint64_t src_mac, uint64_t dst_mac, uint32_t src_IP, uint32_t dst_IP, uint8_t Proto, uint16_t src_Port, uint16_t dst_Port, double HH, uint32_t action_HH, uint32_t SS, uint32_t action_SS) {
	int usage = ruletable->usage;
	int size = ruletable->size;
	Rule_Entry* re =  ruletable -> rule_table[usage];
	if(usage < size){
		re->src_mac = src_mac;
		re->dst_mac = dst_mac;
		re->src_IP = src_IP;
		re->dst_IP = dst_IP;
		re->Proto = Proto;
		re->src_Port = src_Port;
		re->dst_Port = dst_Port;
		re->HH = HH;
		re->action_HH = action_HH;
		re->SS = SS;
		re->action_SS = action_SS;
	}
	ruletable->size += 1;
}

int Rule_Matcher(Rule_Table *ruletable, uint64_t src_mac, uint64_t dst_mac, uint32_t src_IP, uint32_t dst_IP, uint8_t Proto, uint16_t src_Port, uint16_t dst_Port, double HH, uint32_t SS){
	int usage = ruletable->usage;
	int i;
	for (i=0; i < usage; i++){
		Rule_Entry* re = ruletable -> rule_table[i];
		int result = (re->src_mac>0? (re->src_mac ^ src_mac) : 0)+
				(re->dst_mac>0? (re->dst_mac ^ dst_mac) : 0)+
				(re->src_IP>0? (re->src_IP ^ src_IP) : 0)+
				(re->dst_IP>0? (re->dst_IP ^ dst_IP) : 0)+
				(re->Proto>0? (re->Proto ^ Proto) : 0)+
				(re->src_Port>0? (re->src_Port ^ src_Port) : 0)+
				(re->dst_Port>0? (re->dst_Port ^ dst_Port) : 0);
		if (result == 0){ // hit
			if(HH > re->HH){
				return re->action_HH;
			}
			if(SS > re->SS){
				return re->action_SS;
			}
		}else
			return -1;
		    
	}
		
}

