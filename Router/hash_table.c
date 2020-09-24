#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include "hash_table.h"

/* Create a new hashtable. */


Local_Flow_Record_Table_L2* ht_create_L2(uint32_t size) {
	Local_Flow_Record_Table_L2 *table;

	/* Allocate the table itself. */
	if ((table = (Local_Flow_Record_Table_L2*)malloc(sizeof(Local_Flow_Record_Table_L2))) == NULL)
	{
		return NULL;
	}
	table->size = size;
	table->usage = 0;

	/* Allocate pointers to the head nodes. */
	if ((table->htable = malloc(sizeof(entry_L2 *) * size)) == NULL)
	{
		return NULL;
	}
	return table;
}


entry_L2* ht_newpair_L2() {
	entry_L2* newpair;
	if ((newpair = malloc(sizeof(entry_L2))) == NULL) {
		return NULL;
	}
	return newpair;
}


uint32_t ht_insert_L2(Local_Flow_Record_Table_L2 *hashtable, uint32_t hash_value, uint64_t mac_s, uint64_t mac_d, double est) {
	
	uint32_t loc = 0;
	int qp = -1;
	entry_L2* me;
	
	for (;;)
	{
		++qp;
		// prepare set to another place
		loc = (hash_value + (qp + qp*qp) / 2) % 4096; // hash_value + 0.5i+ 0.5i^2
		me = hashtable->htable[loc];

		if (me == NULL)
		{
			//printf("null\n");
			me = ht_newpair_L2();
	
			me->hash_value = hash_value;
			me->mac_s = mac_s;
			me->mac_d = mac_d;
			me->counter=0;
			me->est=0;
			
			if(est==0)
				me->counter+=1;
			else
				me->est+=est;

			hashtable->htable[loc] = me;

			++(hashtable->usage);
			//new flow here
			return me->est;
		}else if(me->hash_value == hash_value)
		{
			//printf("Not null\n");
		    	if(me->mac_s == mac_s && me->mac_d == mac_d)
			{
				if(est==0)
					me->counter+=1;
				else
					me->est+=est;
				hashtable->htable[loc] = me;
				return me->est;
			}
		}else
			continue;
		    
	}
		
}

/*L3*/
///////////////////////////////////////////////////////////////////////////////////////////////////////

/* Create a new hashtable. */

Local_Flow_Record_Table_L3* ht_create_L3( uint32_t size) {
	Local_Flow_Record_Table_L3 *table;

	/* Allocate the table itself. */
	if ((table = (Local_Flow_Record_Table_L3*)malloc(sizeof(Local_Flow_Record_Table_L3))) == NULL)
	{
		return NULL;
	}

	/* Allocate pointers to the head nodes. */
	if ((table->htable = (entry_L3 **)malloc(sizeof(entry_L3 *) * size)) == NULL)
	{
		return NULL;
	}

	table->size = size;
	table->usage = 0;
	
	return table;
}


entry_L3* ht_newpair_L3() {
	entry_L3* newpair;
	if ((newpair = malloc(sizeof(entry_L3))) == NULL) {
	return NULL;
	}

	return newpair;
}

uint32_t ht_insert_L3(Local_Flow_Record_Table_L3 *hashtable, uint32_t hash_value, uint32_t is, uint32_t id, double est) {
	
	uint32_t loc = 0;
	int qp = -1;
	entry_L3* me;

	int hsize = hashtable->size;
	
	for (;;)
	{
		++qp;
		// prepare set to another place
		loc = (hash_value + (qp + qp*qp) / 2) % hsize; // hash_value + 0.5i+ 0.5i^2
		me = hashtable->htable[loc];

		if (me == NULL)
		{
			me = ht_newpair_L3();
	
			me->hash_value = hash_value;
			me->is = is;
			me->id = id;
			me->counter=0;
			me->est=0;
			
			if(est==0)
				me->counter+=1;
			else
				me->est+=est;

			hashtable->htable[loc] = me;

			++(hashtable->usage);
			return me->est;
		}else if(me->hash_value == hash_value)
		{
		    	if(me->is == is && me->id == id)
			{
				if(est==0)
					me->counter+=1;
				else
					me->est+=est;
				hashtable->htable[loc] = me;
				return me->est;
			}
		}else
			continue;
		    
	}
		
}



/*L4*/
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* Create a new hashtable. *///

Local_Flow_Record_Table_L4 *ht_create_L4( uint32_t size) {
	Local_Flow_Record_Table_L4 *table;

	/* Allocate the table itself. */

	if ((table = (Local_Flow_Record_Table_L4*)malloc(sizeof(Local_Flow_Record_Table_L4))) == NULL)
	{
		return NULL;
	}

	printf("%"PRIu32"\n", size);

	/* Allocate pointers to the head nodes. */

	if ((table->htable = (entry_L4 **)malloc(sizeof(entry_L4 *) * size)) == NULL)
	{
		return NULL;
	}

	table->size = size;
	table->usage = 0;
	return table;
}


entry_L4* ht_newpair_L4() {
	entry_L4* newpair;
	if ((newpair = malloc(sizeof(entry_L4))) == NULL) {
			return NULL;
	}
	return newpair;
}

uint32_t ht_insert_L4(Local_Flow_Record_Table_L4 *hashtable, uint32_t hash_value, uint32_t is, uint32_t id, uint8_t proto, uint16_t sp , uint16_t dp, double est) {
	
	uint32_t loc = 0;
	int qp = -1;
	entry_L4* me;

	int hsize = hashtable->size;

	
	for (;;)
	{
		++qp;
		// prepare set to another place
		loc = (hash_value + (qp + qp*qp) / 2) % hsize; // hash_value + 0.5i+ 0.5i^2
		me = hashtable->htable[loc];

		if (me == NULL)
		{
			me = ht_newpair_L4();
	
			me->hash_value = hash_value;
			me->is = is;
			me->id = id;
		    me->proto = proto;
			me->sp = sp;
			me->dp = dp;
			me->counter=0;
			me->est=0;
			
			if(est==0)
				me->counter+=1;
			else
				me->est+=est;

			hashtable->htable[loc] = me;

			++(hashtable->usage);
			return me->est;
		}else if(me->hash_value == hash_value)
		{
		    if(me->is == is && me->id == id && me->proto == proto && me->sp == sp && me->dp == dp)
			{
				if(est==0)
					me->counter+=1;
				else
					me->est+=est;
				hashtable->htable[loc] = me;
				return me->est;
			}
		}else
			continue;
		    
	}
		
}


int verify_L3(Local_Flow_Record_Table_L3 *hashtable, uint32_t is)
{
	int loc, observed_flow = 0;
    for(loc = 0; loc<hashtable->size;++loc)
    {
        if(hashtable->htable[loc] != NULL && hashtable->htable[loc]->is == is)
        {
            observed_flow++;
        }
    }
    return observed_flow;
}

int verify_L4(Local_Flow_Record_Table_L4 *hashtable, uint32_t is, uint32_t id, uint8_t proto, uint16_t sp)
{
	int loc, observed_flow = 0;
    for(loc = 0; loc<hashtable->size;++loc)
    {
        if(hashtable->htable[loc] != NULL && hashtable->htable[loc]->is == is && hashtable->htable[loc]->id == id && hashtable->htable[loc]->proto == proto &&hashtable->htable[loc]->sp == sp)
        {
            observed_flow++;
        }
    }
    return observed_flow;
}
