#include <stdint.h>
#include <stdbool.h>
#include <json.h>
#include <netinet/ether.h>
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <time.h>
#include <pthread.h> // gcc  test.c -o test -lpthread
#include "pcap.h"
#include "hash_table.h"
#include "queue.h"
#include "rule_matcher.h"
#include "utility.h"

#define SIZE_ETHERNET 14
#define counter_size 8192 // memory for sketch 32 KB
#define vector_size 128 //bit
#define vector_est 9.763622328 //when 8 bit vector saturated, the estimation is approx. 9.77 accroding to SketchFlow formular 1. 
#define hash_table_size 1<<16
#define rule_table_size 100

int system(const char *command);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
uint64_t get_device_MAC_address(char *iface);
uint64_t MAC_ff = 281474976710655;
char* interface_name;
uint64_t device_ID;
bool L2 = false;
bool L3 = false;
bool L4 = false;

uint32_t RCC_L2[counter_size];
uint32_t RCC_L3[counter_size];
uint32_t RCC_L4[counter_size];
uint32_t cse_L2[counter_size];
uint32_t cse_L3[counter_size];
uint32_t cse_L4[counter_size];

Local_Flow_Record_Table_L2 *table_L2;
Local_Flow_Record_Table_L3 *table_L3;
Local_Flow_Record_Table_L4 *table_L4;

Rule_Table *rule_table;

struct queue_root *queue;

void usage(){
    printf("Error. Usage: \"./file_name NIC_name Monitoring_Layer\"\nEx. ./rflow eth 3\nMonitoring_Layer: 3 or 4\n" );
}

/* Print Stat */
//Print Stat. When Vector Saturate

static inline void print_L2_stat(){
    int loc, observed_flow = 0;
    printf("Layer-2 Flow Stat.\n   Flow_id|  Real_count|  Estimation\n");
    for(loc = 0; loc<table_L2->size;++loc)
    {
        if(table_L2->htable[loc] != NULL)
        {
           printf("%10"PRIu32"   %10"PRIu32" %12.2f\n",table_L2->htable[loc]->hash_value,table_L2->htable[loc]->counter,table_L2->htable[loc]->est);
        }
    }
}


static inline void print_L3_stat(){
    int loc, observed_flow = 0;
    printf("Layer-3 Flow Stat.\n   Flow_id|  Real_count|  Estimation\n");
    for(loc = 0; loc<table_L3->size;++loc)
    {
        if(table_L3->htable[loc] != NULL)
        {
           printf("%10"PRIu32"   %10"PRIu32" %12.2f\n",table_L3->htable[loc]->hash_value,table_L3->htable[loc]->counter,table_L3->htable[loc]->est);
        }
    } 
}

static inline void print_L4_stat(){
    int loc, observed_flow = 0;
    printf("Layer-4 Flow Stat.\n   Flow_id|  Real_count|  Estimation\n");
    for(loc = 0; loc<table_L4->size;++loc)
    {
        if(table_L4->htable[loc] != NULL)
        {
           printf("%10"PRIu32"   %10"PRIu32" %12.2f\n",table_L4->htable[loc]->hash_value,table_L4->htable[loc]->counter,table_L4->htable[loc]->est);
        }
    } 
}


void* stat_upload(void* para){
	int i;
	while (1){
		sleep(5);
		struct json_object *array, *object, *tmp;
		array = json_object_new_array();
		object = json_object_new_object();
		
		tmp = json_object_new_int64(device_ID);
		json_object_object_add(object, "ID", tmp);
		if(L2){
			//print_L2_stat();
			tmp = json_object_new_int(2);
			json_object_object_add(object, "Layer", tmp);
			for(i = 0; i< table_L2->size; i++){
				if (table_L2->htable[i] != NULL){
					tmp = json_object_new_int(table_L2->htable[i]->hash_value);
					json_object_array_add(array,tmp);
					tmp = json_object_new_double(table_L2->htable[i]->est);
					json_object_array_add(array,tmp);
					table_L2->htable[i]->est = 0;
				}
			}
			
			
		}
		if(L3){
			tmp = json_object_new_int(3);
			json_object_object_add(object, "Layer", tmp);
			for(i = 0; i< table_L3->size; i++){
				if (table_L3->htable[i] != NULL && table_L3->htable[i]->est > 0){
					tmp = json_object_new_int(table_L3->htable[i]->hash_value);
					json_object_array_add(array,tmp);
					tmp = json_object_new_double(table_L3->htable[i]->est);
					json_object_array_add(array,tmp);
					table_L3->htable[i]->est = 0;
				}
			}
		}
		if(L4){
			tmp = json_object_new_int(4);
			json_object_object_add(object, "Layer", tmp);
			for(i = 0; i< table_L4->size; i++){
				if (table_L4->htable[i] != NULL && table_L4->htable[i]->est > 0){
					tmp = json_object_new_int(table_L4->htable[i]->hash_value);
					json_object_array_add(array,tmp);
					tmp = json_object_new_double(table_L4->htable[i]->est);
					json_object_array_add(array,tmp);
					table_L3->htable[i]->est = 0;
				}
			}
		}
		json_object_object_add(object, "Flow_Record", array);
		update(json_object_to_json_string(object));

	}
}

void* packet_processing(void* para){
	uint32_t i, idx, randn;
	uint32_t vector_L2, vector_L3, vector_L4, vector_src; 
	uint32_t hash_L2, hash_L3, hash_L4;
	uint32_t hash_src, hash_dst;
	double HH, SS;
	struct queue_head* hdr;
	while (1){
		hdr = queue_get(queue);
		if (!hdr){
			usleep(10);
			continue;
		}
		if(L2){
			/*RCC-L2*/
			hash_L2 = 0;
			hash_L2 = hash_add64(hash_L2, hdr->mac_s);
			hash_src = hash_L2;
			hash_L2 = hash_add64(hash_L2, hdr->mac_d);
			vector_L2 = vector_maker(hash_L2);
			
			idx=hash_L2%counter_size;
			randn = rand()%8;
			RCC_L2[idx] |= (0x1<<(randn*4))<<((hash_L2>>(randn*4))&0x3);
			
			if(__builtin_popcount(RCC_L2[idx]& vector_L2)>5){
				RCC_L2[idx] &= ~vector_L2;
				HH = ht_insert_L2(table_L2, hash_L2, hdr->mac_s,hdr->mac_d,vector_est);
			}
		
			/*MCSE-L2*/
			hash_dst = hash_add(0,hdr->mac_d);
			vector_src = vector_maker(hash_src);
			idx = hash_src% (counter_size/(vector_size/8));
			cse_L2[idx*(vector_size/8)+(hash_dst%vector_size)/8] |= get_bitmask_of_d_index(vector_src, hash_dst%8);
			
			SS = 0;
			for(i=0; i< vector_size/8; i++){
				SS += __builtin_popcount(cse_L2[idx*(vector_size/8)+i] & vector_src);
			}
			if(SS>= vector_size-2){	
				for(i=0; i< vector_size/8; i++){
					cse_L2[idx*(vector_size/8)+i] &= ~vector_src;
				}
			}
			Rule_Matcher(rule_table, hdr-> mac_s, hdr-> mac_d, hdr->is, hdr->id, hdr->proto, hdr->sp,hdr->dp, HH, SS);
		}
		if(L3){
			/*RCC-L3*/
			hash_L3 = 0;
			hash_L3 = hash_add(hash_L3, hdr->is);
			hash_src = hash_L3;
			hash_L3 = hash_add(hash_L3, hdr->id);
			vector_L3 = vector_maker(hash_L3);
			idx=hash_L3%counter_size;	
			randn = rand()%8;
			RCC_L3[idx] |= (0x1<<(randn*4))<<((hash_L3>>(randn*4))&0x3);

			if(__builtin_popcount(RCC_L3[idx]& vector_L3)>5){
				RCC_L3[idx] &= ~vector_L3;
		   		HH = ht_insert_L3(table_L3, hash_L3, hdr->is,hdr->id,vector_est);
			}

			/*MCSE-L3*/
			hash_dst = hash_add(0,hdr->id);
			vector_src = vector_maker(hash_src);
			idx = hash_src % (counter_size/(vector_size/8));
			cse_L3[idx*(vector_size/8)+(hash_dst%vector_size)/8] |= get_bitmask_of_d_index(vector_src, hash_dst%8);
			SS =0;
			for(i=0; i< vector_size/8; i++){
				SS +=__builtin_popcount(cse_L3[idx*(vector_size/8)+i] & vector_src);
			}
			if(SS>= vector_size-2){	
				for(i=0; i< vector_size/8; i++){
					cse_L3[idx*(vector_size/8)+i] &= ~vector_src;
				}
			}
			Rule_Matcher(rule_table, hdr-> mac_s, hdr-> mac_d, hdr->is, hdr->id, hdr->proto, hdr->sp,hdr->dp, HH, SS);
		}
		if(L4){
			/*RCC-L4*/		
			hash_L4 = 0;
			hash_L4 = hash_add(hash_L3, hdr->proto);
			hash_L4 = hash_add(hash_L4, hdr->sp);
			hash_src = hash_L4;
			hash_L4 = hash_add(hash_L4, hdr->dp);
			vector_L4 = vector_maker(hash_L4);
			idx=hash_L3 % counter_size;	
			randn = rand()%8;
			RCC_L4[idx] |= (0x1<<(randn*4))<<((hash_L4>>(randn*4))&0x3);

			if(__builtin_popcount(RCC_L4[idx] & vector_L4)>5){
			   RCC_L4[idx] &= ~vector_L4;
			   HH = ht_insert_L4(table_L4, hash_L4, hdr->is,hdr->id,hdr->proto,hdr->sp,hdr->dp,vector_est);
			}
			/*MCSE-L4*/
			hash_dst = hash_add(0,hdr->dp);
			vector_src = vector_maker(hash_src);
			idx = hash_src% (counter_size/(vector_size/8));
			cse_L4[idx*(vector_size/8)+(hash_dst%vector_size)/8] |= get_bitmask_of_d_index(vector_src, hash_dst%8);
			SS = 0;
			for(i=0; i< vector_size/8; i++){
				SS += __builtin_popcount(cse_L4[idx*(vector_size/8)+i] & vector_src);
			}
			if(SS>= vector_size-2){	
				for(i=0; i< vector_size/8; i++){
					cse_L4[idx*(vector_size/8)+i] &= ~vector_src;
				}
			}
			Rule_Matcher(rule_table, hdr-> mac_s, hdr-> mac_d, hdr->is, hdr->id, hdr->proto, hdr->sp,hdr->dp, HH, SS);
		}
		free(hdr);
	}

}


int main(int argc,char **argv)
{
	if(argc < 3){
		usage();
		return 1;
	}
	//Get interface name for monitoring
	if(strlen(argv[1]) != 0){
		interface_name = argv[1];
	}else{
		usage();
	return 1;
	}
	//L3 or L4 monitoring?
	if(atoi(argv[2]) == 2)
		L2 = true;
	else if(atoi(argv[2]) == 3)
		L3 = true;
	else if(atoi(argv[2]) == 4)
		L4 = true;
	else{
		usage();
		return 1;
	}
	
	queue = ALLOC_QUEUE_ROOT();


	//Memory allocation for sketch and hashtables    
	if(L2){
		//Data structure of the sketch is int array
		memset(RCC_L2, 0, counter_size*sizeof(int));
		//Hash table/Flow record table
		if ((table_L2 = ht_create_L2(hash_table_size)) == NULL){
		    printf("Fail to allocate memory L3\n");
		    exit(0);
		}
	}else if(L3){
		memset(RCC_L3, 0, counter_size*sizeof(int));
		if ((table_L3 = ht_create_L3(hash_table_size)) == NULL){
		    printf("Fail to allocate memory L3\n");
		    exit(0);
		}
	}else if(L4){
		memset(RCC_L4, 0, counter_size*sizeof(int));
		if ((table_L4 = ht_create_L4(hash_table_size)) == NULL){
		    printf("Fail to allocate memory L4\n");
		    exit(0);
		}
	}
	
	if ((rule_table = rt_create(rule_table_size)) == NULL){
		    printf("Fail to allocate memory rule table\n");
		    exit(0);
	}
		
	printf("Start monitoring\n");

	pcap_if_t *alldevs;             
	pcap_if_t *d;                    
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
        
     
	if(pcap_findalldevs(&alldevs, errbuf) == -1){
			fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
			return 1;
	}
             
	for(d=alldevs; d; d=d->next){
		if(strcmp(d->name ,interface_name)==0)
		break;
	}
	device_ID = get_device_MAC_address(d->name);

	printf("Monitoring interface: %s\n", d->name);
	if ((adhandle= pcap_open_live(d->name, // name of the device
							 65536,             // portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,         // promiscuous mode (nonzero means promiscuous)
							 1000,              // read timeout
							 errbuf         // error buffer
							 )) == NULL){
			fprintf(stderr,"\nUnable to open the adapter. %s is not supported by libpcap\n", d->name);
			pcap_freealldevs(alldevs);
			return -1;
	}
	
	
	pthread_t re;
	pthread_create(&re, NULL, packet_processing, NULL);
	
	pthread_t stat;
	pthread_create(&stat, NULL, stat_upload, NULL);
	
	pcap_loop(adhandle, 0, packet_handler, NULL);
	pcap_close(adhandle);
	pcap_freealldevs(alldevs);
    return 0;
}


/* packet parser */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    	struct ether_header *eptr = (struct ether_header *) pkt_data;
	uint64_t mac_s = mac2int(eptr->ether_shost);
	uint64_t mac_d = mac2int(eptr->ether_dhost);
	struct iphdr *iph = (struct iphdr*)(pkt_data + sizeof(struct ether_header));

	if((unsigned int)iph->version == 4){
		uint32_t src_ip=iph->saddr;
		uint32_t dst_ip=iph->daddr;
		uint8_t proto = iph->protocol;
		uint16_t src_port,dst_port; // source Port, dest Port
		if(proto == 6){
			struct tcphdr *tcpheader = (struct tcphdr*)(pkt_data + sizeof(struct ether_header) + iph->ihl * 4);
			src_port =ntohs(tcpheader->th_sport);
			dst_port = ntohs(tcpheader->th_dport);	
		}else if(proto == 17){
			struct udphdr *udpheader = (struct udphdr*)(pkt_data + sizeof(struct ether_header) + iph->ihl * 4);
			src_port =ntohs(udpheader->uh_sport);
			dst_port = ntohs(udpheader->uh_dport);
		}else{
			src_port = 0; 
			dst_port = 0;
		}
		struct queue_head *item = malloc(sizeof(struct queue_head));
		INIT_QUEUE_HEAD(item, mac_s, mac_d, src_ip, dst_ip, proto, src_port, dst_port);
		queue_put(item, queue);
	}
}








