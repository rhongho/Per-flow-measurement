#include <stdio.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>   //ifreq
#include <unistd.h>
#include <string.h>    //strlen
#include <sys/socket.h>    //socket
#include <arpa/inet.h> //inet_addr
#include <netinet/ether.h>
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <time.h>
#include "pcap.h"
#include "hash_t.h"
#include <stdlib.h>



#define SIZE_ETHERNET 14
int system(const char *command);

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
uint64_t get_MAC_address(char *iface);
uint64_t MAC_ff = 281474976710655;
char* interface_name;
bool L3 = false;
bool L4 = false;

/*****************************************used for hash***********************************/


static inline uint32_t hash_rot(uint32_t x, int k)
{
    return (x << k) | (x >> (32 - k));
}


static inline uint32_t mhash_add__(uint32_t hash, uint32_t data)
{
    /* zero-valued 'data' will not change the 'hash' value */
    if (!data) {
        return hash;
    }

    data *= 0xcc9e2d51;
    data = hash_rot(data, 15);
    data *= 0x1b873593;
    return hash ^ data;
}
static inline uint32_t mhash_add(uint32_t hash, uint32_t data)
{
    hash = mhash_add__(hash, data);
    hash = hash_rot(hash, 13);
    return hash * 5 + 0xe6546b64;
}

static inline uint32_t hash_add(uint32_t hash, uint32_t data)
{
    return mhash_add(hash, data);
}

static inline uint32_t hash_add64(uint32_t hash, uint64_t data)
{
    return hash_add(hash_add(hash, data), data >> 32);
}


/***********************************************************/
#define counter_size 8192 // memory for sketch 32 KB
#define vector_size_cse 16 //bit
#define vector_size_rcc 8  //bit
#define vector_est 9.763622328 //when 8 bit vector saturated, the estimation is approx. 9.77 accroding to SketchFlow formular 1. 

uint32_t counter_L3[counter_size];
uint32_t counter_L4[counter_size];
hashtable_L3 *table_L3;
hashtable_L4 *table_L4;
#define hash_table_size 1<<10

void usage(){
    printf("Error. Usage: \"./file_name NIC_name Monitoring_Layer\"\nEx. ./rflow eth 3\nMonitoring_Layer: 3 or 4\n" );
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
    if(atoi(argv[2]) == 3)
        L3 = true;
    else if(atoi(argv[2]) == 4)
        L4 = true;
    else{
        usage();
        return 1;
    }
	//Memory allocation for sketch and hashtables    
    if(L3){
		//Data structure of the sketch is int array
        memset(counter_L3, 0, counter_size*sizeof(int));
		//Hash table/Flow record table
        if ((table_L3 = ht_create_L3(hash_table_size)) == NULL)
        {
            printf("Fail to allocate memory L3\n");
            exit(0);
        }
    }else if(L4){
        memset(counter_L4, 0, counter_size*sizeof(int));
        if ((table_L4 = ht_create_L4(hash_table_size)) == NULL)
        {
            printf("Fail to allocate memory L4\n");
            exit(0);
        }
    }

    printf("Start monitoring\n");
    
    pcap_if_t *alldevs;             
    pcap_if_t *d;                    
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
        
     
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
			fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
			return 1;
	}
             
	for(d=alldevs; d; d=d->next)
	{
		if(strcmp(d->name ,interface_name)==0)
		break;
	}

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
	pcap_loop(adhandle, 0, packet_handler, NULL);
	pcap_close(adhandle);
	pcap_freealldevs(alldevs);
    return 0;
}

/******************* Rflow+ Utilities *********************************************/

uint64_t mac2int(const uint8_t hwaddr[])
{
    int8_t i;
    uint64_t ret = 0;
    const uint8_t *p = hwaddr;
    for (i = 5; i >= 0; i--) {
        ret |= (uint64_t) *p++ << (CHAR_BIT * i);
    }
    return ret;
}

void int2mac(const uint64_t mac, uint8_t *hwaddr)
{
    int8_t i;
    uint8_t *p = hwaddr;
    for (i = 5; i >= 0; i--) {
        *p++ = mac >> (CHAR_BIT * i);
    }
}

static inline void bin(unsigned n) 
{ 
    printf("Vector: ");
    unsigned i; 
    for (i = 1 << 31; i > 0; i = i / 2) 
        (n & i)? printf("1"): printf("0"); 
    printf("\n");
} 


static inline uint64_t get_device_MAC_address(char *iface)
{
    int fd;
    struct ifreq ifr;
    u_char *mac;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    mac = (u_char *)ifr.ifr_hwaddr.sa_data;
    //display mac address
    printf("%s Mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\t" ,iface, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    uint64_t mac_uint64 = (uint64_t)mac[0] << 40 | (uint64_t)mac[1] << 32 |
    (uint64_t)mac[2] << 24 |
    (uint64_t)mac[3] << 16 |
    (uint64_t)mac[4] << 8  |
    (uint64_t)mac[5];
    printf("id: %"PRId64"\n",mac_uint64);
    return mac_uint64;
}

/***************************** Approximate Counting Utilities ********************************************/

static unsigned int g_seed1 = 0;
static unsigned int g_seed2 = 0;

// Compute a pseudorandom integer.
// Output value in range [0, 32767]
static inline int fast_rand_gen1(void) {
    g_seed1 = (214013*g_seed1+2531011);
    return (g_seed1>>16)&0x7FFF;
}
static inline int fast_rand_gen2(void) {
    g_seed2 = (214013*g_seed2+2531011);
    return (g_seed2>>16)&0x7FFF;
}

static inline int get_bitmask_of_d_index(int vector, int D)
{
    while (D-- > 0)
    {
        vector &= vector - 1;
    }

    return vector & -vector;    // a word that contains the D's bit in the virtual vector
}

static inline uint32_t vector_maker(uint32_t hash_value){
	return (0x1<<(hash_value & 0x3)) | (0x10<<((hash_value>>4) & 0x3))
        | (0x100<<((hash_value>>8) & 0x3)) | (0x1000<<((hash_value>>12) & 0x3))
        | (0x10000<<((hash_value>>16) & 0x3)) | (0x100000<<((hash_value>>20) & 0x3))
        | (0x1000000<<((hash_value>>24) & 0x3)) | (0x10000000<<((hash_value>>28) & 0x3));
}

/******************************** Print Stat *************************************************/

//Print Stat. When Vector Saturate
static inline void print_L3_stat(){
    int loc, observed_flow = 0;
    printf("Layer-3 Flow Stat.\n   Flow_id|  Real_count|  Estimation\n");
    for(loc = 0; loc<table_L3->size;++loc)
    {
        if(table_L3->htable[loc] != NULL)
        {
           printf("%10"PRIu32"   %10"PRIu32" %12.2f\n",table_L3->htable[loc]->hash_value,table_L3->htable[loc]->counter,table_L3->htable[loc]->est);
           //table_L3->htable[loc]= NULL;
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
           //table_L3->htable[loc]= NULL;
        }
    } 
}



/******************* packet parsing pipline and counting*******************/

uint32_t prev_check_point = 0;
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    
    uint32_t is,id; //source IP, dest IP
    uint8_t proto;  //Protocol
    uint16_t sp,dp; // source Port, dest Port
    
    //header conponents
    struct ether_header *eptr;
    struct iphdr *iph;
    struct tcphdr *tcpheader;
    struct udphdr *udpheader;
  

    //struct ether_header *eptr = (struct ether_header *) pkt_data;
    //uint64_t mac_s = mac2int(eptr->ether_shost);
    //uint64_t mac_d = mac2int(eptr->ether_dhost);
    
    iph = (struct iphdr*)(pkt_data + SIZE_ETHERNET);

    if((unsigned int)iph->version == 4){
        
        is = iph->saddr;
        id = iph->daddr;
        proto = iph->protocol;

        if(proto == 6){
            tcpheader = (struct tcphdr*)(pkt_data + SIZE_ETHERNET + iph->ihl * 4);
            sp = ntohs(tcpheader->th_sport);
            dp = ntohs(tcpheader->th_dport);    
        }else if(proto == 17){
            udpheader = (struct udphdr*)(pkt_data + SIZE_ETHERNET+ iph->ihl * 4);
            sp = ntohs(udpheader->uh_sport);
            dp = ntohs(udpheader->uh_dport);
        }else{
            sp = 0; 
            dp = 0;
        }


        uint32_t hash = 0;
        hash = hash_add(hash, is); //CRC check sum based hashing
        hash = hash_add(hash, id);
        
        //L3 real count (for comparing with estimations)
        ht_insert_L3(table_L3, hash, is, id,0);
        
        //L3 approximate count
        uint32_t idx = hash%counter_size;
        uint32_t randn = fast_rand_gen1()%8;
        counter_L3[idx] |= (0x1<<(randn*4))<<((hash>>(randn*4))&0x3);
   
        uint32_t vector =  vector_maker(hash);
        
        //If the vector is saturated, say more than 70% of bit positions are 1.   ex. 8 bit & 0.7 = 5.6 => 5 
        if (__builtin_popcount(counter_L3[idx]&vector) > 5) 
        {
            ht_insert_L3(table_L3, hash, is, id, vector_est);
            counter_L3[idx] &= ~vector;
            if(L3)
                print_L3_stat();
        }

        if(!L4)
            return;
        //L4 flow stat.
        hash = hash_add(hash, proto);
        hash = hash_add(hash, sp);
        hash = hash_add(hash, dp);
        
        
        //L4 real count (for comparing with estimations)
		ht_insert_L4(table_L4,hash,is,id,proto,sp,dp,0);

        //L4 approximate count
        idx = hash%counter_size;
        randn = fast_rand_gen2()%8;
        counter_L4[idx] |= (0x1<<(randn*4))<<((hash>>(randn*4))&0x3);
        
        vector =  vector_maker(hash);
        if (__builtin_popcount(counter_L4[idx]&vector) > 5) 
        {
            ht_insert_L4(table_L4,hash,is,id,proto,sp,dp,vector_est);
            counter_L4[idx] &= ~vector;
            print_L4_stat();
        }
    }
}








