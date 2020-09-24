#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>    //socket
#include <net/if.h>   //ifreq
#include <inttypes.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> //inet_addr
#include <stdlib.h>
#include <unistd.h>

static unsigned int g_seed1 = 0;
static unsigned int g_seed2 = 0;

uint64_t mac2int(const uint8_t hwaddr[]);

void int2mac(const uint64_t mac, uint8_t *hwaddr);

void bin(unsigned n);

uint64_t get_device_MAC_address(char *iface);

uint32_t hash_rot(uint32_t x, int k);

uint32_t mhash_add__(uint32_t hash, uint32_t data);

uint32_t mhash_add(uint32_t hash, uint32_t data);

uint32_t hash_add(uint32_t hash, uint32_t data);

uint32_t hash_add64(uint32_t hash, uint64_t data);

int fast_rand_gen1(void);

int fast_rand_gen2(void);

int get_bitmask_of_d_index(int vector, int D);

uint32_t vector_maker(uint32_t hash_value);
