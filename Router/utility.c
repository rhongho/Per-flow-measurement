#include "utility.h"
/* Rflow+ Utilities */


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

void bin(unsigned n) 
{ 
    printf("Vector: ");
    unsigned i; 
    for (i = 1 << 31; i > 0; i = i / 2) 
        (n & i)? printf("1"): printf("0"); 
    printf("\n");
} 


uint64_t get_device_MAC_address(char *iface)
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


/*Hash Function*/

uint32_t hash_rot(uint32_t x, int k){
    return (x << k) | (x >> (32 - k));
}

uint32_t mhash_add__(uint32_t hash, uint32_t data){
    /* zero-valued 'data' will not change the 'hash' value */
    if (!data) {
        return hash;
    }
    data *= 0xcc9e2d51;
    data = hash_rot(data, 15);
    data *= 0x1b873593;
    return hash ^ data;
}

uint32_t mhash_add(uint32_t hash, uint32_t data){
    hash = mhash_add__(hash, data);
    hash = hash_rot(hash, 13);
    return hash * 5 + 0xe6546b64;
}

uint32_t hash_add(uint32_t hash, uint32_t data){
    return mhash_add(hash, data);
}

uint32_t hash_add64(uint32_t hash, uint64_t data){
    return hash_add(hash_add(hash, data), data >> 32);
}


// Compute a pseudorandom integer.
// Output value in range [0, 32767]
int fast_rand_gen1(void) {
    g_seed1 = (214013*g_seed1+2531011);
    return (g_seed1>>16)&0x7FFF;
}
int fast_rand_gen2(void) {
    g_seed2 = (214013*g_seed2+2531011);
    return (g_seed2>>16)&0x7FFF;
}

int get_bitmask_of_d_index(int vector, int D){
    while (D-- > 0){
        vector &= vector - 1;
    }
    return vector & -vector;    // a word that contains the D's bit in the virtual vector
}

uint32_t vector_maker(uint32_t hash_value){
	return (0x1<<(hash_value & 0x3)) | (0x10<<((hash_value>>4) & 0x3))
        | (0x100<<((hash_value>>8) & 0x3)) | (0x1000<<((hash_value>>12) & 0x3))
        | (0x10000<<((hash_value>>16) & 0x3)) | (0x100000<<((hash_value>>20) & 0x3))
        | (0x1000000<<((hash_value>>24) & 0x3)) | (0x10000000<<((hash_value>>28) & 0x3));
}
