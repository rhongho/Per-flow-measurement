#include "stat_update.h"

void update(char* stat) {
    printf("%s\n", stat);
    int sock = 0, valread; 
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0}; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { 
        printf("\n Socket creation error \n"); 
        return; 
    } 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 
       
    if(inet_pton(AF_INET, "192.168.0.146" , &serv_addr.sin_addr)<=0) { 
        printf("\nInvalid address/ Address not supported \n"); 
        return; 
    } 
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { 
        printf("\nConnection Failed \n"); 
        return; 
    } 
    send(sock , stat , strlen(stat) , 0 ); 
    printf("message sent\n"); 
    
    close(sock);
    //valread = read( sock , buffer, 1024); 
    //printf("%s\n",buffer ); 
} 
