#define _POSIX_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <signal.h>
#include <pthread.h>

#define MAX_CLIENTS 16
#define MAX_DISPS 16

int SUBS_REQ = 0;
int SUBS_ACK = 1;
int SUBS_REJ = 2;
int SUBS_INFO = 3;
int INFO_ACK = 4;
int SUBS_NACK = 5;
int HELLO = 16;
int HELLO_REJ = 17; 
int SEND_DATA = 32;
int SET_DATA = 33;
int GET_DATA = 34;
int DATA_ACK = 35;
int DATA_NACK = 36;
int DATA_REJ = 37;

int DISCONNECTED = 160;
int NOT_SUBSCRIBED = 161;
int WAIT_ACK_SUBS = 162;
int WAIT_INFO = 163;
int WAIT_ACK_INFO = 164;
int SUBSCRIBED = 165;
int SEND_HELLO = 166;

int generate_random(){
    return (rand() % (99999999 - 10000000 + 1)) + 10000000;
}

int generate_UDP_port(){
    return (rand() % (65000 - 1024 + 1)) + 1024;
}

struct client{
    int status;
    char name[9];
    char mac[13];
    char dispositius[16][8];
    struct sockaddr_in addr_UDP;
    struct sockaddr_in addr_TCP;
    int random;
    int TCP_port;
    int new_udp_port;
    int hello_recved;
    int hellos_no_answer;
};

struct PDU_UDP{
    unsigned char tipus;
    char mac[13];
    char aleatori[9];
    char dades[80];
};

struct PDU_TCP{
	unsigned char tipus;
	char mac[13];
	char aleatori[9];
	char dispositiu[8];
	char valor[7];
	char info[80];
};
