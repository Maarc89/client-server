#include "common.h"

pthread_t subscriber_handler,hello_controller_thread,tcp_connections_thread;
volatile int subscriber_handler_hello = 0,hello_controller_hello = 0,tcp_connections_hello = 0;
struct client clients[MAX_CLIENTS];
volatile int server_UDP_port = 0,server_TCP_port = 0;
volatile int server_UDP_socket;
int debug = 0;
char *mac_info = NULL;
char fx_name[9],fx_situation[13];

struct PDU_UDP create_udp_packet(unsigned char tipus, char mac[], char aleatori[], char dades[]){
    struct PDU_UDP packet;
    packet.tipus = tipus;
    strcpy(packet.mac,mac);
    strcpy(packet.aleatori,aleatori);
    strcpy(packet.dades,dades);
    return packet;
}

struct PDU_TCP create_tcp_packet(unsigned char tipus, char mac[], char aleatori[], char dispositiu[], char valor[], char info[]){
    struct PDU_TCP packet;
    packet.tipus = tipus;
    strcpy(packet.mac,mac);
    strcpy(packet.aleatori,aleatori);
    strcpy(packet.dispositiu,dispositiu);
    strcpy(packet.valor,valor);
    strcpy(packet.info,info);
    return packet;
}

void print_debug(char msg[]){
    time_t timet = time(NULL);
    char *tlocal = ctime(&timet);
    tlocal[strlen(tlocal) - 1] = '\0';
    fflush(stdout);
    printf("%s: %s\n",tlocal,msg);
}

int is_SUBS_REQ_correct(struct PDU_UDP buff){
    /* -1 - No enviar res
        0 - Enviar SUBS_ACK
        1 - Enviar SUBS_NACK
        2 - Enviar SUBS_REJ
    */
    int i = 0;
    if(buff.tipus != SUBS_REQ){
        return -1;
    }
    for(i = 0; i < MAX_CLIENTS; i++){
        if(strcmp(buff.mac,(char *) clients[i].mac) == 0){
            break;
        }
        if(i == 15){
            return 2;
        }
    }
    if(clients[i].status != DISCONNECTED && clients[i].status != NOT_SUBSCRIBED){
        if(debug == 1){
            print_debug("S'ha rebut [SUBS_REQ] en un estat que no era DISCONNECTED ni NOT_SUBSCRIBED");
        }
        return 1;
    }
    if(strcmp(buff.aleatori,"00000000\0") != 0 /*|| strcmp(buff.dades,"") != 0*/){
        if(debug == 1){
            print_debug("Les dades o l'aleatori del [SUBS_REQ] son incorrectes");
        }
        return 1;
    }else{
        return 0;
    }
}

void handle_cntrc(){
    print_debug("Sortint per ^C");
    subscriber_handler_hello = 0;
    hello_controller_hello = 0;
    tcp_connections_hello = 0;
    exit(0);
}

void update_client(char affected_mac[],int new_status){
    int i = 0;
    char debug_msg[128];
    fflush(stdout);
    for(i = 0;i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].mac,affected_mac) == 0){
            if(new_status == DISCONNECTED){
                sprintf(debug_msg,"Nou estat del client %s: DISCONNECTED",(char *) affected_mac);
            }else if (new_status == NOT_SUBSCRIBED){
                sprintf(debug_msg,"Nou estat del client %s: NOT_SUBSCRIBED",(char *) affected_mac);
            }else if (new_status == WAIT_ACK_SUBS){
                sprintf(debug_msg,"Nou estat del client %s: WAIT_ACK_SUBS",(char *) affected_mac);
            }else if (new_status == WAIT_INFO){
                sprintf(debug_msg,"Nou estat del client %s: WAIT_INFO",(char *) affected_mac);
            }else if (new_status == WAIT_ACK_INFO){
                sprintf(debug_msg,"Nou estat del client %s: WAIT_ACK_INFO",(char *) affected_mac);
            }else if (new_status == SUBSCRIBED){
                sprintf(debug_msg,"Nou estat del client %s: SUBSCRIBED",(char *) affected_mac);
            }else if (new_status == SEND_HELLO && clients[i].status != SEND_HELLO){
                sprintf(debug_msg,"Nou estat del client %s: SEND_HELLO",(char *) affected_mac);
                print_debug(debug_msg);
            }
            if(new_status != SEND_HELLO && debug == 1){
                print_debug(debug_msg);
            }
            clients[i].status = new_status;
        }
    }
}

void list(){
    int i = 0,j = 0;
    printf("**********DADES DISPOSITIUS**********\n");
    printf("Name\t\tStatus\t\tDispositius\n");
    for(i = 0; i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].name,"\0") != 0){
            if(clients[i].status == DISCONNECTED){
                printf("%s\tDISCONNECTED\t",(char *) clients[i].name);
            }else if (clients[i].status == NOT_SUBSCRIBED){
                printf("%s\tNOT_SUBSCRIBED\t",(char *) clients[i].name);
            }else if (clients[i].status == WAIT_ACK_SUBS){
                printf("%s\tWAIT_ACK_SUBS\t",(char *) clients[i].name);
            }else if (clients[i].status == WAIT_INFO){
                printf("%s\tWAIT_INFO\t",(char *) clients[i].name);
            }else if (clients[i].status == WAIT_ACK_INFO){
                printf("%s\tWAIT_ACK_INFO\t",(char *) clients[i].name);
            }else if (clients[i].status == SUBSCRIBED){
                printf("%s\tSUBSCRIBED\t",(char *) clients[i].name);
            }else if (clients[i].status == SEND_HELLO){
                printf("%s\tSEND_HELLO\t",(char *) clients[i].name);
            }
            for(j = 0; j < MAX_DISPS;j++){
                if(strcmp(clients[i].dispositius[j],"\0") == 0){
                    break;
                }
                printf("%s;",(char *) clients[i].dispositius[j]);
            }
            printf("\n");
        }
    }
    printf("**************************************\n");
}

int get_client_udp_port(char mac[]){
    int i = 0;
    for(i = 0;i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].mac,mac) == 0){
            return clients[i].new_udp_port;
        }
    }
    return 0;
}

int get_client_status(char mac[]){
    int i = 0;
    for(i = 0;i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].mac,mac) == 0){
            return clients[i].status;
        }
    }
    return 0;
}

void set_client_address(char affected_mac[], struct sockaddr_in cl_addrs){
    int i = 0;
    for(i = 0;i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].mac,affected_mac) == 0){
            clients[i].addr_UDP = cl_addrs;
        }
    }
}

void set_client_random(char affected_mac[], int random){
    int i = 0;
    for(i = 0;i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].mac,affected_mac) == 0){
            clients[i].random = random;
        }
    }
}

void set_client_udp_port(char affected_mac[], int udp_port){
    int i = 0;
    for(i = 0;i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].mac,affected_mac) == 0){
            clients[i].new_udp_port = udp_port;
        }
    }
}

int is_HELLO_correct(struct PDU_UDP buff){
    int i = 0;
    if(buff.tipus != HELLO){
        return -1;
    }
    for(i = 0; i < MAX_CLIENTS; i++){
        if(strcmp(buff.mac,(char *) clients[i].mac) == 0){
            break;
        }
        if(i == (MAX_CLIENTS - 1)){
            return -1;
        }
    }
    if(clients[i].status != SUBSCRIBED && clients[i].status != SEND_HELLO){
        if(debug == 1){
            print_debug("S'ha rebut [HELLO] en un estat que no era SUBSCRIBED ni SEND_HELLO");
        }
        return -1;
    }

    if(atoi(buff.aleatori) != clients[i].random){
        if(debug == 1){
            print_debug("Les dades o l'aleatori del [HELLO] son incorrectes");
        }
        return -1;
    }else{
        return 0;
    }
}

void set_client_hello(char mac[]){
    int i = 0;
    for(i = 0;i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].mac,mac) == 0){
            clients[i].hello_recved = 1;
            clients[i].hellos_no_answer = 0;
        }
    }
}

void set_TCP_port(char mac[], char port[]){
    int i = 0;
    for(i = 0;i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].mac,mac) == 0){
            clients[i].TCP_port = atoi(port);
        }
    }
}

void set_TCP_addr(char mac[], struct sockaddr_in addr){
    int i = 0;
    for(i = 0;i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].mac,mac) == 0){
            clients[i].addr_TCP = addr;
        }
    }
}

void add_dispositiu(char mac[], char dispositiu[]){
    int i = 0, j = 0;
    for(i = 0;i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].mac,mac) == 0){
            j = 0;
            for(j = 0;j < MAX_DISPS;j++){
                if(strcmp(clients[i].dispositius[j],dispositiu) == 0){
                    break;
                }
                if(strcmp(clients[i].dispositius[j],"\0") == 0){
                    strcpy(clients[i].dispositius[j],dispositiu);
                    break;
                }
            }
        }
    }
}

void *client_manager(void *argvs){
    struct sockaddr_in serv_new_addrs,cl_addrs,cl_tcp;
    int rand,new_UDP_port,recved,new_UDP_socket,retl;
    char str_rand[9],str_new_UDP_port[5],str_TCP_port[5],debug_msg[128],info_split[128],name[8],situation[12];
    char *ptr,*ptr2, *ptr3;
    struct PDU_UDP buffer,buffer2,SUBS_ACK_packet,SUBS_NACK_packet,SUBS_REJ_packet,HELLO_packet, INFO_packet;
    fd_set selectset;
    struct timeval tv;
    int len = sizeof(cl_addrs);
    int server_UDP_socket = *((int *) argvs);

    recvfrom(server_UDP_socket,&buffer,103, MSG_WAITALL,(struct sockaddr *) &cl_addrs, (socklen_t *) &len);
    if(debug == 1){
        print_debug("S'ha rebut un paquet pel port UDP principal");
    }

    /*Mirar si es SUBS_REQ o HELLO
     * si es SUBS_REQ igual
     * si es HELLO contestar*/
    if((recved = is_SUBS_REQ_correct(buffer)) == 0){
        if(debug == 1){
            print_debug("El paquet SUBS_REQ es correcte");
        }
        buffer.mac[12] = '\0';
        if(debug == 1){
            print_debug("Client envia SUBS_REQ, passa a WAIT_ACK_SUBS");
        }
        update_client(buffer.mac,WAIT_ACK_SUBS);
        set_client_address(buffer.mac,cl_addrs);

        ptr3 = strtok(buffer.dades, ",");

        strcpy(name, ptr3);

        ptr3 = strtok(NULL, ",");

        strcpy(situation, ptr3);
        strcpy(fx_name, name);
        strcpy(fx_situation, situation);

        printf("dades: %s-%s", fx_name, fx_situation);

        rand = generate_random();
        new_UDP_port = generate_UDP_port();
        set_client_random(buffer.mac,rand);
        set_client_udp_port(buffer.mac,new_UDP_port);

        sprintf((char *) str_rand,"%i",rand);
        str_rand[8] = '\0';

        memset(&serv_new_addrs,0,sizeof(struct sockaddr_in));

        serv_new_addrs.sin_family = AF_INET;
        serv_new_addrs.sin_port = htons(new_UDP_port);
        serv_new_addrs.sin_addr.s_addr = INADDR_ANY;

        new_UDP_socket = socket(AF_INET,SOCK_DGRAM,0);

        while(bind(new_UDP_socket,(const struct sockaddr *)&serv_new_addrs,sizeof(serv_new_addrs))<0){
            print_debug("ERROR => No s'ha pogut bindejar el socket");
            new_UDP_port = generate_UDP_port();
            serv_new_addrs.sin_port = htons(new_UDP_port);
        }
        if (debug == 1){
            print_debug("Nou socket bindejat correctament");
        }

        sprintf((char *) str_new_UDP_port,"%i",new_UDP_port);
        str_new_UDP_port[4] = '\0';

        SUBS_ACK_packet = create_udp_packet(SUBS_ACK,mac_info,str_rand,str_new_UDP_port);

        /*Envia SUBS_ACK*/
        sendto(server_UDP_socket,(struct PDU_UDP *) &SUBS_ACK_packet,103,MSG_CONFIRM,(struct sockaddr *) &cl_addrs, len);

        FD_ZERO(&selectset);
        FD_SET(new_UDP_socket,&selectset);

        tv.tv_sec = 2;
        tv.tv_usec = 0;
        retl = select(new_UDP_socket+1,&selectset,NULL,NULL,(struct timeval *) &tv);
        if(retl){
            if(FD_ISSET(new_UDP_socket,&selectset)){
                fflush(stdout);
                recvfrom(new_UDP_socket,&buffer2,103, MSG_WAITALL,(struct sockaddr *) &cl_addrs, (socklen_t *) &len);
                /*Rebut paquet SUBS_INFO, contestar amb el paquet que toqui*/
                if(buffer2.tipus != SUBS_INFO){
                    printf("error: %s", &buffer2.tipus);
                    if (debug == 1){
                        print_debug("Tipus de paquet no esperat, no es contestarà");
                    }
                    update_client(buffer2.mac,DISCONNECTED);
                }else{
                    if(rand == atoi(buffer2.aleatori) && strcmp(buffer.mac,buffer2.mac) == 0){

                        strcpy(info_split,buffer2.dades);

                        ptr = strtok(info_split, ",");

                        set_TCP_port(buffer2.mac,ptr);

                        cl_tcp.sin_family = AF_INET;
                        cl_tcp.sin_port = htons(atoi(ptr));
                        cl_tcp.sin_addr.s_addr = cl_addrs.sin_addr.s_addr;

                        set_TCP_addr(buffer2.mac,cl_tcp);

                        ptr = strtok(NULL, ",");

                        ptr2 = strtok(ptr, ";");

                        while (ptr2 != NULL)
                        {
                            add_dispositiu(buffer2.mac,ptr2);
                            ptr2 = strtok(NULL, ";");
                        }

                        sprintf(str_TCP_port,"%i",server_TCP_port);
                        str_TCP_port[4] = '\0';
                        sprintf((char *) str_rand,"%i",rand);
                        str_rand[8] = '\0';
                        INFO_packet = create_udp_packet(INFO_ACK,mac_info,str_rand,str_TCP_port);
                        sendto(new_UDP_socket,(struct PDU_UDP *) &INFO_packet,103,MSG_CONFIRM,(struct sockaddr *) &cl_addrs, len);
                        /*Paquet SUBS_INFO correcte, llegir dades i contestar amb INFO_ACK*/
                        update_client(buffer2.mac,SUBSCRIBED);
                        sleep(3);
                        if(get_client_status(buffer2.mac) == SUBSCRIBED){ /* El client no ha enviat el primer hello */
                            sprintf(debug_msg,"El client %s no ha enviat el 1r [HELLO]",(char *) buffer2.mac);
                            print_debug(debug_msg);
                            update_client(buffer2.mac,DISCONNECTED);
                        }
                    }else{
                        sprintf((char *) str_rand,"%i",rand);
                        str_rand[8] = '\0';
                        INFO_packet = create_udp_packet(INFO_ACK,mac_info,str_rand,"Info no acceptada");
                    }
                }
            }
        }else{
            sprintf(debug_msg,"El client %s no ha contestat el SUBS_ACK",buffer.mac);
            print_debug(debug_msg);
            update_client(buffer.mac,DISCONNECTED);
        }
    }else if(recved == 1){
        SUBS_NACK_packet = create_udp_packet(SUBS_NACK,mac_info,"00000000","Alguna cosa no quadra entre estats o dades");
        sendto(server_UDP_socket,(struct PDU_UDP *) &SUBS_NACK_packet,103,MSG_CONFIRM,(struct sockaddr *) &cl_addrs, len);
        update_client(buffer.mac,DISCONNECTED);
    }else if(recved == 2){
        SUBS_REJ_packet = create_udp_packet(SUBS_REJ,mac_info,"00000000","Error d'identificació");
        sendto(server_UDP_socket,(struct PDU_UDP *) &SUBS_REJ_packet,103,MSG_CONFIRM,(struct sockaddr *) &cl_addrs, len);
        update_client(buffer.mac,DISCONNECTED);
    }else{ /* El paquet és un HELLO */
        if((recved = is_HELLO_correct(buffer)) == 0){
            set_client_hello(buffer.mac);
            HELLO_packet = create_udp_packet(HELLO,mac_info,buffer.aleatori,buffer.mac);
            update_client(buffer.mac,SEND_HELLO);
            if(debug == 1){
                sprintf(debug_msg,"Enviant paquet [HELLO] a %s",(char *) buffer.mac);
                print_debug(debug_msg);
            }
            sendto(server_UDP_socket,(struct PDU_UDP *) &HELLO_packet,103,MSG_CONFIRM,(struct sockaddr *) &cl_addrs, len);
        }else if (recved == -1){
            HELLO_packet = create_udp_packet(HELLO_REJ,mac_info,buffer.aleatori,buffer.mac);
            update_client(buffer.mac,DISCONNECTED);
            sendto(server_UDP_socket,(struct PDU_UDP *) &HELLO_packet,103,MSG_CONFIRM,(struct sockaddr *) &cl_addrs, len);
        }
    }
    return NULL;
}

void *hello_controller(void *argvs){
    int i = 0;
    char str_rand[9],debug_msg[128];
    struct PDU_UDP HELLO_packet;
    int len = sizeof(struct sockaddr_in);
    while(hello_controller_hello != 0){
        i = 0;
        sleep(2);
        for (i = 0;i < MAX_CLIENTS; i++){
            if(clients[i].status == SEND_HELLO){
                if(clients[i].hellos_no_answer == 3){
                    sprintf(debug_msg,"El client %s ha deixat d'enviar hellos",(char *) clients[i].mac);
                    print_debug(debug_msg);
                    update_client(clients[i].mac,DISCONNECTED);
                }
                if(clients[i].hello_recved == 0){
                    sprintf((char *) str_rand,"%i",clients[i].random);
                    str_rand[8] = '\0';
                    HELLO_packet = create_udp_packet(HELLO,mac_info,str_rand,clients[i].mac);
                    if(debug == 1){
                        sprintf(debug_msg,"Enviant paquet [HELLO] a %s",(char *) clients[i].mac);
                        print_debug(debug_msg);
                    }
                    sendto(server_UDP_socket,(struct PDU_UDP *) &HELLO_packet,103,MSG_CONFIRM,(struct sockaddr *) &clients[i].addr_UDP, len);
                    clients[i].hellos_no_answer++;
                }else{
                    clients[i].hello_recved = 0;
                }
            }
        }
    }
    return NULL;
}

void *subscriber_handler_fun(void *argvs){ /*Bindeja socket 1 i crea thread al rebre paquets SUBS_REQ*/
    struct sockaddr_in serv_addrs;
    pthread_t client_manager_thread;
    fd_set selectset;
    int retl;

    memset(&serv_addrs,0,sizeof(struct sockaddr_in));

    serv_addrs.sin_family = AF_INET;
    serv_addrs.sin_port = htons(server_UDP_port);
    serv_addrs.sin_addr.s_addr = INADDR_ANY;

    server_UDP_socket = socket(AF_INET,SOCK_DGRAM,0);

    if(bind(server_UDP_socket,(const struct sockaddr *)&serv_addrs,sizeof(serv_addrs))<0){
        print_debug("ERROR => No s'ha pogut bindejar el socket");
        exit(-1);
    }
    if(debug == 1){
        print_debug("Socket bindejat correctament");
    }

    while(subscriber_handler_hello == 1){
        FD_ZERO(&selectset);
        FD_SET(server_UDP_socket,&selectset);
        retl = select(server_UDP_socket+1,&selectset,NULL,NULL,0);
        if(retl){
            if(FD_ISSET(server_UDP_socket,&selectset)){
                if(debug == 1){
                    print_debug("Creant thread per a rebre un paquet UDP");
                }
                pthread_create(&client_manager_thread,NULL,client_manager,(void *) &server_UDP_socket);
                sleep(0.1);
            }
        }
    }
    return NULL;
}

int correct_mac(char mac[],int aleatori){
    /* 0 = error
     * 1 = correcte */
    int i = 0;
    for (i = 0; i < MAX_CLIENTS; i++){
        if(strcmp(clients[i].mac,mac) == 0){
            if(aleatori == clients[i].random){
                if(clients[i].status == SEND_HELLO){
                    return 1;
                }else{
                    return 0;
                }
            }else{
                return 0;
            }
        }
    }
    return 0;
}

int dispositiu_in_client(char mac[], char dispositiu[]){
    int i = 0, j = 0;
    for(i = 0;i < MAX_CLIENTS;i++){
        if(strcmp(clients[i].mac,mac) == 0){
            j = 0;
            for(j = 0;j < MAX_DISPS;j++){
                if(strcmp(clients[i].dispositius[j],dispositiu) == 0){
                    return 1;
                }
            }
            return 0;
        }
    }
    return 0;
}

int is_SEND_DATA_correct(struct PDU_TCP buffer){
    /* -1 = No contestar
     *  0 = DATA_ACK
     *  1 = DATA_NACK fitxer
     *  2 = DATA_REJ
     *  3 = DATA_NACK dades
     * */
    FILE *logfile;
    char filename[27];
    char res_str[128];
    time_t timet;
    char *tlocal;
    int putsr;

    if(buffer.tipus != SEND_DATA){
        return -1;
    }

    if(correct_mac(buffer.mac,atoi(buffer.aleatori)) == 0){
        update_client(buffer.mac,DISCONNECTED);
        return 2;
    }else{
        sprintf(filename,"%s-%s.data", (char *) fx_name, (char *) fx_situation);
        if(dispositiu_in_client(buffer.mac,buffer.dispositiu) == 0){
            return 3;
        }
        logfile = fopen(filename,"a");
        timet = time(NULL);
        tlocal = ctime(&timet);
        tlocal[strlen(tlocal) - 1] = '\0';
        fflush(stdout);
        sprintf(res_str,"%s,SEND_DATA,%s,%s\n",tlocal,buffer.dispositiu,buffer.valor);
        putsr = fputs(res_str,logfile);
        if (putsr == EOF){
            return 1;
        }
        putsr = fclose(logfile);
        if (putsr == EOF){
            return 1;
        }
        return 0;
    }
}

void *tcp_man(void *argvs){
    int csocket;
    struct PDU_TCP RECV_packet, SEND_packet;
    int recved;

    csocket = *((int *) argvs);

    recv(csocket,(struct PDU_UDP *) &RECV_packet,sizeof(struct PDU_TCP),0);

    if((recved = is_SEND_DATA_correct(RECV_packet)) == 0){
        SEND_packet = create_tcp_packet(DATA_ACK,mac_info,RECV_packet.aleatori,RECV_packet.dispositiu,RECV_packet.valor,RECV_packet.mac);
    }else if(recved == -1){
        close(csocket);
    }else if(recved == 1){
        SEND_packet = create_tcp_packet(DATA_NACK,mac_info,RECV_packet.aleatori,RECV_packet.dispositiu,RECV_packet.valor,"Hi ha hagut un error amb el fitxer");
    }else if(recved == 2){
        SEND_packet = create_tcp_packet(DATA_REJ,mac_info,RECV_packet.aleatori,RECV_packet.dispositiu,RECV_packet.valor,"Error d'identificació");
    }else if(recved == 3){
        SEND_packet = create_tcp_packet(DATA_NACK,mac_info,RECV_packet.aleatori,RECV_packet.dispositiu,RECV_packet.valor,"Hi ha hagut un error amb els dispositius");
    }
    if(recved != -1){
        send(csocket,&SEND_packet,sizeof(struct PDU_TCP),0);
        close(csocket);
    }
    return NULL;
}

void *tcp_connections(void *argvs){
    int TCP_socket,new_socket,retl,len;
    struct sockaddr_in serv_addrs,cl_addrs;
    pthread_t pack_manager;
    fd_set selectset;

    len = sizeof(serv_addrs);

    TCP_socket = socket(AF_INET,SOCK_STREAM,0);

    serv_addrs.sin_family = AF_INET;
    serv_addrs.sin_port = htons(server_TCP_port);
    serv_addrs.sin_addr.s_addr = INADDR_ANY;

    if(bind(TCP_socket,(const struct sockaddr *)&serv_addrs,(socklen_t) len)<0){
        print_debug("ERROR => No s'ha pogut bindejar el socket TCP");
        exit(-1);
    }
    if(debug == 1){
        print_debug("Socket TCP bindejat correctament");
    }

    listen(TCP_socket,5);

    while(tcp_connections_hello == 1){
        FD_ZERO(&selectset);
        FD_SET(TCP_socket,&selectset);
        retl = select(TCP_socket+1,&selectset,NULL,NULL,0);
        if(retl){
            new_socket = accept(TCP_socket,(struct sockaddr *) &cl_addrs,(socklen_t * ) &len);
            if (debug == 1){
                print_debug("S'ha rebut una connexió pel port TCP");
            }
            pthread_create(&pack_manager,NULL,tcp_man,(void *) &new_socket);
        }
    }
    return NULL;
}

int set(char clname[],char disp[],char val[]){
    struct PDU_TCP SEND_pack,buffer;
    int tcp_sock;
    int i,retl;
    char str_rand[9];
    struct timeval tv;
    fd_set selectset;
    FILE *logfile;
    char filename[128];
    char res_str[128];
    time_t timet;
    char *tlocal;
    if(strcmp(clname,"") == 0 || strcmp(disp,"") == 0 || strcmp(val,"") == 0){
        print_debug("Comanda errònea. Ús: set <nom_controlador> <nom_dispositiu> <valor>");
    }else{
        fflush(stdout);
        tcp_sock = socket(AF_INET,SOCK_STREAM,0);
        i = 0;
        for(i = 0; i < MAX_CLIENTS;i++){
            if(strcmp(clients[i].name,clname) == 0){
                if(clients[i].status == SEND_HELLO){
                    sprintf(str_rand,"%i",clients[i].random);
                    SEND_pack = create_tcp_packet(SET_DATA,mac_info,str_rand,disp,val,clname);
                    connect(tcp_sock,(struct sockaddr *) &clients[i].addr_TCP,sizeof(struct sockaddr_in));
                    send(tcp_sock,(struct PDU_TCP *) &SEND_pack,sizeof(struct PDU_TCP),0);
                    FD_ZERO(&selectset);
                    FD_SET(tcp_sock,&selectset);
                    tv.tv_sec = 3;
                    tv.tv_usec = 0;
                    retl = select(tcp_sock+1,&selectset,NULL,NULL,(struct timeval *) &tv);
                    if(retl){
                        recv(tcp_sock,&buffer,sizeof(struct PDU_TCP),0);
                        if(buffer.tipus == DATA_REJ){
                            print_debug("S'han rebutjat les dades");
                        }else if(buffer.tipus == DATA_NACK){
                            print_debug("No s'han pogut guardar les dades");
                            print_debug(buffer.info);
                        }else if(buffer.tipus == DATA_ACK){
                            print_debug("S'han acceptat les dades");
                            sprintf(filename,"%s.data",(char *) buffer.mac);
                            logfile = fopen(filename,"a");
                            timet = time(NULL);
                            tlocal = ctime(&timet);
                            tlocal[strlen(tlocal) - 1] = '\0';
                            fflush(stdout);
                            sprintf(res_str,"%s,SET_DATA,%s,%s\n",tlocal,buffer.dispositiu,buffer.valor);
                            fputs(res_str,logfile);
                            fclose(logfile);
                            close(tcp_sock);
                            return 0;
                        }else{
                            print_debug("Paquet no esperat");
                        }
                    }else{
                        print_debug("El client no ha contestat");
                    }
                }else{
                    print_debug("El client no està connectat");
                }
            }
        }
    }
    close(tcp_sock);
    return -1;
}

int get(char clname[],char disp[]){
    struct PDU_TCP SEND_pack,buffer;
    int tcp_sock;
    int i,retl;
    char str_rand[9];
    struct timeval tv;
    fd_set selectset;
    FILE *logfile;
    char filename[128];
    char res_str[128];
    time_t timet;
    char *tlocal;
    if(strcmp(clname,"") == 0 || strcmp(disp,"") == 0){
        print_debug("Comanda errònea. Ús: get <nom_controlador> <nom_dispositiu>");
    }else{
        fflush(stdout);
        tcp_sock = socket(AF_INET,SOCK_STREAM,0);
        i = 0;
        for(i = 0; i < MAX_CLIENTS;i++){
            if(strcmp(clients[i].name,clname) == 0){
                if(clients[i].status == SEND_HELLO){
                    sprintf(str_rand,"%i",clients[i].random);
                    SEND_pack = create_tcp_packet(GET_DATA,mac_info,str_rand,disp,"",clname);
                    connect(tcp_sock,(struct sockaddr *) &clients[i].addr_TCP,sizeof(struct sockaddr_in));
                    send(tcp_sock,(struct PDU_TCP *) &SEND_pack,sizeof(struct PDU_TCP),0);
                    FD_ZERO(&selectset);
                    FD_SET(tcp_sock,&selectset);
                    tv.tv_sec = 3;
                    tv.tv_usec = 0;
                    retl = select(tcp_sock+1,&selectset,NULL,NULL,(struct timeval *) &tv);
                    if(retl){
                        recv(tcp_sock,&buffer,sizeof(struct PDU_TCP),0);
                        if(buffer.tipus == DATA_REJ){
                            print_debug("S'han rebutjat les dades");
                        }else if(buffer.tipus == DATA_NACK){
                            print_debug("No s'han pogut guardar les dades");
                        }else if(buffer.tipus == DATA_ACK){
                            print_debug("S'han acceptat les dades");
                            sprintf(filename,"%s.data",(char *) buffer.mac);
                            logfile = fopen(filename,"a");
                            timet = time(NULL);
                            tlocal = ctime(&timet);
                            tlocal[strlen(tlocal) - 1] = '\0';
                            fflush(stdout);
                            sprintf(res_str,"%s,GET_DATA,%s,%s\n",tlocal,buffer.dispositiu,buffer.valor);
                            fputs(res_str,logfile);
                            fclose(logfile);
                            close(tcp_sock);
                            return 0;
                        }else{
                            print_debug("Paquet no esperat");
                        }
                    }else{
                        print_debug("El client no ha contestat");
                    }
                }
            }
        }
    }
    close(tcp_sock);
    return -1;
}

void ajuda(){
    printf("*************** AJUDA **************\n");
    printf("Comanda \tÚs\t\t\t\t\tFunció\n\n");
    printf("set \t\tset <nom_controlador> <nom_ispositiu> <valor>\tEnvia el valor entrat al dispositiu del client\n");
    printf("get \t\tget <nom_controlador> <nom_dispositiu>\t\tRep el valor del dispositiu del client\n");
    printf("list \t\tlist \t\t\t\t\tMostra els clients acceptats amb els seus dispositius\n");
    printf("quit \t\tquit \t\t\t\t\tTanca el servidor\n");
    printf("debug \t\tdebug \t\t\t\t\tActiva o desactiva el mode debug\n");
    printf("ajuda \t\t? \t\t\t\t\tMostra aquesta ajuda\n");
    printf("*************************************\n");
}

void quit(){
    subscriber_handler_hello = 0;
    hello_controller_hello = 0;
    tcp_connections_hello = 0;
    exit(0);
}

int main(int argc,char *argv[]){
    FILE *cfg_file,*dat_file;
    int i,j,operation_result;
    char filename[64] = "",datab_name[64] = "";
    char server_UDP_port_read[32],server_UDP_port_arr[6];
    char server_TCP_port_read[32],server_TCP_port_arr[6];
    char temp_client[32] = "\0";
    char buff_comm[255];
    char params[4][255];
    char *ptr;
    char line[100];
    for(i = 1; i < argc;i++){
        if(strcmp(argv[i],"-c") == 0){
            if((i+1) < argc && strlen(argv[i+1]) <= 64){
                strcpy(filename,argv[i+1]);
                i++;
            }else{
                printf("Ús: ./sr {-c <nom_fitxer>} {-d} {-u <nom_fitxer>}\n");
            }
        }else if(strcmp(argv[i],"-u") == 0){
            if((i+1) < argc && strlen(argv[i+1]) <= 64){
                strcpy(datab_name,argv[i+1]);
                i++;
            }else{
                printf("Ús: ./sr {-c <nom_fitxer>} {-d} {-u <nom_fitxer>}\n");
            }
        }else if(strcmp(argv[i],"-d") == 0){
            debug = 1;
        }else{
            printf("Ús: ./sr {-c <nom_fitxer>} {-d} {-u <nom_fitxer>}\n");
        }
    }
    if(strcmp(filename,"") == 0){
        strcpy(filename,"server.cfg");
    }
    if(strcmp(datab_name,"") == 0){
        strcpy(datab_name,"controllers.dat");
    }
    if(debug == 1){
        print_debug("Llegint fitxers de configuració");
    }
    cfg_file = fopen(filename,"r");

    while (fgets(line, sizeof(line), cfg_file)) {
        if (strstr(line, "MAC") != NULL) {
            char *equal_sign = strchr(line, '=');
            if (equal_sign != NULL) {
                mac_info = equal_sign + 1;
                break;
            }
        }
    }

    fgets(server_UDP_port_read,32,cfg_file);
    j = 0;
    for(i = 0; i < strlen(server_UDP_port_read);i++){
        if(isdigit(server_UDP_port_read[i])){
            server_UDP_port_arr[j] = server_UDP_port_read[i];
            j++;
        }
    }
    server_UDP_port_arr[j] = '\0';
    server_UDP_port = atoi(server_UDP_port_arr);
    fgets(server_TCP_port_read,32,cfg_file);
    j = 0;
    for(i = 0; i < strlen(server_TCP_port_read);i++){
        if(isdigit(server_TCP_port_read[i])){
            server_TCP_port_arr[j] = server_TCP_port_read[i];
            j++;
        }
    }
    server_TCP_port_arr[j] = '\0';
    server_TCP_port = atoi(server_TCP_port_arr);
    if(fclose(cfg_file) != 0){
        if(debug == 1){
            print_debug("Hi ha hagut un error. Sortint");
        }
        exit(-1);
    }
    dat_file = fopen(datab_name,"r");
    i = 0;
    while(i < MAX_CLIENTS && fgets(temp_client,sizeof(temp_client),dat_file) != NULL) {
        char *token = strtok(temp_client, ",");
        if (token != NULL) {
            strncpy(clients[i].name, token, 8);
            clients[i].name[8] = '\0';


            token = strtok(NULL, ",");
            if (token != NULL) {
                strncpy(clients[i].mac, token, 12);
                clients[i].mac[12] = '\0';

                clients[i].status = DISCONNECTED;

                j = 0;
                for (j = 0; j < MAX_DISPS; j++) {
                    strcpy(clients[i].dispositius[j], "\0");
                }
                clients[i].hello_recved = 0;
                clients[i].hellos_no_answer = 0;

            }
            i++;
        }
    }
    if(fclose(dat_file) != 0){
        if(debug == 1){
            print_debug("Hi ha hagut un error. Sortint");
        }
        exit(-1);
    }
    if(debug == 1){
        print_debug("Lectures inicials finalitzades");
    }
    /*  mac_info = mac servidor
        server_TCP_port = port TCP servidor
        server_UDP_port = port UDP servidor
        debug = cal fer debug o no
        allowed_disps = macs aceptades de clients
    */
    subscriber_handler_hello = 1;
    hello_controller_hello = 1;
    tcp_connections_hello = 1;
    pthread_create(&subscriber_handler,NULL,subscriber_handler_fun,NULL);
    pthread_create(&hello_controller_thread,NULL,hello_controller,NULL);
    pthread_create(&tcp_connections_thread,NULL,tcp_connections,NULL);
    signal(SIGINT,handle_cntrc);
    fflush(stdout);
    while(0 < 1){
        printf("Introdueix una comanda: ");
        i = 0;
        while (i < 4){
            strcpy(params[i],"");
            i++;
        }
        fflush(stdout);
        fgets(buff_comm, 255, stdin);
        buff_comm[strlen(buff_comm) - 1] = '\0';
        ptr = strtok(buff_comm, " ");
        i = 0;
        while(i < 4 && ptr != NULL){
            strcpy(params[i],ptr);
            ptr = strtok(NULL, " ");
            i++;
        }
        if (strcmp(params[0],"set") == 0){
            operation_result = set(params[1],params[2],params[3]);
            if(operation_result >= 0){
                print_debug("Operació exitosa");
            }else{
                print_debug("Operació fallida");
            }
        }else if(strcmp(params[0], "get") == 0){
            operation_result = get(params[1],params[2]);
            printf("Operation: %d", operation_result);
            if(operation_result >= 0){
                print_debug("Operació exitosa");
            }else{
                print_debug("Operació fallida");
            }
        }else if(strcmp(params[0],"list") == 0){
            list();
        }else if(strcmp(params[0],"quit") == 0){
            quit();
        }else if(strcmp(params[0],"debug") == 0){
            if(debug == 0){
                print_debug("Mode debug activat");
                debug = 1;
            }else{
                debug = 0;
                print_debug("Mode debug desactivat");
            }
        }else if(strcmp(params[0],"?") == 0){
            ajuda();
        }else{
            print_debug("Comanda errònea");
        }
    }
    exit(0);
}