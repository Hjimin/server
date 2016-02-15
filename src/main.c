#include <stdio.h>
#include <thread.h>
#include <net/ni.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <lwip/tcp.h>
#include <string.h>
#include <timer.h>
#include <util/event.h>
#include <util/list.h>

#define address1 0xc0a8640a	//192.168.100.10

static err_t server_accept(void *arg, struct tcp_pcb *pcb, err_t err);
static err_t server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
static void server_close(struct tcp_pcb *pcb);
static err_t server_sent(void *arg, struct tcp_pcb *pcb, u16_t len);

void destroy() {
}
void gdestroy() {
}

static Packet* pre_process(Packet* packet) {
        if(!packet)
                return NULL;

        Ether* ether = (Ether*)(packet->buffer + packet->start);
        
        if(endian16(ether->type) == ETHER_TYPE_ARP) {
		// ARP response
		ARP* arp = (ARP*)ether->payload;
		if(endian16(arp->operation) == 1 && endian32(arp->tpa) == address1) {
			ether->dmac = ether->smac;
			ether->smac = endian48(packet->ni->mac);
			arp->operation = endian16(2);
			arp->tha = arp->sha;
			arp->tpa = arp->spa;
			arp->sha = ether->smac;
			arp->spa = endian32(address1);
			
			ni_output(packet->ni, packet);
			packet = NULL;
		}
	}
        return packet;
}

bool lwip_loop(void* context) {
        ni_poll();
        return true;
}

bool lwip_timer(void* context) {
        ni_timer();
        return true;
}

void ginit(int argc, char** argv) {

        NetworkInterface* server_ni = ni_get(0);   //set as a client side ni
   
        if(server_ni != NULL) {
                ni_ip_add(server_ni, address1);
                IPv4Interface* v4Inter = ni_ip_get(server_ni, address1);
                v4Inter->gateway = 0xc0a864fe;  //192.168.100.254
                v4Inter->netmask = 0xffffff00;  //255.255.255.0
        }

        mem_init();
        time_init();
        event_init();
        ni_init(server_ni, pre_process, NULL);

        event_idle_add(lwip_loop, NULL);
        event_timer_add(lwip_timer, NULL, 100000, 100000);
}

void init(int argc, char** argv) {
}


static err_t server_accept(void *arg, struct tcp_pcb *pcb, err_t err) {
    	struct tcp_pcb_listen* server = arg; 
        tcp_accepted(server);
	tcp_recv(pcb, server_recv);
	tcp_sent(pcb, server_sent);
        //tcp_poll(pcb, server_poll, 4); //every two seconds of inactivity of the TCP connection
	printf("\n server_accept(): Accepting incoming connection on server...\n");
	return ERR_OK;
}
void server_init(void) {
        printf("server_init start\n");
        struct tcp_pcb *pcb;
   	pcb = tcp_new();
  	err_t err = tcp_bind(pcb, IP_ADDR_ANY, 22000); //server port for incoming connection
        if(err != ERR_OK) {
                printf("ERROR: Manager cannot bind TCP session: %d\n", err);
                return;
        }

        pcb = tcp_listen(pcb);
	tcp_arg(pcb,pcb);  
	tcp_accept(pcb, server_accept);
	
        printf("server_init finished\n");
}

static void server_close(struct tcp_pcb *pcb) {
        tcp_arg(pcb, NULL);
        tcp_sent(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_close(pcb);
        printf("\nserver_close(): Closing...\n");
}
static err_t server_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
	return ERR_OK;
}

static err_t server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err){
        char *string;
        size_t length;

        if (err == ERR_OK && p != NULL) {
                tcp_recved(pcb, p->tot_len);
        	 
                string = p->payload;
                length = strlen(string);
         
                printf("\nserver_recv(): Incoming string is %s\n", string);
      		
		tcp_write(pcb, string, length,0);
	
		pbuf_free(p);
        }else {
                printf("\nserver_recv(): Errors-> ");
                if (err != ERR_OK)
         		printf("Connection is not on ERR_OK state : %d \n", err);
         
                if (p == NULL)
                        printf("Pbuf pointer p is a NULL pointer : \n ");
                printf("Closing server-side connection...");
                pbuf_free(p);
                server_close(pcb);
        }
     
        return ERR_OK;
}





int main(int argc, char** argv) {
	printf("Thread %d booting\n", thread_id());
	if(thread_id() == 0) {
		ginit(argc, argv);
	}
	
	thread_barrior();
	
	init(argc, argv);
	
	thread_barrior();
	
	server_init();	
	while(1) {
		event_loop();
	}
	
	thread_barrior();
	
	destroy();
	
	thread_barrior();
	
	if(thread_id() == 0) {
		gdestroy(argc, argv);
	}
	
	return 0;
}

