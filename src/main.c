#include <stdio.h>
#include <thread.h>
#include <net/ni.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <lwip/tcp.h>
#include <string.h>
#include <timer.h>
#include <util/event.h>
#include <util/list.h>

#include <lwip/opt.h>
#include <lwip/debug.h>
#include <lwip/stats.h>

#define address1 0xc0a8640a	//192.168.100.10

static err_t server_accept(void *arg, struct tcp_pcb *pcb, err_t err);
static err_t server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
//static err_t server_poll(void *arg, struct tcp_pcb *pcb);
static void server_close(struct tcp_pcb *pcb);
void process(NetworkInterface* ni);
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


static err_t server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err){
        char *string;
        size_t length;
	//char *str = "Hello\n";
        //LWIP_UNUSED_ARG(arg);

	printf("recv working \n");     
        if (err == ERR_OK && p != NULL) {
                tcp_recved(pcb, p->tot_len);
        	 
                string = p->payload;
                length = strlen(string);
         
                printf("\nserver_recv(): Incoming string is %s\n", string);
                printf("\nserver_recv(): String length is %d byte\n", length);
                printf("server_recv(): pbuf->len is %d byte\n", p->len);
                printf("server_recv(): pbuf->tot_len is %d byte\n", p->tot_len);
                printf("server_recv(): pbuf->next is %d\n", p->next);
         
		tcp_write(pcb, string, length,0);
		pbuf_free(p);
        }else {
                printf("\nserver_recv(): Errors-> ");
                if (err != ERR_OK)
         		printf("1) Connection is not on ERR_OK state, but in %d state->\n", err);
         
                if (p == NULL)
                        printf("2) Pbuf pointer p is a NULL pointer->\n ");
                printf("server_recv(): Closing server-side connection...");
         
                pbuf_free(p);
                server_close(pcb);
        }
     
        return ERR_OK;
}

static err_t server_accept(void *arg, struct tcp_pcb *pcb, err_t err) {
        //LWIP_UNUSED_ARG(arg);
        //LWIP_UNUSED_ARG(err);
    	struct tcp_pcb_listen* server = arg; 
        tcp_accepted(server);
        //tcp_setprio(pcb, TCP_PRIO_MIN);
        //tcp_arg(pcb, NULL); //tcp_err(pcb, server_err);
        
	tcp_recv(pcb, server_recv);
        
	tcp_sent(pcb, server_sent);
	
	
        //tcp_poll(pcb, server_poll, 4); //every two seconds of inactivity of the TCP connection
	printf("\n server_accept(): Accepting incoming connection on server...\n");
	return ERR_OK;
}

/*
static err_t server_poll(void *arg, struct tcp_pcb *pcb) {
       //static int counter = 1;
       LWIP_UNUSED_ARG(arg);
       LWIP_UNUSED_ARG(pcb);
    
       //printf("\nserver_poll(): Call number %d\n", counter++);
    
       return ERR_OK;
}
*/
static err_t server_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
        //LWIP_UNUSED_ARG(len);
        //LWIP_UNUSED_ARG(arg);
        //server_close(pcb);
     
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




int main(int argc, char** argv) {
	printf("Thread %d booting\n", thread_id());
	if(thread_id() == 0) {
		ginit(argc, argv);
	}
	
	thread_barrior();
	
	init(argc, argv);
	
	thread_barrior();
	
	server_init();	
//	uint32_t i = 0;
	while(1) {
		event_loop();
//		uint32_t count = ni_count();
//		if(count > 0) {
//			i = (i + 1) % count;
//			
//			NetworkInterface* ni = ni_get(i);
//			if(ni_has_input(ni)) {
//				process(ni);
//			}
//		}
	}
	
	thread_barrior();
	
	destroy();
	
	thread_barrior();
	
	if(thread_id() == 0) {
		gdestroy(argc, argv);
	}
	
	return 0;
}
/*

void process(NetworkInterface* ni) {
	Packet* packet = ni_input(ni);
	if(!packet)
		return;
	
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	
	if(endian16(ether->type) == ETHER_TYPE_ARP) {
		// ARP response
		ARP* arp = (ARP*)ether->payload;
		if(endian16(arp->operation) == 1 && endian32(arp->tpa) == address) {
			ether->dmac = ether->smac;
			ether->smac = endian48(ni->mac);
			arp->operation = endian16(2);
			arp->tha = arp->sha;
			arp->tpa = arp->spa;
			arp->sha = ether->smac;
			arp->spa = endian32(address);
			
			ni_output(ni, packet);
			packet = NULL;
		}
	} else if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		
		if(ip->protocol == IP_PROTOCOL_ICMP && endian32(ip->destination) == address) {
			// Echo reply
			ICMP* icmp = (ICMP*)ip->body;
			
			icmp->type = 0;
			icmp->checksum = 0;
			icmp->checksum = endian16(checksum(icmp, packet->end - packet->start - ETHER_LEN - IP_LEN));
			
			ip->destination = ip->source;
			ip->source = endian32(address);
			ip->ttl = endian8(64);
			ip->checksum = 0;
			ip->checksum = endian16(checksum(ip, ip->ihl * 4));
			
			ether->dmac = ether->smac;
			ether->smac = endian48(ni->mac);
			
			ni_output(ni, packet);
			packet = NULL;
		} else if(ip->protocol == IP_PROTOCOL_UDP) {
			UDP* udp = (UDP*)ip->body;
			
			if(endian16(udp->destination) == 7) {
				uint16_t t = udp->destination;
				udp->destination = udp->source;
				udp->source = t;
				udp->checksum = 0;
				
				uint32_t t2 = ip->destination;
				ip->destination = ip->source;
				ip->source = t2;
				ip->ttl = 0x40;
				ip->checksum = 0;
				ip->checksum = endian16(checksum(ip, ip->ihl * 4));

				uint64_t t3 = ether->dmac;
				ether->dmac = ether->smac;
				ether->smac = t3;
				
				ni_output(ni, packet);
				packet = NULL;
			}
		} else if(ip->protocol == IP_PROTOCOL_TCP) {
			printf("tcp working\n");	
			TCP* tcp = (TCP*)ip->body;
			
			if(endian16(tcp->destination) == 22000) {
				server_init();	
			}
	
		}
	}
	
	if(packet)
		ni_free(packet);
}
static err_t server_accept(void *arg, struct tcp_pcb *pcb, err_t err);
static err_t server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
static err_t server_poll(void *arg, struct tcp_pcb *pcb);
static err_t server_err(void *arg, err_t err);

void my_server_init(void)
{
        printf("start\n");
	struct tcp_pcb *pcb;
   	pcb = tcp_new();
  	tcp_bind(pcb, IP_ADDR_ANY, 8000); //server port for incoming connection
        pcb = tcp_listen(pcb);
  	tcp_accept(pcb, server_accept);

}

static void server_close(struct tcp_pcb *pcb)
{
        tcp_arg(pcb, NULL);
        tcp_sent(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_close(pcb);
        printf("\nserver_close(): Closing...\n");
}

static err_t server_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
        LWIP_UNUSED_ARG(arg);
        LWIP_UNUSED_ARG(err);
     
        tcp_setprio(pcb, TCP_PRIO_MIN);
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, server_recv);
        tcp_err(pcb, server_err);
        tcp_poll(pcb, server_poll, 4); //every two seconds of inactivity of the TCP connection
        tcp_accepted(pcb);
        printf("\nserver_accept(): Accepting incoming connection on server...\n"); return ERR_OK;

}

static err_t server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err){
        char *string;
        int length;
        LWIP_UNUSED_ARG(arg);
     
        if (err == ERR_OK && p != NULL)
        {
                tcp_recved(pcb, p->tot_len);
         
                string = p->payload;
                length = strlen(string);
         
                printf("\nserver_recv(): Incoming string is %s\n", string);
         
                printf("\nserver_recv(): String length is %d byte\n", length);
                printf("server_recv(): pbuf->len is %d byte\n", p->len);
                printf("server_recv(): pbuf->tot_len is %d byte\n", p->tot_len);
                printf("server_recv(): pbuf->next is %d\n", p->next);
         
                pbuf_free(p);
                server_close(pcb);
        } else
        {
                printf("\nserver_recv(): Errors-> ");
                if (err != ERR_OK)
         
                printf("1) Connection is not on ERR_OK state, but in %d state->\n", err);
         
                if (p == NULL)
                    printf("2) Pbuf pointer p is a NULL pointer->\n ");
                printf("server_recv(): Closing server-side connection...");
         
                pbuf_free(p);
                server_close(pcb);
        }
     
        return ERR_OK;
}

static err_t server_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
        LWIP_UNUSED_ARG(len);
        LWIP_UNUSED_ARG(arg);
     
        printf("\nserver_sent(): Correctly ACK'ed, closing server-side connection...\n");
     
        server_close(pcb);
     
        return ERR_OK;
}

static err_t server_poll(void *arg, struct tcp_pcb *pcb)
{
       static int counter = 1;
       LWIP_UNUSED_ARG(arg);
       LWIP_UNUSED_ARG(pcb);
    
       printf("\nserver_poll(): Call number %d\n", counter++);
    
       return ERR_OK;
}

static err_t server_err(void *arg, err_t err)
{
       LWIP_UNUSED_ARG(arg);
       LWIP_UNUSED_ARG(err);
    
       printf("\nserver_err(): Fatal error, exiting...\n");
    
       return ERR_OK;
}

*/


