/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024
/* number of bits in an ethernet header*/
#define ETH_HEAD_SIZE 14

/* forward declare */
struct sr_if;
struct sr_rt;


/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    /*interfaces are local addresses given to specific devices (the router, and the two servers) */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
    struct sr_nat nat;
    int nat_enabled;
};


/* ----------------------------------------------------------------------------
    ether_frame

    a struct that encapsulates a type II ethernet frame.
 * -------------------------------------------------------------------------- */
struct ether_frame
{
    uint8_t* mac_dest[6]; /* destination mac address, should be 6 bytes */
    uint8_t* mac_src[6]; /* source mac address, should be 6 bytes */
    uint8_t* ethertype[2]; /* ethertype, should be 2 bytes */
    uint8_t* payload; /* payload, variable size */
    unsigned int len_payload; /*payload size*/
    uint8_t* frame_check[4]; /* */
};



/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* ------------------MADE BY US--------------------------- */
void handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */);

void handle_arp_packet(struct sr_instance*, 
                      uint8_t *, 
                      unsigned int,  
                      char* );

void handle_arp_reply(struct sr_instance* sr, 
                      sr_arp_hdr_t* arp_struct);

sr_arp_hdr_t* construct_arp_reply(sr_arp_hdr_t* arp_request, 
                                  uint8_t* mac);

int send_arp_reply(struct sr_instance* sr, 
                   sr_arp_hdr_t* arp_request, 
                   struct sr_if* sending_interface);

void handle_ip_icmp(struct sr_instance* sr, 
                    uint8_t* ip_packet);

void send_ip_packet(struct sr_instance* sr,
                    uint8_t *buf, 
                    unsigned int len);

void send_icmp_echo(struct sr_instance* sr, 
                    uint8_t* packet, 
                    uint16_t len);

void send_icmp_t3t11(struct sr_instance* sr, 
                     uint8_t* packet, 
                    uint16_t len, 
                    uint8_t type, 
                    uint8_t code);

int icmp_checksum(sr_icmp_hdr_t* icmp_hdr, uint16_t icmp_len);

/* --------------------------------------------------------*/


/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
