/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

uint16_t ARP_REP = 2;
uint16_t ARP_REQ = 1;        
uint16_t IP_ARP = 2054;
uint8_t IP_ICMP = 1; /* IP TYPE OF ICMP */
uint8_t IP_TCP = 6;
uint8_t IP_UDP = 17;
uint8_t MAC_BROADCAST[ETHER_ADDR_LEN] =   {255, 255, 255, 255, 255, 255};


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
 void sr_init(struct sr_instance* sr){
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));
    
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 
 *---------------------------------------------------------------------*/
 void sr_handlepacket(struct sr_instance* sr,
                      uint8_t * packet/* lent */,
                      unsigned int len,
                      char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /* we can assume the packet is correct */
    switch(ethertype(packet)){

        case ethertype_ip :
        printf("ip packet received\n");
        handle_ip_packet(sr, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
        break;

        case ethertype_arp :
        handle_arp_packet(sr, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
        break;

        default :
        printf("unsupported or bad packet type\n");
    }
}/* end sr_ForwardPacket */

/*-----------------------------------------------------------------------------
  handle_ip_packet

  sr: a pointer to the current router instance
  packet: a buffer pointing to the first byte in an IP packet
  interface: the name of the interface the packet was received on.

  handles ALL incoming ip packets.
-----------------------------------------------------------------------------*/
void handle_ip_packet(struct sr_instance* sr,
                      uint8_t * packet/* unchanged/lent */,
                      unsigned int len,
                      char* interface/* lent */)
{
    struct sr_ip_hdr *ippacket = malloc(len);
    memcpy(ippacket, packet, len);

    fprintf(stderr, "type: %d", ippacket->ip_p);

    /*---------------checksum----------------------*/
    sr_ip_hdr_t* check_hdr = malloc(sizeof(sr_ip_hdr_t));
    if(!check_hdr){
        fprintf(stderr, "malloc error in checksum\n");
        return;
    }
    memcpy(check_hdr, ippacket, sizeof(sr_ip_hdr_t));
    check_hdr->ip_sum = 0;
    uint16_t checksum = cksum(check_hdr, sizeof(sr_ip_hdr_t));
    free(check_hdr);
    if(checksum != ippacket->ip_sum){ printf("IP checksum incorrect; packet dropped\n");return;}


    /*-------------check ip minimum len---------------*/
    if(ippacket->ip_len<sizeof(struct sr_ip_hdr)){
        fprintf(stderr , "IP packet is way too short \n");
        return;
    }

    if(sr->nat_enabled){   
        if (ippacket->ip_p == IP_ICMP){
          if(strcmp(interface, "eth1") == 0) {
            
            /*destination is me */ 
            if (find_interface(sr,ippacket->ip_dst)) {  
              fprintf(stderr, "ICMP request!\n");
              handle_ip_icmp(sr, (uint8_t *) ippacket);
            
            /*receive on eth1 but destination is not me: ping server or others outside NAT*/ /*OR it want to be routed within NAT */
            }else{ 
              struct sr_rt *next_rt = rt_lpm(sr, ippacket->ip_dst); 
              if(!next_rt){
                 fprintf(stderr, "something went wrong! could not find interface for echo reply\n");
                 return;
              }
              struct sr_if* nxiface = sr_get_interface(sr, next_rt->interface);
              if(!nxiface){fprintf(stderr, "somethign went wrong! couldnt find iface for echo reply\n"); return;}
              
              if(strcmp(nxiface->name, "eth1") == 0){ /*no attempt to get out NAT, we dont need to modify it and just forward it*/
                if ((ippacket->ip_ttl -= 1) <= 0) { 
                  send_icmp_t3t11(sr, (uint8_t*) ippacket, len, 11, 0); return;
                
                }else{
                  ippacket->ip_sum = 0;
                  ippacket->ip_sum = cksum(ippacket, sizeof(sr_ip_hdr_t)); /*since ttl--, so recompute checksum*/
                  send_ip_packet(sr,ippacket,len);
                }
              
              }else if (strcmp(nxiface->name, "eth2") == 0){
                sr_icmp_hdr_t* icmp_hder = (sr_icmp_hdr_t *) (ippacket + sizeof(sr_ip_hdr_t));
                if(icmp_hder->icmp_type == 8 || icmp_hder->icmp_type == 0){ /*echo reply or echo request to be sent out */
                  sr_nat_mapping_t *mapresult = sr_nat_lookup_internal(&(sr->nat), ippacket->ip_src, icmp_hder->icmp_id, nat_mapping_icmp);/*i added icmp_id to struct icmp_hdr*/
                  if (mapresult == NULL) { /*cannot find the mapping, need to insert*/
                      mapresult = sr_nat_insert_mapping(&(sr->nat), ippacket->ip_src, icmp_hder->icmp_id, nat_mapping_icmp);
                      mapresult->ip_ext = (sr_get_interface(sr, nxiface->name))->ip;
                  }
                  /*mapresult->last_updated = time(NULL);*/
                  nat_handle_outbound_icmp(sr, mapresult, ippacket, len);
                  free(mapresult);
                }
              }
            }
          }
          else if(strcmp(interface, "eth2") == 0) { 
            /* compute checksum */
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *) ((uint8_t*) ippacket + sizeof(sr_ip_hdr_t));
            size_t iphdr_bytelen = ippacket->ip_hl * 4;
            uint16_t icmp_len =  ntohs(ippacket->ip_len) - iphdr_bytelen;
            if(!icmp_checksum(icmp_hdr, icmp_len)){
              return;
            }

            if (!find_interface(sr,ippacket->ip_dst)) {  /*destination is not me*/
              /*we do longest match to find the outgoing interface*/
              struct sr_rt *next_rt = rt_lpm(sr, ippacket->ip_dst); 
              if(!next_rt){
                 fprintf(stderr, "something went wrong! could not find interface for echo reply\n");
                 return;
              }

              struct sr_if* nxiface = sr_get_interface(sr, next_rt->interface);
              if(!nxiface){fprintf(stderr, "somethign went wrong! couldnt find iface for echo reply\n"); return;}
              if(strcmp(nxiface->name, "eth2") == 0){ /*no attempt to get into NAT, wedont need to modify it and just forward it*/
                if ((ippacket->ip_ttl -= 1) <= 0) { 
                  send_icmp_t3t11(sr, (uint8_t*) ippacket, len, 11, 0); return;
                }else{
                  ippacket->ip_sum = 0;
                  ippacket->ip_sum = cksum(ippacket, sizeof(sr_ip_hdr_t));
                  send_ip_packet(sr,ippacket,len);
                }
              }else{ 
                fprintf(stderr,"Unsolicid inbound ICMP packet received attempting to send to internal IP. Drop it");
                /*do we need to sent some icmp unreachable here????*/
                return;
              }
            }
            
            else { /*inbound packet & destination is me*/
              /*struct sr_if* inface = sr_get_interface(sr, interface); first we need to find which interface is the dest.ip */
              /*if(!inface){fprintf(stderr, "somethign went wrong! couldnt find iface for echo reply\n"); return;}*/
              
              if(ippacket->ip_dst == sr_get_interface(sr, "eth1")->ip) { /*cannot happen *bad attempt to get into NAT*/ /*NOT SURE usage correct or not*/
                fprintf(stderr,"Unsolicited inbound ICMP packet received attempting to send to internal IP. Drop it");
                /*do we need to sent some icmp unreachable here????*/
                return;
              }else {/*dest.ip is eth2*/
               /*echo request/reply attempting to send in NAT*/
                struct sr_nat_mapping *mapresult = sr_nat_lookup_external(&(sr->nat), icmp_hdr->icmp_id, nat_mapping_icmp);
                if (mapresult) { /*we can find the mapping of this ip,port pair (already existed)*/
                    fprintf(stderr,"got the mapping associated with this pair");
                    /*then, we need to modify this packet's header using this mapping*/
                    /*mapresult->last_updated = time(NULL); /*correct????*/
                    nat_handle_inbound_icmp(sr, mapresult, ippacket, len);
                    free(mapresult);
                }
                else { /*cannot find the mapping, */
                  if(icmp_hdr->icmp_type == 0){ /*reply*/
                      fprintf(stderr,"since router wouldn't ping others, there shouldn't be echo reply to router itself.we should drop it");
                      return;
                  }else if(icmp_hdr->icmp_type == 8){ /*request,couldn't find mapping,so assume sth outside nat is pinging eth2*/ 
                      handle_ip_icmp(sr, (uint8_t *) ippacket); /*we just send an echo reply back*/
                  }
                }
              }
            }
          }
        }
    }else{
      /*---------------check if it's for me------------*/
      if (find_interface(sr,ippacket->ip_dst)) {

          if (ippacket->ip_p == IP_ICMP){
              fprintf(stderr, "ICMP request!\n");
              handle_ip_icmp(sr, (uint8_t *) ippacket);
          }
          /*-------------check TCP/UDP---------------*/
          else if (ippacket->ip_p == IP_UDP || ippacket->ip_p == IP_TCP) {   /*17--UDP,6--TCP*/
              fprintf(stderr, "TCP/UDP");
              send_icmp_t3t11(sr, (uint8_t *) ippacket, len, 3, 3);

          /* set back to original value; to be included in data portion of ICMP message*/

          }

      } else{            /*//to be forwarded*/
          fprintf(stderr, "packet needs to be forwarded\n");
          /*---------------check TTL----------------------*/
          if ((ippacket->ip_ttl -= 1) <= 0) {  
              /* sends type 11 icmp */
              send_icmp_t3t11(sr, (uint8_t*) ippacket, len, 11, 0);
              fprintf(stderr, "ttl = 0\n");
              return;
          }else{
              ippacket->ip_sum = 0;
              ippacket->ip_sum = cksum(ippacket, sizeof(sr_ip_hdr_t));
              send_ip_packet(sr,(uint8_t *) ippacket, len);
          }
      }
    }
    free(ippacket);
}

/*-----------------------------------------------------------------------------
  Method: icmp_checksum

  computes checksum of ip packet. 1 on success, 0 on failue
-----------------------------------------------------------------------------*/
int icmp_checksum(sr_icmp_hdr_t* icmp_hdr, uint16_t icmp_len){
  sr_icmp_hdr_t* check_hdr = malloc(icmp_len);
    if(!check_hdr){
       fprintf(stderr, "malloc error in checksum\n");
       return;
  }

  memcpy(check_hdr, icmp_hdr, icmp_len);
  check_hdr->icmp_sum = 0;
  uint16_t checksum = cksum(check_hdr,icmp_len);
  free(check_hdr);
  if (checksum == icmp_hdr){ return 1;} else { return 0;}
  
}
/*-----------------------------------------------------------------------------
   Method: handle_ip_icmp

   sr: router state
   ip_packet: a pointer to an IP packet whos payload is an ICMP packet.
   interface: the name of the interface packet was received on

   handles all ICMP requests sent to us.
-----------------------------------------------------------------------------*/
void handle_ip_icmp(struct sr_instance* sr, 
                    uint8_t* ip_packet)
{
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) ip_packet;
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *) (ip_packet + sizeof(sr_ip_hdr_t));
    size_t iphdr_bytelen = ip_header->ip_hl * 4;
    uint16_t icmp_len =  ntohs(ip_header->ip_len) - iphdr_bytelen;
    
    int checksum = icmp_checksum(icmp_hdr, icmp_len);
    if(!checksum){ 
        printf("ICMP checksum incorrect, expected %d, computed: %d; packet dropped\n", icmp_hdr->icmp_sum, checksum);
        return;
    }

    if(icmp_hdr->icmp_type == 8){
        fprintf(stderr, "received echo request\n ");
        send_icmp_echo(sr, (uint8_t*) ip_header, ntohs(ip_header->ip_len));

    } else {
        fprintf(stderr, "unsupprted ICMP type received , ignoring\n ");
    }
}


/*-----------------------------------------------------------------------------
   Method: handle_icmp_echo

   sr: router state
   ip_packet: a pointer to an IP packet whos payload is an ICMP request.
   interface: the name of the interface packet was received on

   handles all incoming ICMP echo requests.
-----------------------------------------------------------------------------*/
 void send_icmp_echo(struct sr_instance* sr, uint8_t* packet, uint16_t len)
{
      sr_ip_hdr_t *ip_header = malloc(len);
      memcpy(ip_header, packet, len);

  /* ---------------CONSTRUCTING IP HEADER--------------------*/
    struct sr_rt *rt = rt_lpm(sr, ip_header->ip_src);
    if(!rt){
        fprintf(stderr, "something went wrong! could not find interface for echo reply\n");
        return;
    } 

    struct sr_if* iface = sr_get_interface(sr, rt->interface);
    if(!iface){fprintf(stderr, "somethign went wrong! couldnt find iface for echo reply\n"); return;}
    uint32_t new_source = ip_header->ip_dst;
    uint32_t new_dst = ip_header->ip_src;
    ip_header->ip_dst = new_dst;
    ip_header->ip_src = new_source;
    /* compute checksum */
    ip_header->ip_ttl = 100;
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
  

  /* -------------------CONSTRUCTING ICMP ECHO HEADER-----------*/
    size_t iphdr_bytelen = ip_header->ip_hl * 4;
    uint16_t icmp_len =  ntohs(ip_header->ip_len) - iphdr_bytelen;
    sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) ((uint8_t *) ip_header + sizeof(sr_ip_hdr_t));

    icmp_header->icmp_type = 0;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum(icmp_header,icmp_len);


  /* -----------------------------------------------------------*/
    send_ip_packet(sr, (uint8_t *) ip_header, len);
    free(ip_header);
}

/*-----------------------------------------------------------------------------
   Method: send_icmp

   sr: router state
   packet: a pointer to an IP packet whose dest is unreachable
   len: length of packet
   code: type of icmp unreachable

   handles all incoming ICMP echo requests.
-----------------------------------------------------------------------------*/
void send_icmp_t3t11(struct sr_instance* sr, 
                  uint8_t* packet, 
                  uint16_t len,  
                  uint8_t type, 
                  uint8_t code)
   {
      uint16_t new_length = (uint16_t) sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
      sr_ip_hdr_t *ip_header = malloc(new_length);
    
    /* just to save the trouble of header length, version etc */
      if(type == 3 && code == 1){
	memcpy(ip_header, (packet+sizeof(sr_ethernet_hdr_t)), sizeof(sr_ip_hdr_t));
      }else{
      memcpy(ip_header, packet, sizeof(sr_ip_hdr_t));
      }
    /* ---------------CONSTRUCTING IP HEADER--------------------*/
    struct sr_rt *rt = rt_lpm(sr, ip_header->ip_src);
    if(!rt){
        fprintf(stderr, "something went wrong! could not find interface for echo reply\n");
        return;
    }
    struct sr_if* iface = sr_get_interface(sr, rt->interface);
    if(!iface){fprintf(stderr, "somethign went wrong! couldnt find iface for echo reply\n"); return;}
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(new_length);
    ip_header->ip_id = 0;
    ip_header->ip_off = htons(IP_DF);
    
    /*if(type == 3 && code == 3){*/
    /*uint32_t new_source = ip_header->ip_dst;*/
      /*ip_header->ip_dst = ip_header->ip_src;*/
      /* ip_header->ip_src = new_source;*/
      /* }else {*/
 
      /* }*/
    uint32_t host_dst = ip_header->ip_dst;
    ip_header->ip_dst = ip_header->ip_src;
    /*for source_ip, we need to treat differently of host and net&port unreachable*/
    if(type == 3 && code == 1){ /* if it is host unreachable, src_ip is the interface we are trying to reach with the initial packet (according to given solution)*/
    fprintf(stderr, "hoooooooooooooooooooooooooooooost\n");
    struct sr_rt *rt_host = rt_lpm(sr, host_dst);
    if(!rt_host){
        fprintf(stderr, "something went wrong! could not find interface for echo reply\n");
        return;
    }
    struct sr_if* iface_host = sr_get_interface(sr, rt_host->interface);
    if(!iface_host) {fprintf(stderr, "somethign went wrong! couldnt find iface for echo reply\n"); return;}
    print_addr_ip_int(ntohl(iface_host->ip)); 
    ip_header->ip_src = iface_host->ip; 

    }
    else if (type == 3 && code == 3)
    {
		ip_header->ip_src = host_dst;
	}
	else
	{
		ip_header->ip_src = iface->ip;
    
    }
    
 

    ip_header->ip_p = ip_protocol_icmp;
    /* compute checksum */
    ip_header->ip_ttl = 100; /* as used in solution */
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

    /* -------------------CONSTRUCTING ICMP ECHO HEADER-----------*/
    sr_icmp_t3_hdr_t *icmp_header = ((uint8_t *) ip_header + sizeof(sr_ip_hdr_t));

    icmp_header->icmp_type = type;
    icmp_header->icmp_code = code;
    icmp_header->icmp_sum = 0;
    icmp_header->unused = 0;
    icmp_header->next_mtu = 0;
    if(type == 3 && code == 1){
    memcpy(icmp_header->data, (packet+sizeof(sr_ethernet_hdr_t)), ICMP_DATA_SIZE);
    }else {
    memcpy(icmp_header->data, packet, ICMP_DATA_SIZE);}

    icmp_header->icmp_sum = cksum(icmp_header,sizeof(sr_icmp_t3_hdr_t));
    /* -----------------------------------------------------------*/

    send_ip_packet(sr, (uint8_t *) ip_header, new_length);
    free(ip_header);
}


/*-----------------------------------------------------------

  send_ip_packet

  packet: pointer to first byte of a fully constructed 
          ethernet packet.
  len: length of ip packet

  handles converting destination IP to mac, and adding to 
  queue if needed, etc.

  Copies buf.

  assumes TTL is >= 0, 
-----------------------------------------------------------*/
void send_ip_packet(struct sr_instance* sr,
                    uint8_t *buf, 
                    unsigned int len)
{


    /*---------copy packet, add space for ethernet header---*/ 
    uint8_t *new_buf = malloc(len + sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t *eth_head = (sr_ethernet_hdr_t *) new_buf;

    sr_ip_hdr_t *packet = (sr_ip_hdr_t *) (new_buf+sizeof(sr_ethernet_hdr_t));
    memcpy(packet, buf, len);

    /*------------check routing table----------*/
    uint32_t dstip = packet->ip_dst;
    struct sr_rt *nexthop_rt = rt_lpm(sr, dstip);
    if (!nexthop_rt){
        fprintf(stderr, "This packet's IP doesn't match any dest. of the routing table, we should ignore this packet.");
        send_icmp_t3t11(sr, (uint8_t *) packet, len, 3, 0);
        /*send icmp & just throw this packet*/
        return;/* or exit? */
    } 

    struct sr_if *send_if;
    if (!(send_if = sr_get_interface(sr, nexthop_rt->interface))) {
        fprintf(stderr, "interface not found!!");
        return;
    }
    /*-----------fill in sending address and type---------------*/

    memcpy(eth_head->ether_shost, send_if->addr, ETHER_ADDR_LEN);
    eth_head->ether_type = htons(ethertype_ip);
    print_hdr_eth( (uint8_t *) eth_head);
    
    /*------------check arp cache-------------------*/
    uint32_t nexthop = (nexthop_rt->gw).s_addr;
    struct sr_arpentry *cacheresult = sr_arpcache_lookup(&(sr->cache), nexthop);
    
    if (cacheresult) { /* IP in ARP entry*/
        fprintf(stderr, "found entry in arp cache\n");
        memcpy(eth_head->ether_dhost, cacheresult->mac, ETHER_ADDR_LEN);
        if (sr_send_packet(sr, new_buf, len + sizeof(sr_ethernet_hdr_t), send_if->name)){
            fprintf(stderr, "Packet forwarding failed\n");
        }
        free(cacheresult);
    } 

    else {   /* not in ARP entry: handle arpreq*/
        fprintf(stderr, "could not find in arpcache, adding to queue\n" );
        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), 
                                                     nexthop, 
                                                     new_buf, 
                                                     len + sizeof(sr_ethernet_hdr_t), 
                                                     nexthop_rt->interface);
        /* queuereq copies the packet given to it*/
        free(new_buf);
        handle_arpreq(sr, req);
    }             
}
/*-----------------------------------------------------------------------------
   Method: handle_arp_packet

   sr: router state
   packet: a buffer pointing to the first byte in an arp packet
   interface: the name of the interface packet was received on

   handles incoming  arp replies and requests.
-----------------------------------------------------------------------------*/
void handle_arp_packet(struct sr_instance* sr,
                       uint8_t * packet/* lent */,
                       unsigned int len,
                       char* interface/* lent */)
{
    sr_arp_hdr_t* arp_struct = (sr_arp_hdr_t *) packet;

    struct sr_if* iface = sr_get_interface(sr, interface);

    if(arp_struct->ar_op == htons(arp_op_request)){
        printf("received ARP request:\n");
        if(arp_struct->ar_tip == iface->ip){
            send_arp_reply(sr, arp_struct, iface);
        }

    } else if ( arp_struct->ar_op == htons(arp_op_reply)){
        printf("received ARP reply:\n");
        if(iface->ip == arp_struct->ar_tip){
            handle_arp_reply(sr, arp_struct);
        } else {
            fprintf(stderr, "ignoring\n");
        }

    }  else {
        printf("unknown\n");
    }
}

/*-----------------------------------------------------------------------------
  handle_arp_reply

  sr: router instance
  arp_struct: a struct containing the received arp reply

  handles all  incoming arp replies.
  # When servicing an arp reply that gives us an IP->MAC mapping
  req = arpcache_insert(ip, mac)

   if req:
       send all packets on the req->packets linked list
       arpreq_destroy(req)
-----------------------------------------------------------------------------*/
void handle_arp_reply(struct sr_instance* sr, 
                      sr_arp_hdr_t* arp_struct)
{    
    uint8_t* dest_mac = arp_struct->ar_sha;
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), dest_mac, arp_struct->ar_sip);

    if(req){
        struct sr_packet* cur_packet = req->packets;
        while(cur_packet){
            struct sr_if* sending_interface = sr_get_interface(sr, cur_packet->iface);
            if(sending_interface){
                memcpy(cur_packet->buf, dest_mac, ETHER_ADDR_LEN);/* add dest address */
                fprintf(stderr,  "sending out packet:");

                if(sr_send_packet(sr, cur_packet->buf, cur_packet->len, sending_interface->name) != 0){
                    fprintf(stderr, "could not send packet\n" );
                }
                cur_packet = cur_packet->next;

            } 
        }

        fprintf(stderr, "done sending out requests:\n");
        sr_arpreq_destroy(&(sr->cache),req);

    } else {
        fprintf(stderr, "could not insert, no entry found.\n");
    }
}

/*-----------------------------------------------------------------------------
  construct_arp_reply

  arp_request: original arp request
  mac: a pointer to the corresponding mac address

  send_arp reply uses this to construct and send a full ethernet packet.

  MUST BE
-----------------------------------------------------------------------------*/
sr_arp_hdr_t* construct_arp_reply(sr_arp_hdr_t* arp_request, uint8_t* mac)
  {

    sr_arp_hdr_t* arp_reply = malloc(sizeof(sr_arp_hdr_t));
    if(!arp_reply){ return NULL; }

    *arp_reply = *arp_request;
    arp_reply->ar_op = ntohs(ARP_REP);
    arp_reply->ar_sip = arp_request->ar_tip;
    arp_reply->ar_tip = arp_request->ar_sip; 
    memcpy(arp_reply->ar_sha, mac, ETHER_ADDR_LEN);
    memcpy(arp_reply->ar_tha, &(arp_request->ar_sha), ETHER_ADDR_LEN); 
    return arp_reply;
}

/*-----------------------------------------------------------------------------
  send_arp_reply

  sr: router instance
  arp_request: original arp request
  mac: a pointer to the corresponding mac address
  sending_interface: interface to send packet to.

  constructs and sends an arp reply. 1 on success, 0 on otherwise.
-----------------------------------------------------------------------------*/
int send_arp_reply( struct sr_instance* sr,
                    sr_arp_hdr_t* arp_request,
                    struct sr_if* sending_interface)
{
    sr_arp_hdr_t* arp_reply = construct_arp_reply(arp_request, &(sending_interface->addr));

    if(arp_reply){
        uint8_t* packet;
        unsigned int len = 
            construct_ethernet_packet(  &(arp_reply->ar_tha),
                                        &(sending_interface->addr), /*sent from this interface*/
                                        ntohs(IP_ARP),
                                        arp_reply,
                                        sizeof(sr_arp_hdr_t),
                                        &packet);

        if(len > 0){
            sr_send_packet(sr, packet, len, sending_interface->name);
        } else {
            printf("could not construct ethernet package\n");
            return 0;
        }
        free(arp_reply);
        free(packet);
    }
    else  { return 0; }

    return 1;
}

void nat_handle_outbound_icmp(struct sr_instance* sr, struct sr_nat_mapping* natmap, uint8_t* ip_packet, uint16_t len){
     sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) ip_packet;
     sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *) (ip_packet + sizeof(sr_ip_hdr_t));
     ip_header->ip_src = natmap->ip_ext;
     icmp_hdr->icmp_id = natmap->aux_ext;
     /* first,ttl-1;  then checksum??*/
     icmp_hdr->icmp_sum = 0;

     icmp_hdr->icmp_sum = cksum(icmp_hdr, (len - sizeof(sr_ip_hdr_t))); /*should we use sizeof(icmp_hdr) OR len-sizeof(ip_hdr)*/
     if ((ip_header->ip_ttl -= 1) <= 0) {  
            send_icmp_t3t11(sr, (uint8_t*) ip_header, len, 11, 0);
            return;
        }
     else{
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
            send_ip_packet(sr,(uint8_t *) ip_header, len);
        }
 } 
                
 
 void nat_handle_inbound_icmp(struct sr_instance* sr, struct sr_nat_mapping* natmap, uint8_t* ip_packet, uint16_t len){
    /*if it is request to sth inside nat,we modify the header using mapping and forward it*/
    /*if it is reply to sth inside nat,we also modify header and forward it*/
     sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) ip_packet;
     sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *) (ip_packet + sizeof(sr_ip_hdr_t));
     ip_header->ip_dst = natmap->ip_int;
     icmp_hdr->icmp_id = natmap->aux_int;
     /* first,ttl-1;  then checksum??*/
     icmp_hdr->icmp_sum = 0;
     icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t)); /*should we use sizeof(icmp_hdr) OR len-sizeof(ip_hdr)*/
     if ((ip_header->ip_ttl -= 1) <= 0) {  
            send_icmp_t3t11(sr, (uint8_t*) ip_header, len, 11, 0);
            return;
        }
     else{
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
            send_ip_packet(sr, (uint8_t *) ip_header, len);
        }
 }

