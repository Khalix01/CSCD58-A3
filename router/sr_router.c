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
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

int check_length(uint8_t *buf,unsigned int len);
struct sr_if* searchIP(struct sr_instance* sr, uint32_t ip);
struct sr_if* searchSubnet(struct sr_instance* sr, uint32_t ip);
void setARPHeader(struct sr_arp_hdr *hdr, struct sr_if *source, struct sr_arp_hdr *arp_hdr, unsigned short type);
void setEthHeader(struct sr_ethernet_hdr *hcr, unsigned char *dst, unsigned char *src, uint16_t type);
void setIPHeader(struct sr_ip_hdr *hdr, struct sr_ip_hdr *rec_hdr, uint32_t dst, uint32_t src); 

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
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
 *
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

    /* fill in code here */


    if (check_length(packet,len)) { //wrong length
        fprintf(stderr, "Packet is Corrupted, failed length check\n");
        return;
    }

    struct sr_ethernet_hdr *ethHeader = (struct sr_ethernet_hdr *)packet; //extract headers
    uint16_t chksum, ethProtocol = ethertype(packet); //get protocol
    struct sr_if *source_if = sr_get_interface(sr, interface);
    
    if (ethProtocol == ethertype_arp) { //If ARP
        uint8_t *frame = packet+sizeof(sr_ethernet_hdr_t);
        struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr *)(frame);
        struct sr_if *target_interface=searchIP(sr,arp_hdr->ar_tip);

        if(target_interface!=NULL){ /*if its an handels interface */
            if (ntohs(arp_hdr->ar_op) == arp_op_request) { //if its a request
                //send a reply
                
                struct arp_packet *sr_arp_send_hdr = (struct arp_packet *)malloc(sizeof(struct arp_packet));
                sr_arp_send_hdr -> arp_hdr = (struct sr_arp_hdr *)malloc(sizeof(struct sr_arp_hdr));
                sr_arp_send_hdr -> eth_hdr = (struct sr_eth_hdr *)malloc(sizeof(sr_ethernet_hdr_t));
                setARPHeader(sr_arp_send_hdr->arp_hdr, target_interface, arp_hdr, arp_op_reply);
                setEthHeader(sr_arp_send_hdr->eth_hdr, ethHeader->ether_shost, target_interface->addr, ethHeader->ether_type); //ethertype(ethHeader->ether_type) arp_hdr->ar_sha

                sr_send_arp(sr, sr_arp_send_hdr, len, interface);
            }
            else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {//if it is a reply
                struct sr_arpreq *arpreq = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, ntohl(arp_hdr->ar_sip));// insert into cache
                if (arpreq) {//send all packets on the req->packets linked list
                    for (struct sr_packet *pkt=arpreq->packets; pkt != NULL; pkt=pkt->next) {
                        setEthHeader((struct sr_ethernet_hdr *)pkt->buf, arp_hdr->ar_sha, target_interface->addr, ethHeader->ether_type);
                        sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
                    }
                    sr_arpreq_destroy(&(sr->cache), arpreq);
                }
            }
        }
    }

    else if (ethProtocol == ethertype_ip) {//if IP
        uint8_t *frame = packet+sizeof(sr_ethernet_hdr_t);
        struct sr_ip_hdr *ip_hdr = (struct sr_ip_hd *)frame;
        struct sr_if *target_interface=searchIP(sr,ip_hdr->ip_dst); //check if the IP is one of our interfaces

        chksum = ip_hdr->ip_sum;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        if (chksum != ip_hdr->ip_sum) { //incorrect checksum
          fprintf(stderr, "Incorrect IP header checksum\n");
          return;
        }

        if (target_interface!=NULL) { //the target is one of our interfaces
            int protocol = ip_protocol(frame); //get the ip protocol
            if (protocol == ip_protocol_icmp) { //if it is ICMP handle it

                struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr *)(frame+sizeof(sr_ip_hdr_t)); ///get icmp header
                if (icmp_hdr->icmp_type != (uint8_t) 8) {
                    fprintf(stderr, "Not a ICMP echo\n");
                    return;
                }//not sure what to put for source
                
                chksum = icmp_hdr->icmp_sum;
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
                if (chksum != icmp_hdr->icmp_sum) {
                  fprintf(stderr, "Incorrect ICMP checksum\n");
                  return;
                }

                sendICMPHeader(sr, target_interface, source_if, ip_hdr, 0, 0, interface, ethHeader, len);
            }
            else if (protocol == ip_protocol_tcp || protocol == ip_protocol_udp) { // if its TCP or UDP, send an ICMP unreachable type3 code3
                sendICMPHeader3(sr, target_interface, source_if, ip_hdr, 3, interface, ethHeader, len);
            }
        } else { //if not handled by our interfaces, forward the packet
            ip_hdr->ip_ttl--; // decraease TTL and recompute checksum
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
            if (ip_hdr->ip_ttl < 0) {//if TTL has run out
                sendICMPHeader(sr, target_interface, source_if, ip_hdr, 11, 0, interface, ethHeader, len);
            } else{ //else forwad the packet
                struct sr_if* target_interface = searchSubnet(sr, ip_hdr->ip_dst); //USE LPM to find subnet
                if (target_interface !=NULL) { //it is a handled interface                    
                    struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ntohl(ip_hdr->ip_dst)); //find corrosponding ARP entry
                    if (entry) { //if found forward the packet
                        setEthHeader(ethHeader,entry->mac,target_interface->addr,ethHeader->ether_type);
                        sr_send_packet(sr, packet, len, target_interface->name);
                        free(entry);
                    }
                    else { //else, add to queue
                        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), ntohl(ip_hdr->ip_dst), packet, len, target_interface->name);
                        handle_arpreq(sr, req);
                    }
                  
                }
                else {
                    //send ICMP type 3 code 0 since its not a handled interface
                    sendICMPHeader3(sr, target_interface, source_if, ip_hdr, 0, interface, ethHeader, len);
                }
            }
        }
    }

}/* end sr_ForwardPacket */

/* Set Ethernet Header given a pointer to the Ethernet header, values or dst and src, and the type */
void setEthHeader(struct sr_ethernet_hdr *hdr, unsigned char *dst, unsigned char *src, uint16_t type) {
    fflush(stdout);
    memcpy(hdr->ether_dhost, dst, ETHER_ADDR_LEN);
    memcpy(hdr->ether_shost, src, ETHER_ADDR_LEN);
    hdr->ether_type = type;
}

/* Set ARP Header given a pointer to the ARP header, pointer to source interface, pointer to the received ARP header, and the operation type */
void setARPHeader(struct sr_arp_hdr *hdr, struct sr_if *source, struct sr_arp_hdr *arp_hdr, unsigned short type) {
    memcpy(hdr, arp_hdr, sizeof(sr_arp_hdr_t));

    fflush(stdout);
    hdr->ar_op = htons(type);
    memcpy(hdr->ar_sha, source->addr, ETHER_ADDR_LEN);
    hdr->ar_sip = source->ip;
    memcpy(hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    hdr->ar_tip = arp_hdr->ar_sip;
}

/* Set IP Header given a pointer to the IP Header, pointer to received IP header, and values of destination and src */
void setIPHeader(struct sr_ip_hdr *hdr, struct sr_ip_hdr* rec_hdr, uint32_t dst, uint32_t src) {
    memcpy(hdr, rec_hdr, sizeof(struct sr_ip_hdr));
    hdr->ip_src = src;
    hdr->ip_dst = dst;
    hdr->ip_sum = 0;
    hdr->ip_ttl = 100;
    hdr->ip_sum = cksum(hdr, sizeof(sr_ip_hdr_t));
}

void setICMPHeader(struct sr_icmp_hdr *icmp_hdr, uint8_t icmp_type, uint8_t icmp_code, unsigned int len) {
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
}

void setICMPHeader3(struct sr_icmp_t3_hdr *icmp_hdr, uint8_t icmp_type, uint8_t icmp_code, unsigned int len) {
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
}

void sendICMPHeader(struct sr_instance* sr, struct sr_if *target_interface, struct sr_if* source_if, 
        struct sr_ip_hdr *ip_hdr, uint8_t icmp_type, uint8_t icmp_code, const char* interface, struct sr_ethernet_hdr* ethHdr, unsigned int len) {
    struct icmp_packet *icmp_pack = (struct icmp_packet *)malloc(sizeof(struct icmp_packet));
    icmp_pack->eth_hdr = (struct sr_ethernet_hdr *)malloc(sizeof(struct sr_ethernet_hdr));
    icmp_pack->ip_hdr = (struct sr_ip_hdr *)malloc(sizeof(struct sr_ip_hdr));
    icmp_pack->icmp_hdr = (struct sr_icmp_hdr *)malloc(sizeof(struct sr_icmp_hdr));
    unsigned long icmp_len = sizeof(struct sr_icmp_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr);
    setEthHeader(icmp_pack->eth_hdr, ethHdr->ether_shost, source_if->addr, ethHdr->ether_type);
    setIPHeader(icmp_pack->ip_hdr, ip_hdr, ip_hdr->ip_src, ip_hdr->ip_dst);
    setICMPHeader(icmp_pack->icmp_hdr, icmp_type, icmp_code, len);

    //Issues with sending, hence we print it.
    print_hdr_eth(icmp_pack->eth_hdr);
    print_hdr_ip(icmp_pack->ip_hdr);
    print_hdr_icmp(icmp_pack->icmp_hdr);

    fflush(stdout);

    //attempt to send
    sr_send_icmp(sr, icmp_pack, icmp_len, interface);
}

void sendICMPHeader3(struct sr_instance* sr, struct sr_if *target_interface, struct sr_if* source_if, 
        struct sr_ip_hdr *ip_hdr, uint8_t icmp_code, const char* interface, struct sr_ethernet_hdr* ethHdr, int len) {
    struct icmp_packet3 *icmp_pack3 = (struct icmp_packet3 *)malloc(sizeof(struct icmp_packet3));
    icmp_pack3->eth_hdr = (struct sr_ethernet_hdr *)malloc(sizeof(struct sr_ethernet_hdr));
    icmp_pack3->ip_hdr = (struct sr_ip_hdr *)malloc(sizeof(struct sr_ip_hdr));
    icmp_pack3->icmp_hdr = (struct sr_icmp_t3_hdr *)malloc(sizeof(struct sr_icmp_t3_hdr));
    unsigned long icmp_len3 = sizeof(struct icmp_packet3);
    
    setEthHeader(icmp_pack3->eth_hdr, ethHdr->ether_shost, source_if->addr, ethertype_ip);
    setIPHeader(icmp_pack3->ip_hdr, ip_hdr, ip_hdr->ip_src, source_if->ip); //->ip_src, ip_hdr->ip_dst, ip_protocol_icmp);
    setICMPHeader3(icmp_pack3->icmp_hdr, 3, icmp_code, len);

    //Issues with sending, hence we print it
    print_hdr_eth(icmp_pack3->eth_hdr);
    print_hdr_ip(icmp_pack3->ip_hdr);
    print_hdr_icmp(icmp_pack3->icmp_hdr);
    
    fflush(stdout);

    //Attempt to send
    sr_send_icmp3(sr, icmp_pack3, icmp_len3, interface);
}

struct sr_if* searchIP(struct sr_instance* sr, uint32_t ip) {
    for (struct sr_if *interface = sr->if_list; interface!=NULL; interface = interface->next){
        if (interface->ip == ip)return interface;    
    }
    return NULL;
}

struct sr_if* searchSubnet(struct sr_instance* sr, uint32_t ip) {    
    struct sr_rt *match = NULL;
    int longest_mask = 0;
    for (struct sr_rt *subnet = sr->routing_table; subnet!=NULL; subnet = subnet->next){
        if (ntohl(subnet->gw.s_addr) == (ntohl(ip) & subnet->mask.s_addr)) { //check if it is in subnet
            if (longest_mask < subnet->mask.s_addr) { //is it the biggest match
                longest_mask = subnet->mask.s_addr;
                match = subnet;
            }
        }
    }
    return match != NULL ? sr_get_interface(sr, match->interface) : NULL;                       
}

int check_length(uint8_t *buf, unsigned int len){ 
    // returns 0 if the lenth is as expected, 1 otherwise.
    // this is done so data curruption (ie the return being changed to non-zero)
    // functions as expect when we do `(!check_length)`
    // tl;dr !check_length(...)is true iff buff is the expected length
    int min = sizeof(sr_ethernet_hdr_t);

    uint16_t type = ethertype(buf);
    if (len < min) return 1;

    if (type == ethertype_ip) { //if its an ip packet
        min += sizeof(sr_ip_hdr_t);
        if (len < min) return 1;

        if (ip_protocol(buf + sizeof(sr_ethernet_hdr_t)) == ip_protocol_icmp) { //checking if its a ICMP ping
            min += sizeof(sr_icmp_hdr_t);
            if (len < min) return 1;
        }
    }
    else if (type == ethertype_arp) { //if its an arp packet
        min += sizeof(sr_arp_hdr_t);
        if (len < min) return 1;
    }
    else return 1; //if its an unhandled packet
    return 0;
}