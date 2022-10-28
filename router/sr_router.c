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

int check_length(uint8_t *buf,unsigned int length);
int check_checksum(sr_ip_hdr_t *ip_hdr);

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

}/* end sr_ForwardPacket */

int check_length(uint8_t *buf, unsigned int len){ 
    // returns 0 if the lenth is as expected, 1 otherwise.
    // this is done so data curruption (ie the return being changed to non-zero)
    // functions as expect when we do `(!check_length)`
    // tl;dr !ceck_length(...)is true iff buff is the expected length
    int min = sizeof(sr_ethernet_hdr_t);
    if (length < min) return 1;

    uint16_t type = ethertype(buf);
    if (type == ethertype_ip) { //if its an ip packet
        min += sizeof(sr_ip_hdr_t);
        if (length < min) return 1;

        if (ip_protocol(buf + sizeof(sr_ethernet_hdr_t)) == ip_protocol_icmp) { //checking if its a ICMP ping
            min += sizeof(sr_icmp_hdr_t);
            if (length < min) return 1;
        }
    }
    else if (type == ethertype_arp) { //if its an arp packet
        min += sizeof(sr_arp_hdr_t);
        if (length < min) return 1;
    }
    else return 1; //if its an unhandled packet
    return 0;
}

int check_checksum(sr_ip_hdr_t *ip_hdr) {
    // returns 0 iff checksum is correct, 1 other wise
    // We do this for the same reason as check_length
    if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != ip_hdr->ip_sum) return 1;
    return 0;
}