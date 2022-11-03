# CSCD58-A3

Names of Team members & Student Numbers: Krutik Tejalkumar Shah 1006213526, Kourosh Jaberi 1005947362

Please run our code without the -anis flag, in order to avoid errors raised by comments with // and please ignore the other warnings with implicit castings/declarations

Split of Work:
    Krutik worked on creating the foundation of what to do, ie helper functions, the layout of how we handle the incoming packets, work for when we receive ARP replies.
    Kourosh worked on creating the logic to send the packets for ICMP and for ARP requests (logic in ), as well as the function handle_arpreq().


# Description of Functions Done:

### In sr_router.c ###
//search given ip address in subnet of sr - Author: Krutik
struct sr_if* searchSubnet(struct sr_instance* sr, uint32_t ip)

//Search IP in interface list of sr - Author: Krutik
struct sr_if* searchIP(struct sr_instance* sr, uint32_t ip)

//Prints and sends ICMP headers of type3, given sr, target interface, source interface, received IP header, icmp_code, the interface, the ethernet header received, and the length - Author: Kourosh
void sendICMPHeader3(struct sr_instance* sr, struct sr_if *target_interface, struct sr_if* source_if, 
        struct sr_ip_hdr *ip_hdr, uint8_t icmp_code, const char* interface, struct sr_ethernet_hdr* ethHdr, int len)

//Prints and sends ICMP headers, given sr, target interface, source interface, received IP header, icmp_code, the interface, the ethernet header received, and the length  - Author: Kourosh
void sendICMPHeader(struct sr_instance* sr, struct sr_if *target_interface, struct sr_if* source_if, 
        struct sr_ip_hdr *ip_hdr, uint8_t icmp_type, uint8_t icmp_code, const char* interface, struct sr_ethernet_hdr* ethHdr, unsigned int len)

//Set ICMP headers for type3 responses, given type, code and length of received message - Author: Kourosh
void setICMPHeader3(struct sr_icmp_t3_hdr *icmp_hdr, uint8_t icmp_type, uint8_t icmp_code, unsigned int len) 

//Set ICMP headers responses, given type, code and length of received message - Author: Kourosh
void setICMPHeader(struct sr_icmp_hdr *icmp_hdr, uint8_t icmp_type, uint8_t icmp_code, unsigned int len)

/* Set IP Header given a pointer to the IP Header, pointer to received IP header, and values of destination and src - Author: Krutik*/ 
void setIPHeader(struct sr_ip_hdr *hdr, struct sr_ip_hdr* rec_hdr, uint32_t dst, uint32_t src)

/* Set ARP Header given a pointer to the ARP header, pointer to source interface, pointer to the received ARP header, and the operation type - Author: Krutik */
void setARPHeader(struct sr_arp_hdr *hdr, struct sr_if *source, struct sr_arp_hdr *arp_hdr, unsigned short type)

/* Set Ethernet Header given a pointer to the Ethernet header, values or dst and src, and the type - Author: Krutik*/
void setEthHeader(struct sr_ethernet_hdr *hdr, unsigned char *dst, unsigned char *src, uint16_t type)

### In sr_vns_comm.c ###
//send ARP packet given sr instance, arp packet, length of said packet, and the iface derived from original message - Author: Kourosh
int sr_send_arp(struct sr_instance* sr, struct arp_packet* arp, unsigned int len, const char* iface) 

//send type 3 ICMP packet sr instance, type3 ICMP packet, length of said packet, and the iface derived from original message  - Author: Kourosh
int sr_send_icmp3(struct sr_instance* sr, struct icmp_packet3* icmp, unsigned int len, const char* iface) 

//send ICMP packet(Not including type 3) given sr instance, type3 ICMP packet, length of said packet, and the iface derived from original message  - Author: Kourosh
int sr_send_icmp(struct sr_instance* sr, struct icmp_packet* icmp, unsigned int len, const char* iface) 

# Missed Functionality
    We are able to properly receive all requests, however we can only properly respond to ARP requests. Other requests we believe we generate the correct headers (which we print to stdout) but they do not send.
    This includes all ICMP header responses.

# Test Cases Ran:
    client ping 192.168.2.1 (Ran on mininet, ARP request is successful but ICMP response is unable to be sent properly)
    client ping 192.168.11.11 (Ran on mininet, ICMP response is unable to be sent properly)
