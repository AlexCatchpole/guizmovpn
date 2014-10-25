//
//  tapemu.h
//  OpenVPN
//
//  Created by Guillaume Duteil on 29/06/2014.
//
//

#ifndef _TAPEMU_H_
#define _TAPEMU_H_

#include "openvpn.h"

#define TAPEMU_ARP_QUERY   0x0100
#define TAPEMU_ARP_REPLY   0x0200

#define TAPEMU_ERROR       0x00
#define TAPEMU_FOUND       0x01
#define TAPEMU_NOT_FOUND   0x02

typedef struct __attribute__((packed, aligned(1)))
{
    unsigned char ether_dest[6];
    unsigned char ether_src[6];
    uint16_t ether_type;
    
    uint16_t hardware_type;
    uint16_t protocol_type;
    
    uint8_t hardware_size;
    uint8_t protocol_size;
    
    uint16_t opcode;
    
    unsigned char sender_mac_address[6];
    uint32_t sender_ip;

    unsigned char target_mac_address[6];
    uint32_t target_ip;
}tapemu_arp;

typedef struct
{
    unsigned char ether_addr[6];
    uint32_t ip;
    bool bValid;
    uint64_t timeLastQuery;
}tapemu_arp_resolution;

typedef struct
{
    uint32_t ip;
    uint32_t netmask;
    uint32_t gateway;
}tapemu_route;

typedef struct
{
	unsigned char lladdr[6];
    
    uint32_t ip;
    uint32_t netmask;

    uint32_t remote_ip;

    tapemu_arp arp_query;
    tapemu_arp arp_reply;
    
    bool bHadARPReplyToSend;
    
    uint32_t nb_arp_resolutions;
    tapemu_arp_resolution *arp_resolutions;

    uint32_t nb_routes;
    tapemu_route *routes;
}tapemu_context;

void tapemu_init();
void tapemu_clear();
void tapemu_set_lladdr(const char *lladdr);
void tapemu_set_local_ip(uint32_t ip,uint32_t netmask);
void tapemu_set_remote_ip(uint32_t ip);
void tapemu_timer(struct context *c);

uint32_t tapemu_get_remote_ip();

void tapemu_add_route(uint32_t dest,uint32_t mask,uint32_t gateway);

int tapemu_read(int fd, uint8_t *buf, int len);
int tapemu_write(int fd, uint8_t *buf, int len);

uint64_t tapemu_timestamp();
const char * tapemu_ip_to_string(uint32_t ip);
const char * tapemu_ether_to_string(unsigned char *lladdr);

int tapemu_get_mac_address(uint32_t ip,unsigned char *ether,uint32_t *gateway_ip);
int tapemu_handle_arp(uint8_t *buf,int len);

#endif
