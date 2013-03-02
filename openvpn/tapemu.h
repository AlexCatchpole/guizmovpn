/*
 *  tapemu - TAP device emulation based on tunemu
 */

#ifndef TAPEMU_H
#define TAPEMU_H
#include "interval.h"

#define TUNEMU_TAP	1

#define NB_ARP		300
#define NB_ROUTES	32

int tapemu_read(int fd, char *buffer, int length);
int tapemu_write(int fd, char *buffer, int length);

void tapemu_init();
void tapemu_init_ppp_inject(char *devicename);
int tapemu_inject(char *buffer,unsigned short size);
bool tapemu_has_ip();

void tapemu_close();
void tapemu_set_lladdr(char *lladdr);

void tapemu_init_multicast();

unsigned char tapemu_has_data();
void tapemu_generate_mac_addr();
void tapemu_set_lladdr(char *address);
void tapemu_get_lladdr(char *address);

void tapemu_set_ip_local(char *address,char *mask);
void tapemu_set_ip_local_long(long ip,long mask);
long tapemu_get_ip_local();
void tapemu_get_ip6_local(unsigned char *ip6);
long tapemu_get_ip_remote();

unsigned char bIsLocalNetIP(long ip);
unsigned char bIsBroadcastIP(long ip);
unsigned char bIsMulticastIP(long ip);

unsigned short tapemu_ip_checksum(unsigned short *data, int size);

bool tapemu_is_ppp_inject();

void tapemu_add_route(long dest,long mask,long gateway);
void tapemu_add_route2(long dest,long mask,long gateway,bool bFromDHCP);
void tapemu_del_dhcp_routes();

struct tapemu_info_struct
{
	unsigned char ether_addr_broadcast[6];
	unsigned char ether_addr_local[6];
    
	long ip_local;
	long mask_local;
	long ip_remote;
	unsigned char ip6_addr_local[16];
	
	unsigned char bHasDataToSend;
	unsigned char ARP_buffer[42];
    
    char mdns_name[64];
};

#define ARP_UNKNOWN				0
#define ARP_REQUESTING			1
#define ARP_RECEIVED			2

struct ARP_struct
{
	unsigned char status;
	long ip;
	unsigned char ether_addr[6];
	struct event_timeout request;
};

struct tapemu_routes_struct
{
	unsigned char bValid;
	unsigned char bFromDHCP;
	long dest;
	long mask;
	long gateway;
};


#endif
