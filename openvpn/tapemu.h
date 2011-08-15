/*
 *  tapemu - TAP device emulation based on tunemu
 */

#ifndef TAPEMU_H
#define TAPEMU_H
#include "interval.h"

#define TUNEMU_TAP	1

#define NB_ARP		64
#define NB_ROUTES	32

int tapemu_read(int fd, char *buffer, int length);
int tapemu_write(int fd, char *buffer, int length);

void tapemu_init();
void tapemu_close();

unsigned char tapemu_has_data();
void tapemu_generate_mac_addr();
void tapemu_set_ether_addr_local(char *address);
void tapemu_set_ip_local(char *address,char *mask);
long tapemu_get_ip_remote();

unsigned char bIsLocalNetIP(long ip);
unsigned char bIsBroadcastIP(long ip);
unsigned char bIsMulticastIP(long ip);

struct tapemu_info_struct
{
	unsigned char ether_addr_broadcast[6];
	unsigned char ether_addr_local[6];
	long ip_local;
	long mask_local;
	long ip_remote;
	
	unsigned char bHasDataToSend;
	unsigned char ARP_buffer[42];
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
	long dest;
	long mask;
	long gateway;
};

struct IP_header
{
    unsigned char IP_version_hdrlength;
    unsigned char differential_service;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    long IP_src;
    long IP_dest;    
};

typedef struct 
{
    unsigned char mac_dest[6];
    unsigned char mac_source[6];
    unsigned char packet_type[2];
    char IP_hdr[20];
}multicast_packet;

typedef struct PseudoHeader{    
    unsigned long int source_ip;
    unsigned long int dest_ip;
    unsigned short protocol;
    unsigned short udp_length;
}PseudoHeader;

#endif
