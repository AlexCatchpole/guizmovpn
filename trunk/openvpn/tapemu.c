/*
 *  tapemu - TAP device emulation on tunemu  
 */

#include "config.h"

#include "syshead.h"
#include "error.h"
#include "tapemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <util.h>
#include <pcap.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <stdint.h>
#include <ctype.h>
#include <fcntl.h>
#include "openvpn.h"

struct tapemu_info_struct tapemu_info;
struct ARP_struct ARP_infos[NB_ARP];
struct tapemu_routes_struct tapemu_routes[NB_ROUTES];

#define ERROR_BUFFER_SIZE 1024
extern unsigned char tunemu_mode;
char tapemu_error[ERROR_BUFFER_SIZE];

pcap_t *pcap=NULL;
static int data_buffer_length = 0;
static char *data_buffer = NULL;

#define ERROR_BUFFER_SIZE 1024
static void tap_error(char *format, ...)
{
	va_list vl;
	va_start(vl, format);
	vsnprintf(tapemu_error, ERROR_BUFFER_SIZE, format, vl);
	va_end(vl);
}

static void tap_noerror()
{
	*tapemu_error = 0;
}

void tapemu_set_pcap(pcap_t *pcap_ptr)
{
	pcap=pcap_ptr;				
}

static void allocate_data_buffer(int size)
{
	if (data_buffer_length < size)
	{
		free(data_buffer);
		data_buffer_length = size;
		data_buffer = malloc(data_buffer_length);
	}
}

// Init TAP emulation
void tapemu_init()
{
	memset(&tapemu_info.ether_addr_broadcast,0,sizeof(tapemu_info.ether_addr_broadcast));
	memset(&tapemu_info.ether_addr_local,0,sizeof(tapemu_info.ether_addr_local));
	
	memset(&tapemu_info.ARP_buffer,0,sizeof(tapemu_info.ARP_buffer));
	tapemu_info.bHasDataToSend=0;
	
	memset(&ARP_infos,0,sizeof(ARP_infos));
	memset(&tapemu_routes,0,sizeof(tapemu_routes));
	
	tapemu_generate_mac_addr();	
}

// Close
void tapemu_close()
{
}

// Generate random local MAC address, and set the broadcast MAC
void tapemu_generate_mac_addr()
{	
	// Set a random local MAC addr
	srand(time(NULL));
	long num=rand();
	
	tapemu_info.ether_addr_local[0] = 0x0a;
	tapemu_info.ether_addr_local[1] = 0x00;
	tapemu_info.ether_addr_local[2] = 0x20;
	tapemu_info.ether_addr_local[3] = (num>>24 & 0xFF);
	tapemu_info.ether_addr_local[4] = (num>>16 & 0xFF);
	tapemu_info.ether_addr_local[5] = (num>>8 & 0xFF);
	
	// Set the broadcast MAC addr
	tapemu_info.ether_addr_broadcast[0]=0xFF;
	tapemu_info.ether_addr_broadcast[1]=0xFF;
	tapemu_info.ether_addr_broadcast[2]=0xFF;
	tapemu_info.ether_addr_broadcast[3]=0xFF;
	tapemu_info.ether_addr_broadcast[4]=0xFF;
	tapemu_info.ether_addr_broadcast[5]=0xFF;
	
	msg (M_INFO,"Tapemu : Local MAC address : 0A:00:20:%.02X:%.02X:%.02X",tapemu_info.ether_addr_local[3],tapemu_info.ether_addr_local[4],tapemu_info.ether_addr_local[5]);
}

// Check if we have prepared ARP data to be sent
unsigned char tapemu_has_data()
{
	return tunemu_mode==TUNEMU_TAP && tapemu_info.bHasDataToSend;
}

// Set local IP
void tapemu_set_ip_local(char *address,char *mask)
{	
	if(address && mask)
	{
		tapemu_info.ip_local=inet_addr(address);
		tapemu_info.mask_local=inet_addr(mask);
		msg (M_INFO,"Tapemu : Received local IP : %s/%s",address,mask);
	}
}

// Set gateway IP
void tapemu_set_ip_remote(char *address)
{	
	if(address)
	{
		tapemu_info.ip_remote=inet_addr(address);
	}
}

// Get gateway IP
long tapemu_get_ip_remote()
{	
	return tapemu_info.ip_remote;
}

// Check is the destination IP is on the local subnet or if we need to forward it to a router
unsigned char bIsLocalNetIP(long ip)
{
	return (!ip) || ((ip&tapemu_info.mask_local) == (tapemu_info.ip_local&tapemu_info.mask_local));
}

// Check is the destination IP is a broadcast IP
unsigned char bIsBroadcastIP(long ip)
{
    return (((ip>>24)&0xFF) == 0xFF);
}

// Check is the destination IP is a multicast IP
unsigned char bIsMulticastIP(long ip)
{
    unsigned char IP_1=ip&0xFF;
    return (IP_1==224 || IP_1==232 || IP_1==223 || IP_1==239);
}


// Get a MAC address from an IP
unsigned char tapemu_get_mac_address(long ip,unsigned char *mac_dest)
{
	int i=0;

    // Check if the IP is multicast
    if(bIsMulticastIP(ip))
    {
        unsigned char tmp_mac[6];
        tmp_mac[0]=0x01;
        tmp_mac[1]=0x00;
        tmp_mac[2]=0x5E;
        tmp_mac[3]=(ip>>8)&0x7F;
        tmp_mac[4]=(ip>>16)&0xFF;
        tmp_mac[5]=(ip>>24)&0xFF;
        
        /*msg (M_INFO,"Tapemu : MAC address for %d.%d.%d.%d (Multicast) : %.02X:%.02X:%.02X:%.02X:%.02X:%.02X",
             ip&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF,
             tmp_mac[0],tmp_mac[1],tmp_mac[2],tmp_mac[3],tmp_mac[4],tmp_mac[5]);*/
        
        memcpy(mac_dest,tmp_mac,6);
        
        return 1;
    }
    
    // Check if the IP is broadcast (just check the last byte, incorrect, may have to change it later)
    if(bIsBroadcastIP(ip))
    {
/*        msg (M_INFO,"Tapemu : MAC address for %d.%d.%d.%d (Broadcast) : FF:FF:FF:FF:FF:FF",
             ip&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF);*/
        
        memset(mac_dest,0xFF,6);
        return 1;
    }
    
	for(i=0;i<NB_ARP;i++)
	{
		if(ARP_infos[i].status==ARP_RECEIVED &&
		   ARP_infos[i].ip == ip)
		{
			memcpy(mac_dest,ARP_infos[i].ether_addr,6);
			return 1;
		}
	}
	
	return 0;
}

// Set a received MAC address for an IP
void tapemu_set_mac_address(long ip,char *mac_addr)
{
	int i=0;
	
	for(i=0;i<NB_ARP;i++)
	{
		if(ARP_infos[i].status == ARP_UNKNOWN || ARP_infos[i].ip == ip)
		{
			if(mac_addr)
			{
				memcpy(ARP_infos[i].ether_addr,mac_addr,6);
				msg (M_INFO,"Tapemu : MAC address for %d.%d.%d.%d : %.02X:%.02X:%.02X:%.02X:%.02X:%.02X",
					 ip&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF,
					 ARP_infos[i].ether_addr[0],
					 ARP_infos[i].ether_addr[1],
					 ARP_infos[i].ether_addr[2],
					 ARP_infos[i].ether_addr[3],
					 ARP_infos[i].ether_addr[4],
					 ARP_infos[i].ether_addr[5]);
			
				ARP_infos[i].status=ARP_RECEIVED;
				ARP_infos[i].ip=ip;
			} else {
				memset(ARP_infos[i].ether_addr,0,6);
				ARP_infos[i].status=ARP_REQUESTING;
				ARP_infos[i].ip=ip;
			}
			
			return;
		}
	}
	
	// No empty slot to save MAC address, flushing...
	memset(&ARP_infos,0,sizeof(ARP_infos));
	
	// Then store the received ARP in first slot
	memcpy(ARP_infos[0].ether_addr,mac_addr,6);
	msg (M_INFO,"Tapemu : MAC address for %d.%d.%d.%d : %.02X:%.02X:%.02X:%.02X:%.02X:%.02X",
		 ip&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF,
		 ARP_infos[0].ether_addr[0],
		 ARP_infos[0].ether_addr[1],
		 ARP_infos[0].ether_addr[2],
		 ARP_infos[0].ether_addr[3],
		 ARP_infos[0].ether_addr[4],
		 ARP_infos[0].ether_addr[5]);
	
	ARP_infos[0].status=ARP_RECEIVED;
	ARP_infos[0].ip=ip;	
}

// Called every 10 sec to see if we have ARP to resend
void tapemu_check_resend_ARP (struct context *c)
{
	int i=0;
	
	if(tunemu_mode==TUNEMU_TAP)
	{
		for(i=0;i<NB_ARP;i++)
		{
			if (ARP_infos[i].status == ARP_REQUESTING)
			{
				ARP_infos[i].status=ARP_UNKNOWN;
				return;
			}
		}
	}
	
	return;
}

// Send an ARP request to get MAC address
int tapemu_send_arp_request(char *buffer,long ip)
{
	// Check if we need to wait
	int i=0;	
	for(i=0;i<NB_ARP;i++)
	{
		if(ARP_infos[i].ip == ip && ARP_infos[i].status == ARP_REQUESTING)
		{
			return 0;
		}
	}
	
	// MAC broadcast
	memcpy(buffer,tapemu_info.ether_addr_broadcast,6);
	
	// MAC local
	memcpy(buffer+6,tapemu_info.ether_addr_local,6);
	
	// Protocol
	buffer[12] = 0x08;
	buffer[13] = 0x06;
	
	// Set ARP header
	buffer[14]=0x00;
	buffer[15]=0x01;
	buffer[16]=0x08;
	buffer[17]=0x00;
	buffer[18]=0x06;
	buffer[19]=0x04;
	
	// ARP request
	buffer[20]=0x00;
	buffer[21]=0x01;
	
	// Our MAC address
	memcpy(buffer+22,tapemu_info.ether_addr_local,6);
	
	// Our IP address
	memcpy(buffer+28,&tapemu_info.ip_local,4);
	
	// Target MAC address
	memset(buffer+32,0,6);
	
	// Target IP address
	memcpy(buffer+38,&ip,4);
	msg (M_INFO,"Tapemu : Requesting MAC address for %d.%d.%d.%d",ip&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF);

	tapemu_set_mac_address(ip,NULL);
	
	return 42;
}

// Find the closest gateway to access the destination IP
long tapemu_find_gateway(long ip)
{	
	int i;
	
	for(i=0;i<NB_ROUTES;i++)
	{
		if(tapemu_routes[i].bValid==1)
		{
			// Check if the route matches the IP
			if((ip&tapemu_routes[i].mask)==(tapemu_routes[i].dest&tapemu_routes[i].mask))
			{
				// Check if the gateway is accessible directly
				if(!bIsLocalNetIP(tapemu_routes[i].gateway))
				{
					return tapemu_find_gateway(tapemu_routes[i].gateway);
				} else {
					return tapemu_routes[i].gateway;
				}
			}			
		}
	}
	
	return 0;
}

// Store routes, will be used to find gateway to use later on
void tapemu_add_route(long dest,long mask,long gateway)
{
	if(tunemu_mode==TUNEMU_TAP)
	{
		int i=0;
	
		for(i=0;i<NB_ROUTES;i++)
		{
			if(tapemu_routes[i].bValid==0)
			{
				msg (M_INFO,"Tapemu : Route added for %d.%d.%d.%d/%d.%d.%d.%d gateway %d.%d.%d.%d",
					 dest&0xFF,(dest>>8)&0xFF,(dest>>16)&0xFF,(dest>>24)&0xFF,
					 mask&0xFF,(mask>>8)&0xFF,(mask>>16)&0xFF,(mask>>24)&0xFF,
					 gateway&0xFF,(gateway>>8)&0xFF,(gateway>>16)&0xFF,(gateway>>24)&0xFF);
				tapemu_routes[i].bValid=1;
				tapemu_routes[i].dest=dest;
				tapemu_routes[i].mask=mask;			
				tapemu_routes[i].gateway=gateway;
				return;
			}
		}
	}
}

// Datas are ready to be sent to VPN
int tapemu_read(int ppp_sockfd, char *buffer, int length)
{
	// Get destination IP
	long dest_ip;
	memcpy(&dest_ip,buffer+30,4);
	unsigned char dest_mac[6];
	
	// Do we have an ARP request to reply ?	
	if(tapemu_info.bHasDataToSend)
	{
		tapemu_info.bHasDataToSend=0;
		memcpy(buffer,tapemu_info.ARP_buffer,sizeof(tapemu_info.ARP_buffer));
		return sizeof(tapemu_info.ARP_buffer);	
	} else {
		// Normal packet, define dest_mac.
		// If we don't have MAC address, send an ARPrequest
		
		// Check if we need to forward it to a gateway
		if(!bIsLocalNetIP(dest_ip))
		{
			long gateway_ip=tapemu_find_gateway(dest_ip);
			
			// Try to find which gateway we need to contact
			if(gateway_ip)
			{
				if(!tapemu_get_mac_address(gateway_ip,dest_mac))
				{
					return tapemu_send_arp_request(buffer,gateway_ip);
				}
			}			
		} else {
			// Send an ARP request
			if(!tapemu_get_mac_address(dest_ip,dest_mac) && dest_ip)
			{
				return tapemu_send_arp_request(buffer,dest_ip);
			}
		}
	}
	
	// Normal packet
	allocate_data_buffer(length + 2);	
	length = read(ppp_sockfd, data_buffer, length + 2);

	if (length < 0)
	{
		tap_error("reading packet: %s", strerror(errno));
		return length;
	}
	tap_noerror();
	
	if (length < 0)
	{
		return 0;
	}
	
	// Mac remote
	memcpy(buffer,dest_mac,6);
	
	// Mac local
	memcpy(buffer+6,tapemu_info.ether_addr_local,6);
	
	// Protocol
	buffer[12] = 0x08;
	buffer[13] = 0x00;
	
	// Data
	memcpy(buffer + 14, data_buffer + 2, length);
	
	tap_error("TAP read %d", length);
	return length+14;	
}

// Received datas from VPN
int tapemu_write(int ppp_sockfd, char *buffer, int length)
{
	// Is it an ARP ?
	if(buffer[12]==0x08 && buffer[13]==0x06)
	{
		// ARP request
		if(buffer[20]==0x00 && buffer[21]==0x01 &&
		   memcmp(buffer+38,&tapemu_info.ip_local,4)==0)
		{
			// Reply to the ARP request
			memset(tapemu_info.ARP_buffer,0,sizeof(tapemu_info.ARP_buffer));
			
			// Mac remote
			//memcpy(tapemu_info.ARP_buffer,tapemu_info.ether_addr_remote,6);
			memcpy(tapemu_info.ARP_buffer,buffer+22,6);
			
			// Mac local
			memcpy(tapemu_info.ARP_buffer+6,tapemu_info.ether_addr_local,6);
			
			// Protocol
			tapemu_info.ARP_buffer[12] = 0x08;
			tapemu_info.ARP_buffer[13] = 0x06;
			
			// Set ARP header
			tapemu_info.ARP_buffer[14]=0x00;
			tapemu_info.ARP_buffer[15]=0x01;
			tapemu_info.ARP_buffer[16]=0x08;
			tapemu_info.ARP_buffer[17]=0x00;
			tapemu_info.ARP_buffer[18]=0x06;
			tapemu_info.ARP_buffer[19]=0x04;
			
			// ARP reply 
			tapemu_info.ARP_buffer[20]=0x00;
			tapemu_info.ARP_buffer[21]=0x02;
			
			// Our MAC address
			memcpy(tapemu_info.ARP_buffer+22,tapemu_info.ether_addr_local,6);
			
			// Our IP address
			memcpy(tapemu_info.ARP_buffer+28,&tapemu_info.ip_local,4);			
			
			// Target MAC address
			memcpy(tapemu_info.ARP_buffer+32,buffer+22,6);
			
			// Target IP address
			memcpy(tapemu_info.ARP_buffer+38,buffer+28,4);
			
			tapemu_info.bHasDataToSend=1;
			
			// ARP reply
		} else if(memcmp(buffer,tapemu_info.ether_addr_local,6)==0 && 
				  buffer[20]==0x00 && buffer[21]==0x02) {
			
			long ip;
			memcpy(&ip,buffer+28,4);
			tapemu_set_mac_address(ip,buffer+22);
		}
		return length;
	} else {
		allocate_data_buffer(length + 18);
		
		data_buffer[0] = 0x02;
		data_buffer[1] = 0x00;
		data_buffer[2] = 0x00;
		data_buffer[3] = 0x00;
		
		memcpy(data_buffer + 4, buffer+14, length);
		
		if (pcap == NULL)
		{
			tap_error("pcap not open");
			return -1;
		}
		
		length = pcap_inject(pcap, data_buffer, length + 4);
		if (length < 0)
		{
			tap_error("injecting packet: %s", pcap_geterr(pcap));
			return length;
		}
		tap_noerror();
		
		length -= 4;
		if (length < 0)
			return 0;
		
		return length;
	}
}
