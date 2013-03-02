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
#include "tapemu_dhcp.h"
#include <ctype.h>
#include <sys/utsname.h>

struct tapemu_info_struct tapemu_info;
struct ARP_struct ARP_infos[NB_ARP];
struct tapemu_routes_struct tapemu_routes[NB_ROUTES];

#define ERROR_BUFFER_SIZE 1024
extern unsigned char tunemu_mode;
char tapemu_error[ERROR_BUFFER_SIZE];

pcap_t *pcap=NULL;
static int tapemu_data_buffer_length = 0;
static char *tapemu_data_buffer = NULL;

static unsigned char tapemu_has_lladdr_option=false;

static pcap_t* pcap_ppp=NULL;

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

bool tapemu_is_active()
{
    return (tunemu_mode==TUNEMU_TAP);
}

bool tapemu_has_ip()
{
    bool ret=true;
    if(tunemu_mode==TUNEMU_TAP && !tapemu_info.ip_local)
    {
        ret=false;
    }
    return ret;
}
void tapemu_set_pcap(pcap_t *pcap_ptr)
{
	pcap=pcap_ptr;				
}

static void tapemu_allocate_data_buffer(int size)
{
	if (tapemu_data_buffer_length < size)
	{
		free(tapemu_data_buffer);
		tapemu_data_buffer_length = size;
		tapemu_data_buffer = malloc(tapemu_data_buffer_length);
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
	
    // Generate IPv6
    tapemu_info.ip6_addr_local[0]=0xfe;
    tapemu_info.ip6_addr_local[1]=0x80;
    tapemu_info.ip6_addr_local[2]=0x00;
    tapemu_info.ip6_addr_local[3]=0x00;
    
    srand(time(NULL));
    short i;
    for(i=4;i<16;i+=4)
    {
        long num=rand();
        memcpy(&tapemu_info.ip6_addr_local[i],&num,sizeof(num));
    }
    
    // If we don't have IP, init the DHCP client
    if(!tapemu_has_ip())
    {
        tapemu_dhcp_init();
    }
    
    // Set the mdns name
    struct utsname systemInfo;
    uname(&systemInfo);
    for(i=0;i<strlen(systemInfo.nodename);i++)
    {
        systemInfo.nodename[i]=tolower(systemInfo.nodename[i]);
    }
    sprintf(tapemu_info.mdns_name,"%s.local",systemInfo.nodename);
}

void tapemu_get_mdns_name(char *name)
{
    strcpy(name,tapemu_info.mdns_name);
}

bool tapemu_is_ppp_inject()
{
    if(pcap_ppp)
    {
        return true;
    } else {
        return false;
    }
}

// Init pcap on ppp to inject extra packets
void tapemu_init_ppp_inject(char * devicename)
{
    if(!tapemu_is_ppp_inject())
    {
        pcap_ppp = pcap_open_live(devicename, BUFSIZ, 0, 1, NULL);    
        if (pcap_ppp == NULL)
        {
            msg (M_INFO,"Problem starting ppp inject");
            return;
        }
    }
}

int tapemu_inject(char *buffer,unsigned short size)
{
    if(pcap_ppp)
    {
        int len=pcap_inject(pcap_ppp, buffer-2, size+2);
        if(len<0)
        {
            msg (M_INFO,"Problem sending packet (%s)",pcap_geterr(pcap_ppp));
        }
        return len;
    } else {
        return 0;
    }
}

// Close
void tapemu_close()
{
    if(pcap_ppp)
    {
        pcap_close(pcap_ppp); 
    }
    tapemu_del_dhcp_routes();
    tapemu_dhcp_close();    
}

// Set the local mac address
void tapemu_set_lladdr(char *lladdr)
{
	int a,b,c,d,e,f;
	sscanf(lladdr,"%x:%x:%x:%x:%x:%x",&a,&b,&c,&d,&e,&f);
	tapemu_info.ether_addr_local[0]=(a & 0xFF);
        tapemu_info.ether_addr_local[1]=(b & 0xFF);
        tapemu_info.ether_addr_local[2]=(c & 0xFF);
	tapemu_info.ether_addr_local[3]=(d & 0xFF);
	tapemu_info.ether_addr_local[4]=(e & 0xFF);
	tapemu_info.ether_addr_local[5]=(f & 0xFF);

	tapemu_has_lladdr_option=true;

	msg (M_INFO,"Tapemu : Local MAC address changed to : %.02X:%.02X:%.02X:%.02X:%.02X:%.02X",
			tapemu_info.ether_addr_local[0],
			tapemu_info.ether_addr_local[1],
			tapemu_info.ether_addr_local[2],
			tapemu_info.ether_addr_local[3],
			tapemu_info.ether_addr_local[4],
			tapemu_info.ether_addr_local[5]);
}

// Get local MAC address
void tapemu_get_lladdr(char *address)
{	
    memcpy(address,tapemu_info.ether_addr_local,sizeof(tapemu_info.ether_addr_local));
}


// Generate random local MAC address, and set the broadcast MAC
void tapemu_generate_mac_addr()
{	
	if(!tapemu_has_lladdr_option)
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
	}

	// Set the broadcast MAC addr
	tapemu_info.ether_addr_broadcast[0]=0xFF;
	tapemu_info.ether_addr_broadcast[1]=0xFF;
	tapemu_info.ether_addr_broadcast[2]=0xFF;
	tapemu_info.ether_addr_broadcast[3]=0xFF;
	tapemu_info.ether_addr_broadcast[4]=0xFF;
	tapemu_info.ether_addr_broadcast[5]=0xFF;
	
	msg (M_INFO,"Tapemu : Local MAC address : %.02X:%.02X:%.02X:%.02X:%.02X:%.02X",
                                        tapemu_info.ether_addr_local[0],
                                        tapemu_info.ether_addr_local[1],
                                        tapemu_info.ether_addr_local[2],
					tapemu_info.ether_addr_local[3],
					tapemu_info.ether_addr_local[4],
					tapemu_info.ether_addr_local[5]);
}

// Check if we have prepared ARP data to be sent
unsigned char tapemu_has_data()
{
	return tunemu_mode==TUNEMU_TAP && tapemu_info.bHasDataToSend;
}

// Set local IP
void tapemu_set_ip_local(char *address,char *mask)
{
    tapemu_set_ip_local_long(inet_addr(address),inet_addr(mask));
}

void tapemu_set_ip_local_long(long address,long mask)
{	
	if(address && mask)
	{
		tapemu_info.ip_local=address;
		tapemu_info.mask_local=mask;
        
		msg (M_INFO,"Tapemu : Received local IP : %d.%d.%d.%d/%d.%d.%d.%d",
             address&0xFF,
             (address>>8)&0xFF,
             (address>>16)&0xFF,
             (address>>24)&0xFF,
             mask&0xFF,
             (mask>>8&0xFF),
             (mask>>16&0xFF),
             (mask>>24&0xFF));
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

// Get local IP
long tapemu_get_ip_local()
{	
	return tapemu_info.ip_local;
}


// Get local IP6
void tapemu_get_ip6_local(unsigned char *ip6)
{	
    memcpy(ip6,tapemu_info.ip6_addr_local,sizeof(tapemu_info.ip6_addr_local));
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

    if(!ip)
    {
        return 0;
    }
    
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
    tapemu_add_route2(dest,mask,gateway,false);
}

void tapemu_add_route2(long dest,long mask,long gateway,bool bFromDHCP)
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
                tapemu_routes[i].bFromDHCP=bFromDHCP;
				tapemu_routes[i].dest=dest;
				tapemu_routes[i].mask=mask;			
				tapemu_routes[i].gateway=gateway;
				return;
			}
		}
	}
}

void tapemu_del_dhcp_routes()
{
    if(tunemu_mode==TUNEMU_TAP)
	{
		int i=0;
        
		for(i=0;i<NB_ROUTES;i++)
		{
			if(tapemu_routes[i].bValid && tapemu_routes[i].bFromDHCP)
			{
                tapemu_dhcp_del_route(tapemu_routes[i].dest,tapemu_routes[i].mask,tapemu_routes[i].gateway);
			}
		}
	}
}

// Datas are ready to be sent to VPN
int tapemu_read(int ppp_sockfd, char *buffer, int length)
{    
    // Get destination IP
    long source_ip,dest_ip;
    unsigned char dest_mac[6];

    // Do we have an ARP request to reply ?	
    if(tapemu_info.bHasDataToSend)
    {
        tapemu_info.bHasDataToSend=0;
        memcpy(buffer,tapemu_info.ARP_buffer,sizeof(tapemu_info.ARP_buffer));
        return sizeof(tapemu_info.ARP_buffer);	
    } else {
        // Normal packet
        tapemu_allocate_data_buffer(length + 2);	
        length = read(ppp_sockfd, tapemu_data_buffer, length + 2);
        memcpy(&dest_ip,tapemu_data_buffer+18,4);
        memcpy(&source_ip,tapemu_data_buffer+14,4);
        
        /*msg (M_INFO,"Receiving1 %d (%d.%d.%d.%d -> %d.%d.%d.%d)",length,source_ip&0xFF,(source_ip>>8)&0xFF,(source_ip>>16)&0xFF,(source_ip>>24&0xFF),
             dest_ip&0xFF,(dest_ip>>8)&0xFF,(dest_ip>>16)&0xFF,(dest_ip>>24&0xFF));*/

        // If we don't have MAC address, send an ARPrequest        
        // Check if we need to forward it to a gateway
        if(!bIsLocalNetIP(dest_ip) && !bIsMulticastIP(dest_ip))
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
    
    
    /*msg (M_INFO,"Receiving %d (%d.%d.%d.%d -> %d.%d.%d.%d)",length,source_ip&0xFF,(source_ip>>8)&0xFF,(source_ip>>16)&0xFF,(source_ip>>24&0xFF),
         dest_ip&0xFF,(dest_ip>>8)&0xFF,(dest_ip>>16)&0xFF,(dest_ip>>24&0xFF));*/

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
    memcpy(buffer + 14, tapemu_data_buffer + 2, length);        
    
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
        
    // Handle DHCP
	} else if(!tapemu_has_ip() && buffer[36]==0 && buffer[37]==0x44) {
        return tapemu_dhcp_receive(buffer,length);

    // Other packets
    } else {
        // Handle multicast packets
        long dest_ip;
        memcpy(&dest_ip,buffer+30,4);
/*        if(bIsMulticastIP(dest_ip) )
        {
            msg (M_INFO,"Multicast from VPN (%d)",length);
//            return multicast_receive(buffer,length);
        }*/
        

		tapemu_allocate_data_buffer(length + 18);
		
		tapemu_data_buffer[0] = 0x02;
		tapemu_data_buffer[1] = 0x00;
		tapemu_data_buffer[2] = 0x00;
		tapemu_data_buffer[3] = 0x00;
		
		memcpy(tapemu_data_buffer + 4, buffer+14, length);
		
		if (pcap == NULL)
		{
			tap_error("pcap not open");
			return -1;
		}
		
		length = pcap_inject(pcap, tapemu_data_buffer, length + 4);
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

unsigned short tapemu_ip_checksum(unsigned short *data, int size)
{
    unsigned long checksum=0;
    while(size>1)
    {
        checksum=checksum+*data++;
        size=size-sizeof(unsigned short);
    }
    
    if(size)
        checksum=checksum+*(unsigned char*)data;
    
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum=checksum+(checksum>>16);
    
    return (unsigned short)(~checksum);
}
