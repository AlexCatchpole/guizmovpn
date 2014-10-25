//
//  tapemu.c
//  OpenVPN
//
//  Created by Guillaume Duteil on 29/06/2014.
//
//

#include "config.h"

#include "syshead.h"
#include "error.h"
#include <sys/time.h>

static tapemu_context tapemu_ctx;

/*
 * tapemu_init() :
 *      Init tapemu context
 */
void tapemu_init()
{
    // Set a random local MAC addr
    srand(time(NULL));
    long num=rand();
	
    tapemu_ctx.lladdr[0] = 0x0a;
    tapemu_ctx.lladdr[1] = 0x00;
    tapemu_ctx.lladdr[2] = 0x20;
    tapemu_ctx.lladdr[3] = (num>>24 & 0xFF);
    tapemu_ctx.lladdr[4] = (num>>16 & 0xFF);
    tapemu_ctx.lladdr[5] = (num>>8 & 0xFF);
    
	msg (M_INFO,"Tapemu : Local MAC address : %s",tapemu_ether_to_string(tapemu_ctx.lladdr));
    
    tapemu_ctx.ip=0;
    tapemu_ctx.netmask=0;
    tapemu_ctx.remote_ip=0;
    
    // Prepare a standard ARP query
    memset(tapemu_ctx.arp_query.ether_dest,0xFF,sizeof(tapemu_ctx.arp_query.ether_dest));
    memcpy(tapemu_ctx.arp_query.ether_src,tapemu_ctx.lladdr,sizeof(tapemu_ctx.arp_query.ether_src));
    tapemu_ctx.arp_query.ether_type=0x0608;
    tapemu_ctx.arp_query.hardware_type=0x0100;
    tapemu_ctx.arp_query.protocol_type=0x0008;
    tapemu_ctx.arp_query.hardware_size=6;
    tapemu_ctx.arp_query.protocol_size=4;
    tapemu_ctx.arp_query.opcode=TAPEMU_ARP_QUERY;
    memcpy(tapemu_ctx.arp_query.sender_mac_address,tapemu_ctx.lladdr,sizeof(tapemu_ctx.arp_query.sender_mac_address));
    tapemu_ctx.arp_query.sender_ip=0;
    memset(tapemu_ctx.arp_query.target_mac_address,0,sizeof(tapemu_ctx.arp_query.target_mac_address));
    tapemu_ctx.arp_query.target_ip=0;

    // Prepare a standard ARP reply
    memset(tapemu_ctx.arp_reply.ether_dest,0,sizeof(tapemu_ctx.arp_query.ether_dest));
    memcpy(tapemu_ctx.arp_reply.ether_src,tapemu_ctx.lladdr,sizeof(tapemu_ctx.arp_query.ether_src));
    tapemu_ctx.arp_reply.ether_type=0x0608;
    tapemu_ctx.arp_reply.hardware_type=0x0100;
    tapemu_ctx.arp_reply.protocol_type=0x0008;
    tapemu_ctx.arp_reply.hardware_size=6;
    tapemu_ctx.arp_reply.protocol_size=4;
    tapemu_ctx.arp_reply.opcode=TAPEMU_ARP_REPLY;
    memcpy(tapemu_ctx.arp_reply.sender_mac_address,tapemu_ctx.lladdr,sizeof(tapemu_ctx.arp_reply.sender_mac_address));
    tapemu_ctx.arp_reply.sender_ip=0;
    memset(tapemu_ctx.arp_reply.target_mac_address,0,sizeof(tapemu_ctx.arp_reply.target_mac_address));
    tapemu_ctx.arp_reply.target_ip=0;
    tapemu_ctx.bHadARPReplyToSend=false;
    
    // Init ARP cache
    tapemu_ctx.nb_arp_resolutions=0;
    tapemu_ctx.arp_resolutions=NULL;
    
    // Init routes cache
    tapemu_ctx.nb_routes=0;
    tapemu_ctx.routes=NULL;
}

/*
 * tapemu_clear() :
 *      Release allocated buffers
 */
void tapemu_clear()
{
    if(tapemu_ctx.arp_resolutions != NULL)
    {
        tapemu_ctx.nb_arp_resolutions=0;
        free(tapemu_ctx.arp_resolutions=NULL);
    }

    if(tapemu_ctx.routes != NULL)
    {
        tapemu_ctx.nb_routes=0;
        tapemu_ctx.routes=NULL;
    }
}

/*
 * tapemu_set_lladdr(const char *lladdr) :
 *      Set local MAC address
 */
void tapemu_set_lladdr(const char *lladdr)
{
	int tmp[6];
	sscanf(lladdr,"%x:%x:%x:%x:%x:%x",&tmp[0],&tmp[1],&tmp[2],&tmp[3],&tmp[4],&tmp[5]);
    for(int i=0;i<6;i++)
        tapemu_ctx.lladdr[i]=(tmp[i]&0xFF);

    // Update ARP query
    memcpy(tapemu_ctx.arp_query.ether_src,tapemu_ctx.lladdr,sizeof(tapemu_ctx.arp_query.ether_src));
    memcpy(tapemu_ctx.arp_query.sender_mac_address,tapemu_ctx.lladdr,sizeof(tapemu_ctx.arp_query.sender_mac_address));

    // Update ARP reply    
    memcpy(tapemu_ctx.arp_reply.ether_src,tapemu_ctx.lladdr,sizeof(tapemu_ctx.arp_query.ether_src));
    memcpy(tapemu_ctx.arp_reply.sender_mac_address,tapemu_ctx.lladdr,sizeof(tapemu_ctx.arp_reply.sender_mac_address));
    
	msg (M_INFO,"Tapemu : Local MAC address changed to : %s",tapemu_ether_to_string(tapemu_ctx.lladdr));
}

/*
 * tapemu_set_local_ip(uint32_t ip,uint32_t netmask) :
 *      Set local IP/netmask
 */
void tapemu_set_local_ip(uint32_t ip,uint32_t netmask)
{
    tapemu_ctx.ip=ip;
    tapemu_ctx.netmask=netmask;

    char szIP[16];
    strncpy(szIP,tapemu_ip_to_string(tapemu_ctx.ip),sizeof(szIP));

    tapemu_ctx.arp_query.sender_ip=ip;
    tapemu_ctx.arp_reply.sender_ip=ip;
    
	msg (M_INFO,"Tapemu : Local IP address is : %s/%s",szIP,tapemu_ip_to_string(tapemu_ctx.netmask));
}

/*
 * tapemu_set_remote_ip(uint32_t ip) :
 *      Set remote IP
 */
void tapemu_set_remote_ip(uint32_t ip)
{
    tapemu_ctx.remote_ip=ip;
    
    msg (M_INFO,"Tapemu : Remote IP address is : %s",tapemu_ip_to_string(tapemu_ctx.remote_ip));
}

/*
 * tapemu_get_remote_ip() :
 *      Get remote IP
 */
uint32_t tapemu_get_remote_ip()
{
    return tapemu_ctx.remote_ip;
}

/*
 * tapemu_tapemu_timer(struct context *c) :
 *      Timer executed every second
 */
void tapemu_timer(struct context *c)
{
    
}

/*
 * tapemu_add_route(uint32_t dest,uint32_t mask,uint32_t gateway) :
 *      Store VPN routes to handle properly ARP resolution
 */
void tapemu_add_route(uint32_t dest,uint32_t mask,uint32_t gateway)
{
    char szDest[32],szMask[32],szGateway[32];
    strncpy(szDest,tapemu_ip_to_string(dest),sizeof(szDest)-1);
    strncpy(szMask,tapemu_ip_to_string(mask),sizeof(szMask)-1);
    strncpy(szGateway,tapemu_ip_to_string(gateway),sizeof(szGateway)-1);
    
    // Check if this route already exists
    for(int i=0;i<tapemu_ctx.nb_routes;i++)
    {
        if(tapemu_ctx.routes[i].ip==dest)// && tapemu_ctx.routes[i].netmask==mask && tapemu_ctx.routes[i].gateway==gateway)
        {
            msg (M_INFO,"Tapemu : Route for for %s/%s gateway %s already exists", szDest, szMask, szGateway);
            return;
        }
    }
    
    // Create a new route
    tapemu_ctx.routes=(tapemu_route *)realloc(tapemu_ctx.routes, sizeof(tapemu_route)*(tapemu_ctx.nb_routes+1));
    tapemu_ctx.routes[tapemu_ctx.nb_routes].ip=dest;
    tapemu_ctx.routes[tapemu_ctx.nb_routes].netmask=mask;
    tapemu_ctx.routes[tapemu_ctx.nb_routes].gateway=gateway;
    tapemu_ctx.nb_routes++;
    
    msg (M_INFO,"Tapemu : Route added for %s/%s gateway %s", szDest, szMask, szGateway);
}

/*
 * tapemu_get_gateway(uint32_t ip) :
 *      Returns the closest gateway to reach the IP.
 *      If the IP belongs to our subnet, we concider this IP as the gateway
 *      If the route is not found, returns the default gateway.
 *      If default gateway is not set, returns 0.
 */
uint32_t tapemu_get_gateway(uint32_t ip)
{
    // IP on our subnet or invalid ?
    if(ip==0 || (ip&tapemu_ctx.netmask) == (tapemu_ctx.ip&tapemu_ctx.netmask))
    {
        //msg (M_INFO,"Tapemu : local %s", tapemu_ip_to_string(ip));
        return ip;
    }
    
    // Search for the route matching the ip with the most restrictive netmask
    uint32_t gateway_ip=0;
    uint32_t mask=0;
    
    for(int i=0;i<tapemu_ctx.nb_routes;i++)
    {
        if((ip&tapemu_ctx.routes[i].netmask)==(tapemu_ctx.routes[i].ip&tapemu_ctx.routes[i].netmask))
        {
            if(htonl(tapemu_ctx.routes[i].netmask)>htonl(mask))
            {
                gateway_ip=tapemu_ctx.routes[i].gateway;
                mask=tapemu_ctx.routes[i].netmask;
            }
        }
    }
    
    //msg (M_INFO,"Tapemu : gateway is %s", tapemu_ip_to_string(gateway_ip));
    return tapemu_get_gateway(gateway_ip);
}

/*
 * tapemu_read(int fd, uint8_t *buf, int len) :
 *      Send datas through VPN.
 *
 *      In normal conditions, it sends a packet, but it can also send ARP queries if destination MAC address is unknown.
 *      It can also send a reply is it received a query for our IP.
 *      ARP queries are sent maximum every 1 secs.
 */

int tapemu_read(int fd, uint8_t *buf, int len)
{
    // Send a ARP reply if needed
    if(tapemu_ctx.bHadARPReplyToSend)
    {
        memcpy(buf,&tapemu_ctx.arp_reply,sizeof(tapemu_ctx.arp_reply));
        tapemu_ctx.bHadARPReplyToSend=false;
        return sizeof(tapemu_ctx.arp_reply);
    }
    
    // Read a message from utun interface (leaving space for ethernet header) and get the final destination IP
    int ret=read(fd, buf+10, len-10);
    uint32_t dest_ip=*(uint32_t *)(buf+30);
    
    // Check if we already know the ether_dest address, if not, send an arp request
    // TODO : If the IP is unroutable (TAPEMU_ERROR), handle it.
    uint32_t gateway_ip;
    if(tapemu_get_mac_address(dest_ip,buf,&gateway_ip)==TAPEMU_NOT_FOUND)
    {
        // If a previous ARP query for this IP has been sent less than 1 sec ago, we stop here and wait.
        bool bFound=false;
        for(int i=0;i<tapemu_ctx.nb_arp_resolutions;i++)
        {
            if(tapemu_ctx.arp_resolutions[i].ip==gateway_ip)
            {
                if(tapemu_timestamp()<tapemu_ctx.arp_resolutions[i].timeLastQuery+1000)
                {
                    return 0;
                }
                bFound=true;
                break;
            }
        }
        
        // It's the first time we try query this IP, we create a new arp_resolutions slot
        if(!bFound)
        {
            tapemu_ctx.arp_resolutions=(tapemu_arp_resolution *)realloc(tapemu_ctx.arp_resolutions, sizeof(tapemu_arp_resolution) * (tapemu_ctx.nb_arp_resolutions+1));
            tapemu_ctx.arp_resolutions[tapemu_ctx.nb_arp_resolutions].ip=gateway_ip;
            tapemu_ctx.arp_resolutions[tapemu_ctx.nb_arp_resolutions].bValid=false;
            memset(tapemu_ctx.arp_resolutions[tapemu_ctx.nb_arp_resolutions].ether_addr,0,sizeof(tapemu_ctx.arp_resolutions[tapemu_ctx.nb_arp_resolutions].ether_addr));
            tapemu_ctx.arp_resolutions[tapemu_ctx.nb_arp_resolutions].timeLastQuery=tapemu_timestamp();

            tapemu_ctx.nb_arp_resolutions++;
        }
        
        // Replace the buffer with our ARP query
        msg (M_INFO,"Tapemu : Requesting MAC address for %s",tapemu_ip_to_string(gateway_ip));
        tapemu_ctx.arp_query.target_ip=gateway_ip;
        memcpy(buf,&tapemu_ctx.arp_query,sizeof(tapemu_ctx.arp_query));
        return sizeof(tapemu_ctx.arp_query);
    }
    
    
    // We have everything to build our header
    memcpy(buf+6,tapemu_ctx.lladdr,sizeof(tapemu_ctx.lladdr));
    
    // IP Protocol
    buf[12] = 0x08;
    buf[13] = 0x00;
    
    return ret+10;
}

/*
 * tapemu_write(int fd, uint8_t *buf, int len) :
 *      Read datas from VPN.
 *
 *      In normal conditions, it writes a packet to the utun interface, but it can also handle ARP messages
 */
int tapemu_write(int fd, uint8_t *buf, int len)
{
	// Is it an ARP ?
	if(buf[12]==0x08 && buf[13]==0x06)
	{
        return tapemu_handle_arp(buf,len);
    }
    
    // Normal packet, we change the header
    uint8_t *tmpbuf=(uint8_t *)malloc(len-10);
    tmpbuf[0]=0x00;
    tmpbuf[1]=0x00;
    tmpbuf[2]=0x00;
    tmpbuf[3]=0x02;
    memcpy(tmpbuf + 4, buf+14, len-14);
    
    int ret=write (fd, tmpbuf, len-10);
	//msg (M_DEBUG,"Tapemu_write (%d)(%d) : %s from %s", len, ret, tapemu_ether_to_string(buf), tapemu_ether_to_string(buf+6));
    free(tmpbuf);
    return len;
}

/*
 * tapemu_ether_to_string(unsigned char *lladdr) :
 *      Returns a string containing a MAC address with form XX:XX:XX:XX:XX:XX
 */
const char * tapemu_ether_to_string(unsigned char *lladdr)
{
    static char szEther[20];
    snprintf(szEther,sizeof(szEther)-1,"%.02X:%.02X:%.02X:%.02X:%.02X:%.02X",lladdr[0],lladdr[1],lladdr[2],lladdr[3],lladdr[4],lladdr[5]);
    return szEther;
}

/*
 * tapemu_ip_to_string(uuint32_t ip) :
 *      Returns a string containing a IP address with form XXX.XXX.XXX.XXX
 */
const char * tapemu_ip_to_string(uint32_t ip)
{
    static char szIP[32];
    snprintf(szIP,sizeof(szIP)-1,"%d.%d.%d.%d",ip&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF);
    return szIP;
}

/*
 * tapemu_timestamp() :
 *      Returns a timestamp in milliseconds
 */
uint64_t tapemu_timestamp()
{
    struct timeval te;
    gettimeofday(&te, NULL);
    uint64_t milliseconds = te.tv_sec*1000LL + te.tv_usec/1000;
    return milliseconds;
}

/*
 * tapemu_get_mac_address(uint32_t ip,unsigned char *ether,uint32_t *gateway_ip) :
 *      Set a MAC address from the ip.
 *      If unknown, set the gateway_ip in order to request the correct IP in the ARP request, and returns TAPEMU_NOT_FOUND.
 *      If unroutable, returns TAPEMU_ERROR
 */
int tapemu_get_mac_address(uint32_t ip,unsigned char *ether,uint32_t *gateway_ip)
{
    *gateway_ip=0;
    
    // Broadcast ? (last byte is 0xFF)
    if(((ip>>24)&0xFF) == 0xFF)
    {
        memset(ether,0xFF,6);
        return TAPEMU_FOUND;
        
    // Multicast ? (first 4 bits are 1110)
    } else if((ip&0xF0) == 0xE0) {
        // Multicast prefix
        ether[0]=0x01;
        ether[1]=0x00;
        ether[2]=0x5E;
        
        ether[3]=((ip>>8)&0x7F);
        ether[4]=((ip>>16)&0xFF);
        ether[5]=((ip>>24)&0xFF);
        
        return TAPEMU_FOUND;
        
    // All other addresses
    } else {
        // We need to detect if the target is a IP from our subnet, or if we need to use a gateway to reach it
        uint32_t dest_ip=tapemu_get_gateway(ip);
        char szTmp0[32];
        strncpy(szTmp0,tapemu_ip_to_string(ip),30);
        //msg (M_INFO,"Tapemu : gateway for %s : %s", szTmp0, tapemu_ip_to_string(dest_ip));
        if(dest_ip==0)
        {
            return TAPEMU_ERROR;
        }
        
        *gateway_ip=dest_ip;
        
        for(int i=0;i<tapemu_ctx.nb_arp_resolutions;i++)
        {
            if(tapemu_ctx.arp_resolutions[i].ip==dest_ip)
            {
                if(tapemu_ctx.arp_resolutions[i].bValid)
                {
                    memcpy(ether,tapemu_ctx.arp_resolutions[i].ether_addr,sizeof(tapemu_ctx.arp_resolutions[i].ether_addr));
                    return TAPEMU_FOUND;
                } else {
                    return TAPEMU_NOT_FOUND;
                }
            }
        }
    }
    return TAPEMU_NOT_FOUND;
}

/*
 * tapemu_handle_arp(uint8_t *buf,int len) :
 *      Handles ARP packets.
 *      It prepares a ARP reply if the query is for us, of update our ARP cache if it's a reply
 */
int tapemu_handle_arp(uint8_t *buf,int len)
{
    tapemu_arp *arp=(tapemu_arp *)buf;
    
    if(arp->opcode==TAPEMU_ARP_QUERY)
    {
        //msg (M_DEBUG,"ARP query : %s",tapemu_ip_to_string(arp->target_ip));
        if(arp->target_ip==tapemu_ctx.ip)
        {
            // This query is for us, prepare a reply
            memcpy(tapemu_ctx.arp_reply.ether_dest,arp->sender_mac_address,sizeof(tapemu_ctx.arp_reply.ether_dest));
            memcpy(tapemu_ctx.arp_reply.target_mac_address,arp->sender_mac_address,sizeof(tapemu_ctx.arp_reply.target_mac_address));
            tapemu_ctx.arp_reply.target_ip=arp->sender_ip;
            
            tapemu_ctx.bHadARPReplyToSend=true;
        }
    } else if(arp->opcode==TAPEMU_ARP_REPLY) {
        // Update our ARP cache if we requested this resolution
        for(int i=0;i<tapemu_ctx.nb_arp_resolutions;i++)
        {
            if(tapemu_ctx.arp_resolutions[i].ip==arp->sender_ip)
            {
                memcpy(tapemu_ctx.arp_resolutions[i].ether_addr,arp->sender_mac_address,sizeof(tapemu_ctx.arp_resolutions[i].ether_addr));
                tapemu_ctx.arp_resolutions[i].bValid=true;

                msg (M_INFO,"Tapemu : MAC address for %s : %s", tapemu_ip_to_string(arp->sender_ip), tapemu_ether_to_string(arp->sender_mac_address));
                break;
            }
        }
    }
    
    return len;
}