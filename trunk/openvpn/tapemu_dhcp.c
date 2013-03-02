//
//  tapemu_dhcp.c
//  OpenVPN
//
//  Created by Guillaume Duteil on 20/02/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#include "config.h"

#include "syshead.h"
#include "error.h"
#include "openvpn.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <tapemu_dhcp.h>
#include <tapemu.h>

#define MAX_TAPEMU_DHCP_SIZE 1500
static char *tapemu_dhcp_data_buffer = NULL;
struct tapemu_dhcp_options_struct tapemu_dhcp_options;
struct tapemu_dhcp_settings_struct tapemu_dhcp_settings;

static unsigned char tapemu_dhcp_stage=TAPEMU_DHCP_DISCOVER;

void tapemu_dhcp_init()
{
    tapemu_dhcp_data_buffer = malloc(MAX_TAPEMU_DHCP_SIZE);        
    memset(tapemu_dhcp_data_buffer,0,MAX_TAPEMU_DHCP_SIZE);
    tapemu_dhcp_init_buffer();

    memset(&tapemu_dhcp_settings,0,sizeof(tapemu_dhcp_settings));
    tapemu_dhcp_settings.mtu=1500;
}

void tapemu_dhcp_close()
{
    if(tapemu_dhcp_data_buffer)
    {
        free(tapemu_dhcp_data_buffer);
    }
}

void tapemu_dhcp_set_mtu(long mtu)
{
    tapemu_dhcp_settings.mtu=mtu;
}

void tapemu_dhcp_init_buffer()
{
    tapemu_dhcp_stage=TAPEMU_DHCP_DISCOVER;
    
    memset(&tapemu_dhcp_options,0,sizeof(tapemu_dhcp_options));
    
    // Type
    tapemu_dhcp_data_buffer[0]=0x08;
    tapemu_dhcp_data_buffer[1]=0x00;
    
    // IP version
    tapemu_dhcp_data_buffer[2]=0x45;

    // TTL
    tapemu_dhcp_data_buffer[10]=0xFF;
    
    // Protocol
    tapemu_dhcp_data_buffer[11]=0x11;
    
    // Dest IP
    memset(tapemu_dhcp_data_buffer+18,0xFF,4);
    
    // Source port
    tapemu_dhcp_data_buffer[23]=0x44;
    
    // Destination port
    tapemu_dhcp_data_buffer[25]=0x43;

    // Message type
    tapemu_dhcp_data_buffer[30]=0x01;

    // Hardware type
    tapemu_dhcp_data_buffer[31]=0x01;
    
    // Hardware address length
    tapemu_dhcp_data_buffer[32]=0x06;
    
    // Transaction ID
    srand(time(NULL));
    unsigned long transaction_id=rand();
    memcpy(tapemu_dhcp_data_buffer+34,&transaction_id,sizeof(transaction_id));
    
    // Client mac address
    tapemu_get_lladdr(tapemu_dhcp_data_buffer+58);

    // Magic cookie
    tapemu_dhcp_data_buffer[266]=0x63;
    tapemu_dhcp_data_buffer[267]=0x82;
    tapemu_dhcp_data_buffer[268]=0x53;
    tapemu_dhcp_data_buffer[269]=0x63;
}

void tapemu_dhcp_send_discover()
{
    // IP Size
    tapemu_dhcp_data_buffer[4]=0x01;
    tapemu_dhcp_data_buffer[5]=0x48;
    
    // UDP Size
    tapemu_dhcp_data_buffer[26]=0x01;
    tapemu_dhcp_data_buffer[27]=0x34;

    // Option 1 : DHCP Message Type
    tapemu_dhcp_data_buffer[270]=0x35;
    tapemu_dhcp_data_buffer[271]=0x01;
    tapemu_dhcp_data_buffer[272]=TAPEMU_DHCP_DISCOVER;
    
    // Option 2 : Parameters request list
    tapemu_dhcp_data_buffer[273]=0x37;
    tapemu_dhcp_data_buffer[274]=0x09;
    tapemu_dhcp_data_buffer[275]=0x01; // Subnet mask
    tapemu_dhcp_data_buffer[276]=0x03; // Router
    tapemu_dhcp_data_buffer[277]=0x06; // DNS
    tapemu_dhcp_data_buffer[278]=0x0F; // Domain Name
    tapemu_dhcp_data_buffer[279]=0x77; // Domain Search
    tapemu_dhcp_data_buffer[280]=0x5F; // LDAP
    tapemu_dhcp_data_buffer[281]=0xFC; // Proxy
    tapemu_dhcp_data_buffer[282]=0x2C; // NetBIOS Name Server
    tapemu_dhcp_data_buffer[283]=0x2E; // NetBIOS Node Type
    
    // Option 3 : Max DHCP size
    tapemu_dhcp_data_buffer[284]=0x39;
    tapemu_dhcp_data_buffer[285]=0x02;
    tapemu_dhcp_data_buffer[286]=0x05;
    tapemu_dhcp_data_buffer[287]=0xDC;
    
    // Option 4 : Client identifier
    tapemu_dhcp_data_buffer[288]=0x3D;
    tapemu_dhcp_data_buffer[289]=0x07;
    tapemu_dhcp_data_buffer[290]=0x01;
    tapemu_get_lladdr(tapemu_dhcp_data_buffer+291);
    
    // Option 5 : IP Address Lease Time
    tapemu_dhcp_data_buffer[297]=0x33;
    tapemu_dhcp_data_buffer[298]=0x04;
    tapemu_dhcp_data_buffer[299]=0x00;
    tapemu_dhcp_data_buffer[300]=0x76;    
    tapemu_dhcp_data_buffer[301]=0xA7;    
    tapemu_dhcp_data_buffer[302]=0x00;
    
    // End
    tapemu_dhcp_data_buffer[303]=0xFF;
    
    // Send
    tapemu_dhcp_send_packet(328);
}

void tapemu_dhcp_send_request()
{
    tapemu_dhcp_stage=TAPEMU_DHCP_REQUEST;
    
    // Change type
    tapemu_dhcp_data_buffer[272]=TAPEMU_DHCP_REQUEST;

    // Change Option 5 : Requested IP address
    tapemu_dhcp_data_buffer[297]=0x32;
    tapemu_dhcp_data_buffer[298]=0x04;
    memcpy(tapemu_dhcp_data_buffer+299,&tapemu_dhcp_options.ip,sizeof(tapemu_dhcp_options.ip));

    // Option 6 : DHCP server identifier
    tapemu_dhcp_data_buffer[303]=0x36;
    tapemu_dhcp_data_buffer[304]=0x04;
    memcpy(tapemu_dhcp_data_buffer+305,&tapemu_dhcp_options.server,sizeof(tapemu_dhcp_options.server));    
    
    // End
    tapemu_dhcp_data_buffer[309]=0xFF;
    
    // Send
    tapemu_dhcp_send_packet(328);
}

void tapemu_dhcp_send_packet(short length)
{
    if(!tapemu_is_ppp_inject())
    {
        system("ifconfig ppp0 up");
        system("ifconfig ppp0 0.0.0.1 netmask 255.255.255.255 0.0.0.1");
    }
    
    tapemu_init_ppp_inject("ppp0");
    
    // Create random ident
    srand(time(NULL));
    unsigned short ident=rand();
    memcpy(tapemu_dhcp_data_buffer+6,&ident,sizeof(ident));
    
    // Update IP checksum
    tapemu_dhcp_data_buffer[12]=0x00;
    tapemu_dhcp_data_buffer[13]=0x00;
    unsigned short ip_checksum=tapemu_ip_checksum((unsigned short *)tapemu_dhcp_data_buffer+1,20);
    memcpy(tapemu_dhcp_data_buffer+12,&ip_checksum,sizeof(ip_checksum));
    
    tapemu_inject(tapemu_dhcp_data_buffer,length);
}

char tapemu_dhcp_parse_options(char *buffer,int max_len)
{
    char *ptr=buffer;
    char msg_type=0;
    
    while(max_len>0)
    {
        char option_type=*ptr++;
        char option_length=*ptr++;
        
        long tmp_ip=0;
        memcpy(&tmp_ip,ptr,sizeof(tmp_ip));
        
        switch(option_type)
        {
            // Subnet mask
            case 1:
                tapemu_dhcp_options.mask=tmp_ip;
                break;
                
            // Router
            case 3:                
                tapemu_dhcp_options.gateway=tmp_ip;
                break;
                
            // DNS
            case 6:
                if(!tapemu_dhcp_options.dns1)
                {
                    tapemu_dhcp_options.dns1=tmp_ip;
                } else {
                    tapemu_dhcp_options.dns2=tmp_ip;
                }
                break;
                
            // Message type
            case 53:
                msg_type=*ptr;
                break;

            // DHCP server identifier
            case 54:
                tapemu_dhcp_options.server=tmp_ip;
                break;
                
            default:
                break;
        }
        
        if((option_type&0xFF)==0xFF || option_length<=0)
        {
            max_len=0;
        } else {        
            max_len-=option_length;
        }
        
        ptr+=option_length;
    }
    
    return msg_type;
}

int tapemu_dhcp_receive(char *buffer,int length)
{
    // Is it a reply
    if(buffer[42]==0x02)
    {        
        // Is it for us ?
        char ether_addr[6];
        tapemu_get_lladdr(ether_addr);
        
        if(!memcmp(ether_addr,buffer+70,6))
        {
            long tmp_ip;
            memcpy(&tmp_ip,buffer+58,sizeof(tmp_ip));
            tapemu_dhcp_options.ip=tmp_ip;
            
            short max_size;
            memcpy(&max_size,buffer+16,sizeof(max_size));
            char msg_type=tapemu_dhcp_parse_options(buffer+282,htons(max_size));
            
            switch(msg_type)
            {
                case TAPEMU_DHCP_OFFER:
                    tapemu_dhcp_send_request();
                    break;
                
                case TAPEMU_DHCP_ACK:
                    // Set IP
                    tapemu_dhcp_set_ip();
                    
                    break;

                default:
                    tapemu_dhcp_init_buffer();
                    msg (M_INFO,"Unknown DHCP message type %d",msg_type);
                    break;
            }
        }
    }
    return length;
}

void tapemu_dhcp_send()
{
    switch(tapemu_dhcp_stage)
    {
        case TAPEMU_DHCP_DISCOVER:
            tapemu_dhcp_send_discover();
            break;
        
        case TAPEMU_DHCP_REQUEST:
            tapemu_dhcp_send_request();
            break;

        default:
            tapemu_dhcp_init_buffer();
            msg (M_INFO,"Unknown DHCP stage %d",tapemu_dhcp_stage);
            break;
    }
}

void tapemu_dhcp_set_ip()
{
    tapemu_set_ip_local_long(tapemu_dhcp_options.ip,tapemu_dhcp_options.mask);

    char cmd[255],ip[16],mask[16];
    
    guizmovpn_ip_to_string(tapemu_dhcp_options.ip,ip);
    guizmovpn_ip_to_string(tapemu_dhcp_options.mask,mask);
        
    sprintf(cmd,"%s %s %s %s netmask %s mtu %d up",
                 IFCONFIG_PATH,
                 "ppp0",
                 ip,
                 ip,
                 mask,
                 tapemu_dhcp_settings.mtu
                 );
    
    msg (M_INFO,"Running %s",cmd);
    
    system(cmd);
    
    tapemu_dhcp_add_route(tapemu_dhcp_options.ip, tapemu_dhcp_options.mask, tapemu_dhcp_options.ip);
    
    
}

void tapemu_dhcp_run_delay_script(struct env_set *es)
{
    // Add DNS1
    if(tapemu_dhcp_options.dns1)
    {
        char option[64];
        char szIP[16];
        guizmovpn_ip_to_string(tapemu_dhcp_options.dns1,szIP);
        
        sprintf(option,"dhcp-option DNS %s",szIP);
        setenv_str (es, "foreign_option_1", option);
    }
    
    // Add DNS2
    if(tapemu_dhcp_options.dns2)
    {
        char option[64];
        char szIP[16];
        guizmovpn_ip_to_string(tapemu_dhcp_options.dns2,szIP);
        
        sprintf(option,"dhcp-option DNS %s",szIP);
        setenv_str (es, "foreign_option_2", option);
    }

    // Add infos
    char tmpip[16];
    guizmovpn_ip_to_string(tapemu_dhcp_options.ip,tmpip);
    setenv_str (es, "ifconfig_local", tmpip);

    guizmovpn_ip_to_string(tapemu_dhcp_options.mask,tmpip);
    setenv_str (es, "ifconfig_netmask", tmpip);
    
    guizmovpn_ip_to_string(tapemu_dhcp_options.gateway,tmpip);
    setenv_str (es, "InfosGateway", tmpip);

    run_guizmovpn_updown_dorun(es);
}
void tapemu_dhcp_add_route(long l_dest,long l_mask,long l_gateway)
{
    tapemu_add_route2(l_dest,l_mask,l_gateway,true);
    
    long l_netip=l_dest&l_mask;
    
    char cmd[255],netip[16],gateway_ip[16],mask[16];
    
    guizmovpn_ip_to_string(l_netip,netip);
    guizmovpn_ip_to_string(l_mask,mask);
    guizmovpn_ip_to_string(l_gateway,gateway_ip);
    
    
    sprintf(cmd,"%s add -net %s %s %s",ROUTE_PATH,netip,gateway_ip,mask);
    
    msg (M_INFO,"Running %s",cmd);

    system(cmd);
}

void tapemu_dhcp_del_route(long l_dest,long l_mask,long l_gateway)
{
    long l_netip=l_dest&l_mask;
    
    char cmd[255],netip[16],gateway_ip[16],mask[16];
    
    guizmovpn_ip_to_string(l_netip,netip);
    guizmovpn_ip_to_string(l_mask,mask);
    guizmovpn_ip_to_string(l_gateway,gateway_ip);
    
    sprintf(cmd,"%s delete -net %s %s %s",ROUTE_PATH,netip,gateway_ip,mask);    
    msg (M_INFO,"Running %s",cmd);  
    
    system(cmd);
}
