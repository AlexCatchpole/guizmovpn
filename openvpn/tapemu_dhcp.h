//
//  tapemu_dhcp.h
//  OpenVPN
//
//  Created by Guillaume Duteil on 20/02/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#ifndef tapemu_dhcp_h
#define tapemu_dhcp_h

#define TAPEMU_DHCP_DISCOVER    1
#define TAPEMU_DHCP_OFFER       2
#define TAPEMU_DHCP_REQUEST     3
#define TAPEMU_DHCP_ACK         5


struct tapemu_dhcp_options_struct
{
    long ip;
    long mask;
    long gateway;
    long dns1;    
    long dns2;
    long server;
};

struct tapemu_dhcp_settings_struct
{
    long mtu;
};

void tapemu_dhcp_send_packet(short length);
void tapemu_dhcp_init_buffer();
void tapemu_dhcp_set_ip();
void tapemu_dhcp_run_script();

void tapemu_dhcp_add_route(long l_dest,long l_mask,long l_gateway);
void tapemu_dhcp_del_route(long l_dest,long l_mask,long l_gateway);
void tapemu_dhcp_close();
#endif
