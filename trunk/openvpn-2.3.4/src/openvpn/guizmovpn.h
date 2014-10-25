//
//  guizmovpn.h
//  OpenVPN
//
//  Created by Guillaume Duteil on 12/08/2014.
//
//

#ifndef _GUIZMOVPN_H_
#define _GUIZMOVPN_H_

#include "proxy.h"

#define GUIZMOVPN_PREFS "/var/mobile/Library/Preferences/com.yourcompany.GuizmOVPN.plist"
#define GUIZMOVPN_TOOLS "/Applications/GuizmOVPN.app/tools"
#define GUIZMOVPN_COMMAND "/Applications/GuizmOVPN.app/guizmovpn_updown.sh"

typedef struct
{
    bool bAutoproxy;
    
    char client_proxy_ip[16];
    uint16_t client_proxy_port;
}guizmovpn_context;

void GuizmOVPN_init();

void GuizmOVPN_initialization_sequence_completed();
void GuizmOVPN_close_tun();
void GuizmOVPN_Error(int errorno);

void GuizmOVPN_get_user_pass(char *username,char *password,const int capacity, char * prefix);

bool GuizmOVPN_ReadPrefs(char *pref,char *value);
void GuizmOVPN_tools(const char *szParam);

struct auto_proxy_info *GuizmOVPN_get_auto_proxy (struct gc_arena *gc);
void GuizmOVPN_RestoreProxy();
void GuizmOVPN_set_client_proxy(char *szIP,char *szPort);

void GuizmOVPN_updown (const char *command, const struct plugin_list *plugins, int plugin_type, const char *arg, const char *dev_type, int tun_mtu, int link_mtu, const char *ifconfig_local, const char* ifconfig_remote, const char *context, const char *signal_text, const char *script_type, struct env_set *es);
#endif
