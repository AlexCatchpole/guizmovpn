/*
 *  guizmovpn.h
 *  GuizmOVPN
 *
 *  Created by guizmo on 26/06/10.
 *  Copyright 2010 GuizmOVPN. All rights reserved.
 *
 */
#ifndef GUIZMOVPN_H
#define GUIZMOVPN_H
#define GUIZMOVPN_COMMAND "/Applications/GuizmOVPN.app/guizmovpn_updown.sh"

#include "syshead.h"
#include <notify.h>
#include <stdio.h>
#include <sys/errno.h>
#include "error.h"
#include "proxy.h"
#include "buffer.h"
#include "misc.h"
#include "options.h"

void guizmovpn_init();
void GuizmOVPN_get_user_pass(char *username,char *password,const int capacity,char *prefix);
void GuizmOVPN_initialisation_sequence_completed();
void GuizmOVPN_connecting();
void GuizmOVPN_close_tun();

void run_guizmovpn_updown (const struct plugin_list *plugins,
						   int plugin_type,
						   const char *arg,
						   int tun_mtu,
						   int link_mtu,
						   const char *ifconfig_local,
						   const char* ifconfig_remote,
						   const char *context,
						   const char *signal_text,
						   const char *script_type,
						   struct env_set *es);

void GuizmOVPN_Error(int errorno);
void run_guizmovpn_updown_dorun(struct env_set *es);

void guizmovpn_ip_to_string(long ip,char *str);

bool guizmovpn_autoproxy_is_set();
struct auto_proxy_info *guizmovpn_get_proxy_settings (char **err, struct gc_arena *gc);

bool guizmovpn_hans_is_active();
void guizmovpn_run_hans(char *szServerIP,char *password);
void guizmovpn_stop_hans();
bool guizmovpn_set_hans_gateway(char *gateway);
void guizmovpn_get_hans_gateway(char *gateway);
void guizmovpn_hans_create_route(char *remote_host);

bool guizmovpn_stunnel_is_active();
void guizmovpn_run_stunnel(char *szServerIP,int port);
void guizmovpn_stop_stunnel();
void guizmovpn_get_stunnel_server(char *server);

void guizmovpn_set_client_proxy(char *szIP,char *szPort);

struct guizmovpn_hans_infos
{
    bool isActive;
    char server_ip[16];    
    char gateway_ip[16];    
    char vpnserver_ip[16];
};

struct guizmovpn_stunnel_infos
{
    bool isActive;
    char vpnserver_ip[16];
};

struct guizmovpn_client_proxy_infos
{
    bool active;
    char server_ip[16];
    long port;
};

#endif
