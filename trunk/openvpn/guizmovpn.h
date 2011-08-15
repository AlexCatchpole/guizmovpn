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
#include "buffer.h"
#include "misc.h"

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
#endif
