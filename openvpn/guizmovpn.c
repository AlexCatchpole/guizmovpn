/*
 *  guizmovpn.c
 *  GuizmOVPN
 *
 *  Created by guizmo on 26/06/10.
 *  Copyright 2010 GuizmOVPN. All rights reserved.
 *
 */

#include "guizmovpn.h"

char * ReadPrefs(char *pref)
{
	char buf[255];
	char temp[32];
	char key[128];
	char value[32];
	char *pch;
	
	memset(buf,0,sizeof(buf));
	
	FILE *fp=fopen("/var/mobile/Library/Preferences/com.yourcompany.GuizmOVPN.plist","r");
	
	if(fp != NULL)
	{
		while(fgets(buf , sizeof(buf)-1 , fp))
		{
			if(strstr(buf,"<key>"))
			{
				memset(key,0,sizeof(key));
				sscanf(buf," <key>%31s</key>",temp);
				pch = strtok (temp,"<");
				if(pch)
				{
					sprintf(key,pch);
				}
			}

			if(strstr(buf,"<string>"))
			{
				memset(value,0,sizeof(value));
				sscanf(buf," <string>%31s</string>",temp);
				pch = strtok (temp,"<");
				if(pch)
				{
					sprintf(value,pch);
				}
				
				if(strcmp(key,pref) == 0)
				{
					break;
				}
			}
		}
		fclose(fp);
	}
	return value;
}

// Send notifications that the tunnel is running
void GuizmOVPN_initialisation_sequence_completed()
{
	notify_post("com.guizmo.openvpn/StatusIconAdd");
}

// Send notifications that the tunnel is running
void GuizmOVPN_close_tun()
{
	notify_post("com.guizmo.openvpn/StatusIconRemove");
}

// Send notification that we are trying to connect
void GuizmOVPN_connecting()
{
	notify_post("com.guizmo.openvpn/Connecting");
}

// Request username/password from the user
void GuizmOVPN_get_user_pass(char *username,char *password,const int capacity, char * prefix)
{
	int token, status, check;
	
	status = notify_register_check("com.guizmo.openvpn/ReceivedUserPass", &token);
	notify_check(token, &check);
	if (status != NOTIFY_STATUS_OK)
	{
		msg (M_FATAL, "Unable to receive authentification");
	}
	
	// Check which user/pass request to handle
	if(!strcmp(prefix,"token-insertion-request"))
	{
		notify_post("com.guizmo.openvpn/RequestTokenInsertionPass");
		
	} else if(!strcmp(prefix,"Auth")) {
		notify_post("com.guizmo.openvpn/RequestAuthUserPass");
		
	} else if(!strcmp(prefix,"HTTP Proxy")) {
		notify_post("com.guizmo.openvpn/RequestProxyUserPass");
		
	} else if(!strcmp(prefix,"pkcs11-id-request")) {
		notify_post("com.guizmo.openvpn/RequestPKCS11UserPass");
		
	} else if(!strcmp(prefix,"Private Key")) {
		notify_post("com.guizmo.openvpn/RequestPrivateKeyPass");
		
	} else if(!strstr(prefix," token")) {
		notify_post("com.guizmo.openvpn/RequestTokenPIN");
		
	} else {
		printf("Unknown user/pass request : %s\n",prefix);
		return;
	}
	
	printf("Waiting for username/password (%s)\n",prefix);	
	// May need to do a cleaner wait
	int received=0;
	while(!received)
	{
		status = notify_check(token, &check);
		if ((status == NOTIFY_STATUS_OK) && (check != 0))
		{
			printf("Username/password received\n");
			received=1;
		}
		sleep(1);
	}
	
	// Read the username/password from file
	const char *path="/tmp/guizmovpn_temp_auth";
	FILE *fp = fopen (path, "r");
	if (!fp)
	{
		msg (M_FATAL, "Error receiving authentification");
	}
	
	if (fgets (username, capacity, fp) == NULL || fgets (password, capacity, fp) == NULL)
	{
		msg (M_FATAL, "Error receiving authentification");
	}
	
	fclose (fp);
	unlink(path);
	
	chomp (username);
	chomp (password);

	return;
}

/*
 * Pass tunnel endpoint and MTU parms to a user-supplied script.
 * Used to execute the up/down script/plugins.
 */
void
run_guizmovpn_updown (const struct plugin_list *plugins,
					  int plugin_type,
					  const char *arg,
					  int tun_mtu,
					  int link_mtu,
					  const char *ifconfig_local,
					  const char* ifconfig_remote,
					  const char *context,
					  const char *signal_text,
					  const char *script_type,
					  struct env_set *es)
{
	struct gc_arena gc = gc_new ();
	char InfosGateway[16];

	if (signal_text)
		setenv_str (es, "signal", signal_text);
	setenv_str (es, "script_context", context);
	setenv_int (es, "tun_mtu", tun_mtu);
	setenv_int (es, "link_mtu", link_mtu);
	setenv_str (es, "dev", arg);
	
	if (!ifconfig_local)
		ifconfig_local = "";
	if (!ifconfig_remote)
	{
		ifconfig_remote = "";
	}

	long ip_addr_remote=htonl(tapemu_get_ip_remote());
        sprintf(InfosGateway,"%d.%d.%d.%d",(ip_addr_remote>>24)&0xFF,(ip_addr_remote>>16)&0xFF,(ip_addr_remote>>8)&0xFF,ip_addr_remote&0xFF);
	setenv_str (es, "InfosGateway", InfosGateway);

	if (!context)
		context = "";
	
	struct argv argv = argv_new ();
	ASSERT (arg);
	setenv_str (es, "script_type", script_type);
	
	if(strcmp(ReadPrefs("DNSPush"),"NO") != 0)
	{
		setenv_str (es, "DNSPush", "Y");
	}

	if(strcmp(ReadPrefs("DNSKeep"),"NO") != 0)
	{
		setenv_str (es, "DNSKeep", "Y");
	}
	
	argv_printf (&argv,
				 "%sc %s %d %d %s %s %s",
				 GUIZMOVPN_COMMAND,
				 arg,
				 tun_mtu, link_mtu,
				 ifconfig_local, ifconfig_remote,
				 context);
	
	openvpn_execve_check (&argv, es, 0, "script failed");
	argv_reset (&argv);
	gc_free (&gc);
}

// Send notification that there is an error
void GuizmOVPN_Error(int errorno)
{
	switch(errorno)
	{
		case EHOSTUNREACH:
			notify_post("com.guizmo.openvpn/NoRouteToHost");
			break;
			
		case EADDRNOTAVAIL:
			notify_post("com.guizmo.openvpn/CantAssignRequestedAddress");
			break;
		
		case HOST_NOT_FOUND:
			notify_post("com.guizmo.openvpn/HostNotFound");
			break;			
	}
}
