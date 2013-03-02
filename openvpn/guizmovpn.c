/*
 *  guizmovpn.c
 *  GuizmOVPN
 *
 *  Created by guizmo on 26/06/10.
 *  Copyright 2010 GuizmOVPN. All rights reserved.
 *
 */

#include "guizmovpn.h"
#include "tapemu.h"

static struct argv guizmovpn_argv;
struct env_set *guizmovpn_es;
struct guizmovpn_hans_infos hans_infos;
struct guizmovpn_stunnel_infos stunnel_infos;
struct guizmovpn_client_proxy_infos client_proxy_infos;

void guizmovpn_init()
{
    memset(&stunnel_infos,0,sizeof(stunnel_infos));
    memset(&hans_infos,0,sizeof(hans_infos));
    memset(&client_proxy_infos,0,sizeof(client_proxy_infos));
}

void ReadPrefs(char *pref,char *value)
{
	char buf[255];
	char temp[32];
	char key[128];
	char val[32]="\0";
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
				memset(val,0,sizeof(val));
				sscanf(buf," <string>%31s</string>",temp);
  
                if(temp[0]!='<')
                {
                    pch = strtok (temp,"<");
                    if(pch)
                    {
                        strcpy(val,pch);
                    }
                }
				
				if(strcmp(key,pref) == 0)
				{
					strcpy(value,val);
					break;
				}
			}
		}
		fclose(fp);
	}
}

// Send notifications that the tunnel is running
void GuizmOVPN_initialisation_sequence_completed()
{
    //tethering_start();
	notify_post("com.guizmo.openvpn/StatusIconAdd");
}

// Send notifications that the tunnel is running
void GuizmOVPN_close_tun()
{
	notify_post("com.guizmo.openvpn/StatusIconRemove");
    
    // Kill hans
    guizmovpn_stop_hans();

    // Kill stunnel
    guizmovpn_stop_stunnel();
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
	
    argv_reset(&guizmovpn_argv);
	guizmovpn_argv = argv_new ();
    
	ASSERT (arg);
	setenv_str (es, "script_type", script_type);

	char szTemp[32];
    szTemp[0]='\0';
	ReadPrefs("DNSPush",szTemp);	
	if(strcmp(szTemp,"NO") != 0)
	{
		setenv_str (es, "DNSPush", "Y");
	}

    szTemp[0]='\0';
	ReadPrefs("DNSKeep",szTemp);
	if(strcmp(szTemp,"NO") != 0)
	{
		setenv_str (es, "DNSKeep", "Y");
	}

    szTemp[0]='\0';
    ReadPrefs("Multicast",szTemp);
	if(tapemu_is_active() && strcmp(szTemp,"YES") == 0)
	{
		setenv_str (es, "Multicast", "Y");
	}
    
    if(client_proxy_infos.active)
    {
		setenv_str (es, "ClientProxyIP", client_proxy_infos.server_ip);
		setenv_int (es, "ClientProxyPort", client_proxy_infos.port);
    }
    
	argv_printf (&guizmovpn_argv,
				 "%sc %s %d %d %s %s %s",
				 GUIZMOVPN_COMMAND,
				 arg,
				 tun_mtu, link_mtu,
				 ifconfig_local, ifconfig_remote,
				 context);
    
    run_guizmovpn_updown_dorun(es);
}

// Run script
void run_guizmovpn_updown_dorun(struct env_set *es)
{
    if(tapemu_has_ip())
    {
        msg (M_INFO, "Running script");
        openvpn_execve_check (&guizmovpn_argv, es, 0, "script failed");
        msg (M_INFO, "Script ended");
        //argv_reset (&guizmovpn_argv);    
    }
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

// Convert IP long to string
void guizmovpn_ip_to_string(long ip,char *str)
{
    sprintf(str,"%d.%d.%d.%d",ip&0xFF,
            (ip>>8)&0xFF,
            (ip>>16)&0xFF,
            (ip>>24)&0xFF);
}

bool guizmovpn_autoproxy_is_set()
{
    bool ret=false;

    char szTemp[32];
    ReadPrefs("AutoProxy",szTemp);
	if(strcmp(szTemp,"NO") != 0)
    {
        ret=true;
    }

    return ret;
}

// Run proxy detection and disable it if needed
struct auto_proxy_info *guizmovpn_get_proxy_settings (char **err, struct gc_arena *gc)
{
    system("/Applications/GuizmOVPN.app/tools handle_proxy");

    if (err)
        *err = NULL;
    
    struct auto_proxy_info *pi;

    char szHTTPProxyIP[32];
    char szHTTPProxyPort[32];
    long HTTPProxyPort=0;
    
    szHTTPProxyIP[0]='\0';
    ReadPrefs("HTTPProxy",szHTTPProxyIP);
    
    szHTTPProxyPort[0]='\0';    
    ReadPrefs("HTTPPort",szHTTPProxyPort);
    HTTPProxyPort=atoi(szHTTPProxyPort);
    
    if(strlen(szHTTPProxyIP)>7 && HTTPProxyPort>=0)
    {
        ALLOC_OBJ_CLEAR_GC (pi, struct auto_proxy_info, gc);
        pi->http.server=string_alloc(szHTTPProxyIP,gc);
        pi->http.port = HTTPProxyPort;
        
        printf("Proxy detected : %s:%d\n",szHTTPProxyIP,HTTPProxyPort);
        return pi;
    } else {
    	return NULL;
    }
}

bool guizmovpn_hans_is_active()
{
    return hans_infos.isActive;
}

// Start hans
void guizmovpn_run_hans(char *szServerIP,char *password)
{
    msg (M_INFO, "Script ended");
    
    // Check if file exists
    FILE *fp=fopen("/usr/sbin/hans", "r");
    if (fp!=NULL)
    {
        fclose(fp);
    } else {
        notify_post("com.guizmo.openvpn/HansNotFound");
        msg (M_FATAL, "Hans is not installed, please install it from Cydia and try again.");
    }
    
    hans_infos.isActive=true;
    strncpy(hans_infos.server_ip,szServerIP,sizeof(hans_infos.server_ip));
    
    // Kill an eventual old hans client
    guizmovpn_stop_hans();
    
    // Start Hans client
    char szCmd[255];
    
    if(!password)
    {
        sprintf(szCmd,"/usr/sbin/hans -c %s -d ppp1",szServerIP);
    } else {
        sprintf(szCmd,"/usr/sbin/hans -c %s -d ppp1 -p %s",szServerIP,password);        
    }
    
    msg (M_INFO, "Running %s",szCmd);
    system(szCmd);
    
    // Wait that the Hans tunnel finish to initialize and retrieve the endpoint
    memset(hans_infos.gateway_ip,0,sizeof(hans_infos.gateway_ip));
    memset(hans_infos.vpnserver_ip,0,sizeof(hans_infos.vpnserver_ip));    
    while(!guizmovpn_set_hans_gateway(hans_infos.gateway_ip))
    {
        msg (M_INFO, "Waiting for Hans to become active...");
        sleep(1);
    }
    
    msg (M_INFO,"Found Hans gateway : %s",hans_infos.gateway_ip);
}

void guizmovpn_stop_hans()
{
    if(strlen(hans_infos.vpnserver_ip) > 0)
    {
        char cmd[128];
        sprintf(cmd,"%s delete -net %s %s 255.255.255.255",ROUTE_PATH,hans_infos.vpnserver_ip,hans_infos.gateway_ip);
        msg (M_INFO,"Running %s",cmd);
        system(cmd);
    }

    system("killall -9 hans >/dev/null 2>&1");
}


void guizmovpn_get_hans_server(char *server)
{
    if(hans_infos.isActive && strlen(hans_infos.server_ip) > 0)
    {
        strncpy(server,hans_infos.server_ip,sizeof(hans_infos.server_ip));
    }
}

void guizmovpn_get_hans_gateway(char *gateway)
{
    if(hans_infos.isActive && strlen(hans_infos.gateway_ip) > 0)
    {
        strncpy(gateway,hans_infos.gateway_ip,sizeof(hans_infos.gateway_ip));
    }
}

// Set hans gateway
bool guizmovpn_set_hans_gateway(char *gateway)
{
    bool bFound=false;
    FILE *in=popen("netstat -rna", "r");
    char tmp[256]={0x0};
    while(fgets(tmp,sizeof(tmp),in)!=NULL)
    {
        if(strstr(tmp,"ppp1"))
        {
            strncpy(gateway,tmp,15);
            gateway[15]='\0';
            bFound=true;
            break;
        }
    }
    pclose(in);
    
    return bFound;
}

void guizmovpn_hans_create_route(char *remote_host)
{
    strncpy(hans_infos.vpnserver_ip,remote_host,sizeof(hans_infos.vpnserver_ip));

    char cmd[128];
    sprintf(cmd,"%s add -net %s %s 255.255.255.255",ROUTE_PATH,hans_infos.vpnserver_ip,hans_infos.gateway_ip);
    msg (M_INFO,"Running %s",cmd);
    system(cmd);
}

bool guizmovpn_stunnel_is_active()
{
    return stunnel_infos.isActive;
}

// Start stunnel
void guizmovpn_run_stunnel(char *szServerIP,int port)
{
    guizmovpn_stop_stunnel();
    
    stunnel_infos.isActive=true;
    strncpy(stunnel_infos.vpnserver_ip,szServerIP,sizeof(stunnel_infos.vpnserver_ip)-1);
    
    // Check if file exists
    FILE *fp=fopen("/usr/bin/stunnel", "r");
    if (fp!=NULL)
    {
        fclose(fp);
    } else {
        notify_post("com.guizmo.openvpn/StunnelNotFound");
        msg (M_FATAL, "Stunnel is not installed, please install it from Cydia and try again.");
    }
    
    // Generate conf file
    FILE *fpConf=fopen("/tmp/stunnel.conf","w");
    if(fpConf != NULL)
    {
        fprintf(fpConf,"client = yes\n");
        fprintf(fpConf,"pid = /tmp/stunnel.pid\n\n");
        fprintf(fpConf,"[openvpn]\n");
        fprintf(fpConf,"accept = 127.0.0.1:31194\n");
        fprintf(fpConf,"connect = %s:%d",szServerIP,port);
        fclose(fpConf);
        
        msg (M_INFO,"Running stunnel to %s:%d\n",szServerIP,port);
        system("/usr/bin/stunnel /tmp/stunnel.conf");
    }
}

// Stop stunnel
void guizmovpn_stop_stunnel()
{
    remove("/tmp/stunnel.conf");
    system("killall -9 stunnel >/dev/null 2>&1");
}

void guizmovpn_get_stunnel_server(char *server)
{
    if(stunnel_infos.isActive && strlen(stunnel_infos.vpnserver_ip) > 0)
    {
        strncpy(server,stunnel_infos.vpnserver_ip,sizeof(stunnel_infos.vpnserver_ip));
    }
}

void guizmovpn_set_client_proxy(char *szIP,char *szPort)
{
    snprintf(client_proxy_infos.server_ip,sizeof(client_proxy_infos.server_ip)-1,szIP);
    client_proxy_infos.port=atoi(szPort);
    client_proxy_infos.active=true;
    msg (M_INFO,"Received client HTTP proxy %s:%d",client_proxy_infos.server_ip,client_proxy_infos.port);
    
}