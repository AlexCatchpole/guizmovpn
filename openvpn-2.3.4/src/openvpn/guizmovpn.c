//
//  guizmovpn.c
//  OpenVPN
//
//  Created by Guillaume Duteil on 12/08/2014.
//
//

#include "config.h"
#include "syshead.h"


#include <notify.h>
#include <stdio.h>
#include <sys/errno.h>
#include "error.h"
#include "buffer.h"
#include "misc.h"
#include "options.h"
#include <netdb.h>

#include "guizmovpn.h"
#include "tapemu.h"

static guizmovpn_context guizmovpn_ctx;

/*
 * GuizmOVPN_init() :
 *      Init GuizmOVPN context
 */
void GuizmOVPN_init()
{
    guizmovpn_ctx.bAutoproxy=false;
    memset(guizmovpn_ctx.client_proxy_ip,0,sizeof(guizmovpn_ctx.client_proxy_ip));
    guizmovpn_ctx.client_proxy_port=0;
}

/*
 * GuizmOVPN_initialization_sequence_completed() :
 *      Handle actions when tunnel is initialized
 */
void GuizmOVPN_initialization_sequence_completed()
{
	notify_post("com.guizmo.openvpn/StatusIconAdd");
}

/*
 * GuizmOVPN_close_tun() :
 *      Handle actions when tunnel is closed
 */
void GuizmOVPN_close_tun()
{
    tapemu_clear();
    
	notify_post("com.guizmo.openvpn/StatusIconRemove");
}

/*
 * GuizmOVPN_Error(int errorno) :
 *      Send notification when an error occurs
 */
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

/*
 * GuizmOVPN_get_user_pass(char *username,char *password,const int capacity, char * prefix) :
 *      Request username/password from the user
 */
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
		msg (M_FATAL, "Unknown user/pass request : %s",prefix);
		return;
	}
	
    msg (M_INFO, "Waiting for username/password (%s)",prefix);
	// May need to do a cleaner wait
	int received=0;
	while(!received)
	{
		status = notify_check(token, &check);
		if ((status == NOTIFY_STATUS_OK) && (check != 0))
		{
			msg (M_INFO,"Username/password received");
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
 * GuizmOVPN_ReadPrefs(char *pref,char *value) :
 *      Read app preferences (returns false if not found)
 */
bool GuizmOVPN_ReadPrefs(char *pref,char *value)
{
	char buf[255];
	char temp[32];
	char key[128];
	char val[64]="\0";
	char *pch;
	bool bFound=false;
    
	memset(buf,0,sizeof(buf));
	
	FILE *fp=fopen(GUIZMOVPN_PREFS,"r");
	
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
					strcpy(key,pch);
				}
			}
            
			if(strstr(buf,"<string>"))
			{
				memset(val,0,sizeof(val));
				sscanf(buf," <string>%64s</string>",temp);
                
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
                    bFound=true;
					break;
				}
			}
		}
		fclose(fp);
	}
    
    return bFound;
}

/*
 * GuizmOVPN_tools (const char *szParam) :
 *      Run exernal tools app
 */
void GuizmOVPN_tools(const char *szParam)
{
    char szCmd[255];
    snprintf(szCmd, sizeof(szCmd)-1, "%s %s",GUIZMOVPN_TOOLS,szParam);
    system(szCmd);
}

/*
 * GuizmOVPN_get_auto_proxy (struct gc_arena *gc) :
 *      Detect proxy settings
 */
struct auto_proxy_info *GuizmOVPN_get_auto_proxy (struct gc_arena *gc)
{
    guizmovpn_ctx.bAutoproxy=true;
    
    GuizmOVPN_tools("handle_proxy");
    
    struct auto_proxy_info *pi;
    
    char szHTTPProxyIP[32];
    char szHTTPProxyPort[32];
    int32_t HTTPProxyPort=0;
    
    szHTTPProxyIP[0]='\0';
    GuizmOVPN_ReadPrefs("HTTPProxy",szHTTPProxyIP);
    
    szHTTPProxyPort[0]='\0';
    GuizmOVPN_ReadPrefs("HTTPPort",szHTTPProxyPort);
    HTTPProxyPort=atoi(szHTTPProxyPort);
    
    if(strlen(szHTTPProxyIP)>7 && HTTPProxyPort>=0)
    {
        ALLOC_OBJ_CLEAR_GC (pi, struct auto_proxy_info, gc);
        pi->http.server=string_alloc(szHTTPProxyIP,gc);
        pi->http.port = HTTPProxyPort;
        
        msg (M_INFO,"Proxy detected : %s:%d",szHTTPProxyIP,HTTPProxyPort);
        return pi;
    } else {
    	return NULL;
    }
}

/*
 * GuizmoVPN_autoproxy_is_set() :
 *      Restore proxy if needed
 */
bool GuizmoVPN_autoproxy_is_set()
{
    return guizmovpn_ctx.bAutoproxy;
}

/*
 * GuizmOVPN_RestoreProxy() :
 *      Restore proxy if needed
 */
void GuizmOVPN_RestoreProxy()
{
    GuizmOVPN_tools("restore_proxy");
}

/*
 * GuizmOVPN_set_client_proxy(char *szIP, char *szPort) :
 *      Set proxy when the tunnel is active
 */
void GuizmOVPN_set_client_proxy(char *szIP,char *szPort)
{
    strncpy(guizmovpn_ctx.client_proxy_ip,szIP,sizeof(guizmovpn_ctx.client_proxy_ip)-1);
    guizmovpn_ctx.client_proxy_port=atoi(szPort);
    msg (M_INFO,"Received client HTTP proxy %s:%d",guizmovpn_ctx.client_proxy_ip,guizmovpn_ctx.client_proxy_port);
    
}

/*
 * GuizmOVPN_updown (const char *command, const struct plugin_list *plugins, int plugin_type, const char *arg, const char *dev_type, int tun_mtu, int link_mtu, const char *ifconfig_local, const char* ifconfig_remote, const char *context, const char *signal_text, const char *script_type, struct env_set *es) :
 *      Run external script
 */
void GuizmOVPN_updown (const char *command,
                       const struct plugin_list *plugins,
                       int plugin_type,
                       const char *arg,
                       const char *dev_type,
                       int tun_mtu,
                       int link_mtu,
                       const char *ifconfig_local,
                       const char* ifconfig_remote,
                       const char *context,
                       const char *signal_text,
                       const char *script_type,
                       struct env_set *es)
{
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
    
    setenv_str (es, "InfosGateway", tapemu_ip_to_string(tapemu_get_remote_ip()));
    
    if (!context)
        context = "";
    
    static struct argv guizmovpn_argv;
    argv_reset(&guizmovpn_argv);
    guizmovpn_argv = argv_new ();
    
    ASSERT (arg);
    setenv_str (es, "script_type", script_type);
    
    char szTemp[32];
    szTemp[0]='\0';
    GuizmOVPN_ReadPrefs("DNSPush",szTemp);
    if(strcmp(szTemp,"NO") != 0)
    {
        setenv_str (es, "DNSPush", "Y");
    }
    
    GuizmOVPN_ReadPrefs("DNSKeep",szTemp);
    if(strcmp(szTemp,"NO") != 0)
    {
        setenv_str (es, "DNSKeep", "Y");
    }
    
    szTemp[0]='\0';
    GuizmOVPN_ReadPrefs("Multicast",szTemp);
    
    if(dev_type!=NULL && !strcmp(dev_type,"tap") && strcmp(szTemp,"NO") != 0)
    {
        setenv_str (es, "Multicast", "Y");
    }
    
/*    if(client_proxy_infos.active)
    {
        setenv_str (es, "ClientProxyIP", client_proxy_infos.server_ip);
        setenv_int (es, "ClientProxyPort", client_proxy_infos.port);
    }*/
    
    argv_printf (&guizmovpn_argv,
                 "%sc %s %d %d %s %s %s",
                 GUIZMOVPN_COMMAND,
                 arg,
                 tun_mtu, link_mtu,
                 ifconfig_local, ifconfig_remote,
                 context);
    
    openvpn_execve (&guizmovpn_argv, es, 0);
}
