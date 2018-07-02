/**
 * @author Martin Slapak <slapak@cesnet.cz>
 *
 * @copyright Copyright 2018 CESNET a.l.e.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*******************************************************************************/

// TODO: implement logging like in: http://kev009.com/wp/2010/12/no-nonsense-logging-in-c-and-cpp/

#ifdef __cplusplus
extern "C"
{
#endif

#include "config.h"
#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"

#ifdef __cplusplus
}
#endif

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>

using namespace std;

#ifndef DSTPATH
    #define DSTPATH "/etc/systemd/network"
#endif

#define XPATH_MAX_LEN 256
#define PRIORITY 0 // greater numbers mean later called callback
#define OK 1
#define ERR 0
#define IFEXT "network"
#define PATH_MAX_LEN 256
#define IPBINARY "/bin/ip"

#define MAX(a,b) (((a)>(b))?(a):(b))

/*******************************************************************************/
/* progress of YANG model implementation                                       */
/*******************************************************************************/
/*
+--rw interfaces          
|  +--rw interface* [name]
|     +--rw name                        string            OK - W
|     +--rw description?                string            OK - W
|     +--rw type                        identityref       OK - W - only iana-if-type:ethernetCsmacd
|     +--rw enabled?                    boolean           OK - initial create when enabled
|     +--rw link-up-down-trap-enable?   enumeration       IGNORED - linkUp/linkDown SNMP notifications
+--ro interfaces-state
 +--ro interface* [name]                                  NOT IMPLEMENTED and all of following
    +--ro name               string                       PART
    +--ro type               identityref                  PART
    +--ro admin-status       enumeration
    +--ro oper-status        enumeration
    +--ro last-change?       yang:date-and-time
    +--ro if-index           int32
    +--ro phys-address?      yang:phys-address
    +--ro higher-layer-if*   interface-state-ref
    +--ro lower-layer-if*    interface-state-ref
    +--ro speed?             yang:gauge64
    +--ro statistics                                      PART
       +--ro discontinuity-time    yang:date-and-time
       +--ro in-octets?            yang:counter64
       +--ro in-unicast-pkts?      yang:counter64
       +--ro in-broadcast-pkts?    yang:counter64
       +--ro in-multicast-pkts?    yang:counter64
       +--ro in-discards?          yang:counter32
       +--ro in-errors?            yang:counter32
       +--ro in-unknown-protos?    yang:counter32
       +--ro out-octets?           yang:counter64
       +--ro out-unicast-pkts?     yang:counter64
       +--ro out-broadcast-pkts?   yang:counter64
       +--ro out-multicast-pkts?   yang:counter64
       +--ro out-discards?         yang:counter32
       +--ro out-errors?           yang:counter3
 
 
/ietf-interfaces:interfaces/interface[name='XYZ']/ietf-ip:(ipv4|ipv6)
module: ietf-ip
 augment /if:interfaces/if:interface:
   +--rw ipv4!
   |  +--rw enabled?      boolean                                     OK - W
   |  +--rw forwarding?   boolean                                     OK - W
   |  +--rw mtu?          uint16                                      OK - W
   |  +--rw address* [ip]
   |  |  +--rw ip               inet:ipv4-address-no-zone             OK - W
   |  |  +--rw (subnet)
   |  |  |  +--:(prefix-length)                                       OK - W
   |  |  |  |  +--rw prefix-length?   uint8
   |  |  |  +--:(netmask)
   |  |  |     +--rw netmask?         yang:dotted-quad                ERR - sysrepo bug?
   |  |  |             {ipv4-non-contiguous-netmasks}?
   |  |  +--ro origin?          ip-address-origin                     IGNORED
   |  +--rw neighbor* [ip]
   |     +--rw ip                    inet:ipv4-address-no-zone        OK - W
   |     +--rw link-layer-address    yang:phys-address                OK - W
   |     +--ro origin?               neighbor-origin                  IGNORED
   +--rw ipv6!
      +--rw enabled?                     boolean                      OK - W
      +--rw forwarding?                  boolean                      OK - W
      +--rw mtu?                         uint32                       OK - W
      +--rw address* [ip]
      |  +--rw ip               inet:ipv6-address-no-zone             OK - W
      |  +--rw prefix-length    uint8                                 OK - W
      |  +--ro origin?          ip-address-origin                     IGNORED
      |  +--ro status?          enumeration                           IGNORED
      +--rw neighbor* [ip]
      |  +--rw ip                    inet:ipv6-address-no-zone        OK - W
      |  +--rw link-layer-address    yang:phys-address                OK - W
      |  +--ro origin?               neighbor-origin                  IGNORED
      |  +--ro is-router?            empty                            IGNORED
      |  +--ro state?                enumeration                      IGNORED
      +--rw dup-addr-detect-transmits?   uint32                       OK - W
 
*/
/*******************************************************************************/
/*
 * Handle sysrepo return codes and log optional error when needed.
 */
static int handle_sr_return(int rc, string xpath = "") {
    if (SR_ERR_NOT_FOUND == rc) {
        syslog(LOG_DEBUG, "NOT FOUND error %s : %s\n", &xpath[0u], sr_strerror(rc));
        printf("NOT FOUND error %s : %s\n", &xpath[0u], sr_strerror(rc));
        return ERR;
    } else if (SR_ERR_OK != rc) {
        syslog(LOG_DEBUG, "GENERIC error %s : %s\n", &xpath[0u], sr_strerror(rc));
        printf("GENERIC error %s : %s\n", &xpath[0u], sr_strerror(rc));
        return ERR;
    }
    return OK; // no error
}

/*******************************************************************************/
/*
 * Retrieve a value from sysrepo based on xpath.
 */
static sr_val_t *get_val(sr_session_ctx_t *session, string xpath) {
    int rc = SR_ERR_OK;
    sr_val_t *data = NULL;
    rc = sr_get_item(session, &xpath[0u], &data);
    handle_sr_return(rc, xpath);
    return data;
}

/*******************************************************************************/
/*
 * Create dir path sequentially
 */
// source & inspiration: https://stackoverflow.com/a/12904145
static int mkpath(string s, mode_t mode) {
    size_t pre=0, pos;
    string dir;
    int ret;

    // force trailing / so we can handle everything in loop
    if(s[s.size()-1]!='/'){
        s+='/';
    }

    while((pos = s.find_first_of('/',pre)) != string::npos){
        dir = s.substr(0, pos++);
        pre = pos;
        if(dir.size() == 0) continue; // if leading / first time is 0 length
        if((ret = mkdir(dir.c_str(), mode)) && errno != EEXIST){
            return ret;
        }
    }
    return ret;
}

/*******************************************************************************/
/*
 * Use ip utility to add entry to ARP cache.
 *
 * calls: ip neigh add <IP> lladdr <MAC> dev <DEV>
*/
// TODO: forks should away to one central point :-/
// void exec_process(const std::vector<std::string>& args) 
// alternatively: https://stackoverflow.com/questions/35910479/how-to-clear-arp-cache-in-linux-by-program-not-command
// https://svn.nmap.org/nmap/libdnet-stripped/src/arp-ioctl.c
static int add_arp_cache_entry(char * devname, string addr, string lladdr) {
    int pid, status;
    
    string cmd = "neigh add "+addr+" lladdr "+lladdr+" dev "+devname;    
    cout << "Adding this entry: " << cmd << endl;
    syslog(LOG_DEBUG, "Adding this entry: %s\n", &cmd[0u]);
    
    if ((pid = fork())) {
       // pid != 0 parent
       waitpid(pid, &status, 0);
       printf("Binary %s returned status code = %d\n", IPBINARY, status);
       if (status == 0)   syslog(LOG_DEBUG, "ARP CACHE entry %s -> %s sucessfully added.\n", &addr[0u], &lladdr[0u]);
       if (status == 512) syslog(LOG_DEBUG, "ARP CACHE entry %s -> %s already exists.\n", &addr[0u], &lladdr[0u]);
    } else {
       // pid == 0 child
       int ret = execl(IPBINARY, "-v", "neigh", "add", &addr[0u], "lladdr", &lladdr[0u], "dev", devname, NULL);
       // reachable only when command failed
       printf("Something wrong happened during call %s neigh add, returned code = %d\n", IPBINARY, ret);
       syslog(LOG_DEBUG, "Something wrong happened during call %s neigh add, returned code = %d\n", IPBINARY, ret);
    }
    return status;
}

/*******************************************************************************/
/*
 * Use ip utility to del entry from ARP cache.
 *
 * calls: ip neigh del <IP> lladdr <MAC> dev <DEV>
*/
static int del_arp_cache_entry(char * devname, string addr, string lladdr) {
    int pid, status;
    
    string cmd = "neigh del "+addr+" lladdr "+lladdr+" dev "+devname;    
    cout << "Deleting this entry: " << cmd << endl;
    syslog(LOG_DEBUG, "Deleting this entry: %s\n", &cmd[0u]);
    
    if ((pid = fork())) {
       // pid != 0 parent
       waitpid(pid, &status, 0);
       printf("Binary %s returned status code = %d\n", IPBINARY, status);
       if (status == 0)   syslog(LOG_DEBUG, "ARP CACHE entry %s -> %s sucessfully deleted.\n", &addr[0u], &lladdr[0u]);
       if (status == 512) syslog(LOG_DEBUG, "ARP CACHE entry %s -> %s already exists.\n", &addr[0u], &lladdr[0u]);
    } else {
       // pid == 0 child
       int ret = execl(IPBINARY, "-v", "neigh", "del", &addr[0u], "lladdr", &lladdr[0u], "dev", devname, NULL);
       // reachable only when command failed
       printf("Something wrong happened during call %s neigh del, returned code = %d\n", IPBINARY, ret);
       syslog(LOG_DEBUG, "Something wrong happened during call %s neigh del, returned code = %d\n", IPBINARY, ret);
    }
    return status;
}

/*******************************************************************************/
/*
 * Map elements in ipv4/neighbor* to entries of ARP cache.
*/
static void create_arp_cache_entries(sr_session_ctx_t *session, char *devname, int ipv) {
    syslog(LOG_DEBUG, "create_arp_cache_entries called\n");
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    // shortcut for xpath queries
    string ifipvXxpath = "/ietf-interfaces:interfaces/interface[name='"+(string)devname+"']/ietf-ip:ipv"+to_string(ipv);
    string xpath = ifipvXxpath + "/neighbor/ip";
    rc = sr_get_items(session, &xpath[0u], &values, &count);
    if (handle_sr_return(rc, xpath) == OK) {
        for (size_t i = 0; i < count; i++){
            string addr = (string)(&values[i])->data.string_val;
            sr_val_t *ipvlladdress = get_val(session, ifipvXxpath + "/neighbor[ip='"+addr+"']/link-layer-address");
            
            string lladdr = (string)ipvlladdress->data.string_val;

            add_arp_cache_entry(devname, addr, lladdr);

            sr_free_val(ipvlladdress);
        }
        sr_free_values(values, count);
    }
}

/*******************************************************************************/
/* 
 * Handle IPv4/6 forwarding
 * IPForward accepts boolean value or "ipv4" or "ipv6"
 * systemd boolean true = (1, yes, on, true); false = (0, no off, false)
 */
static void set_forwarding(sr_session_ctx_t *session, ini_table_s* ifcfg, char *name) {
    string ifipv6xpath = "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/ietf-ip:ipv6/forwarding";
    string ifipv4xpath = "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/ietf-ip:ipv4/forwarding";
    
    sr_val_t *ipv4forward = get_val(session, ifipv4xpath);
    sr_val_t *ipv6forward = get_val(session, ifipv6xpath);
    
    // new entries will be overwriten
    if (ipv6forward != NULL && ipv4forward != NULL && ipv6forward->data.bool_val && ipv4forward->data.bool_val) {        
        ini_table_create_entry(ifcfg, "Network", "IPForward", "yes");
    } else if (ipv4forward != NULL && ipv4forward->data.bool_val) {
        ini_table_create_entry(ifcfg, "Network", "IPForward", "ipv4");
    } else if (ipv6forward != NULL && ipv6forward->data.bool_val) {
        ini_table_create_entry(ifcfg, "Network", "IPForward", "ipv6");
    } else {
        // no is default, may be ommited
        ini_table_create_entry(ifcfg, "Network", "IPForward", "no");
    }
    sr_free_val(ipv4forward);
    sr_free_val(ipv6forward);
}

/*******************************************************************************/
/* 
 * Handle MTU byte size
 * notice: MTU sizes with suffixes (e.g. K, M, G) is not supported by sysrepo.
 * notice: minimum MTU size for IPv6 is 1280, we handle it for networkd
 */
static void set_mtu(sr_session_ctx_t *session, ini_table_s* ifcfg, char *name) {
    string ifipv6xpath = "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/ietf-ip:ipv6/mtu";
    string ifipv4xpath = "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/ietf-ip:ipv4/mtu";
    
    sr_val_t *ipv4mtu = get_val(session, ifipv4xpath);
    sr_val_t *ipv6mtu = get_val(session, ifipv6xpath);
    
    // new entries will be overwriten
    if (ipv4mtu != NULL && ipv6mtu != NULL) {
        uint16_t mtu = MAX(ipv4mtu->data.uint16_val, ipv6mtu->data.uint16_val);
        if (mtu < 1280) mtu = 1280;
        string smtu = to_string(mtu);
        ini_table_create_entry(ifcfg, "Link", "MTUBytes", &smtu[0u]);
    } else if (ipv4mtu != NULL) {
        string smtu = to_string(ipv4mtu->data.uint16_val);
        ini_table_create_entry(ifcfg, "Link", "MTUBytes", &smtu[0u]);
    } else if (ipv6mtu != NULL) {
        uint16_t mtu = ipv6mtu->data.uint16_val;
        if (mtu < 1280) mtu = 1280;
        string smtu = to_string(mtu);
        ini_table_create_entry(ifcfg, "Link", "MTUBytes", &smtu[0u]);
    }
    
    sr_free_val(ipv4mtu);
    sr_free_val(ipv6mtu);
}

/*******************************************************************************/
/* 
 * Set DHCP
 * Accepts "yes", "no", "ipv4", or "ipv6". Defaults to "no".
 * 
 * ugly temporary hack to determine DHCP - DHCP is used when description starts with "DHCPv4" od "DHCPv6"
 */
static bool set_dhcp(sr_session_ctx_t *session, ini_table_s* ifcfg, char *name) {
    sr_val_t *description = get_val(session, "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/description");
    bool r = true;
    if (description != NULL) {
        string sdesc = (string) description->data.string_val;
        //cout << "DHCPDHCPDHCP -> " << sdesc.substr(0,6) << endl;
        
        if ((sdesc.substr(0,6).compare("DHCPv4") == 0) && (sdesc.substr(0,6).compare("DHCPv6") == 0)) {
            ini_table_create_entry(ifcfg, "Network", "DHCP", "yes");
        } else if (sdesc.substr(0,6).compare("DHCPv4") == 0) {
            ini_table_create_entry(ifcfg, "Network", "DHCP", "ipv4");
        } else if (sdesc.substr(0,6).compare("DHCPv6") == 0) {
            ini_table_create_entry(ifcfg, "Network", "DHCP", "ipv6");
        } else {
            r = false;
            // no is default, may be ommited
            ini_table_create_entry(ifcfg, "Network", "DHCP", "no");
        }
    }
    
    sr_free_val(description);
    return r;
}

/*******************************************************************************/
/* 
 * Set DNS
 * requires proper entries in eitf-system module
 */
static void set_dns(sr_session_ctx_t *session, ini_table_s* ifcfg, char *name) {
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    string xpath = "/ietf-system:system/dns-resolver/server/name";
    string dnsprefix = "/ietf-system:system/dns-resolver";
    rc = sr_get_items(session, &xpath[0u], &values, &count);
    if (handle_sr_return(rc) == OK) {
        for (size_t i = 0; i < count; i++){
            sr_val_t *dnsip = get_val(session, dnsprefix + "/server[name='"+(string)(&values[i])->data.string_val+"']/udp-and-tcp/address");
            
            // probably not supproted by systemd.networkd config
            //sr_val_t *dnsport = get_val(session, dnsprefix + "/server[name='"+(string)(&values[i])->data.string_val+"']/udp-and-tcp/port");
            
            if (dnsip != NULL) {
                string sdnsip = dnsip->data.string_val;
                printf("DNS ip = %s\n", &sdnsip[0u]);
                ini_table_create_entry_duplicate(ifcfg, "Network", "DNS", &sdnsip[0u]);
            }
            /*
            if (dnsport != NULL) {
                printf("DNS port = %s\n", dnsport->data.string_val);
                ini_table_create_entry_duplicate(ifcfg, "Network", "DNS", &addr[0u]);
            }
            * sr_free_val(dnsport);
            */

            sr_free_val(dnsip);
            

        }
        sr_free_values(values, count);
    }
}

/*******************************************************************************/
/* 
 * Set default gateway
 * requires proper entries in eitf-system module
 */
static void set_gateway(sr_session_ctx_t *session, ini_table_s* ifcfg, char *name) {
    // ini_table_create_entry(ifcfg, "Network", "Gateway", "");
    
    string xpath = "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='ietf-routing:static'][name='st0']/static-routes/ietf-ipv4-unicast-routing:ipv4/route[destination-prefix='0.0.0.0/0']/next-hop/next-hop-address";
    
    
}
    
/*******************************************************************************/
/* 
 * Add interface stuff for IPv4
 */
static void interface_ipv4(sr_session_ctx_t *session, ini_table_s* ifcfg, char *name) {
    string xpath = "";
    string ifipv4xpath = "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/ietf-ip:ipv4";
    
    set_forwarding(session, ifcfg, name);
    set_mtu(session, ifcfg, name);
    bool is_dhcp = set_dhcp(session, ifcfg, name);

    if (!is_dhcp) {
        // STATIC adresses
        sr_val_t *values = NULL;
        size_t count = 0;
        int rc = SR_ERR_OK;
        xpath = ifipv4xpath + "/address/ip";
        rc = sr_get_items(session, &xpath[0u], &values, &count);
        if (handle_sr_return(rc) == OK) {
            for (size_t i = 0; i < count; i++){
                //printf("IPv4 ip = %s\n", (&values[i])->data.string_val);

                sr_val_t *ipv4prefixlen = get_val(session, ifipv4xpath + "/address[ip='"+(string)(&values[i])->data.string_val+"']/prefix-length");

                sr_val_t *ipv4netmask = get_val(session, ifipv4xpath + "/address[ip='"+(string)(&values[i])->data.string_val+"']/netmask");
                
                // prepare output of addr + prefix len / netmask
                string addr = (string)(&values[i])->data.string_val;
                if (ipv4prefixlen != NULL) {
                    addr += "/" + to_string(ipv4prefixlen->data.uint8_val);
                }
                if (ipv4netmask != NULL) {
                    addr += "/" + (string)ipv4netmask->data.string_val;
                    cout << "Netmask is prefferef over prefix-len." << endl;
                }

                // it is possible to have more addres, need to create entry allowing duplicate key
                ini_table_create_entry_duplicate(ifcfg, "Network", "Address", &addr[0u]);

                sr_free_val(ipv4prefixlen);
                sr_free_val(ipv4netmask);
            }
            sr_free_values(values, count);
        }
    }

    // create ARP cache entries defined by ipv{4|6}/neighbor*
    create_arp_cache_entries(session, name, 4);
}

/*******************************************************************************/
/* 
 * Add interface stuff for IPv6
 */
static void interface_ipv6(sr_session_ctx_t *session, ini_table_s* ifcfg, char *name) {
    string xpath = "";
    string ifipv6xpath = "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/ietf-ip:ipv6";
    
    set_forwarding(session, ifcfg, name);
    set_mtu(session, ifcfg, name);
    bool is_dhcp = set_dhcp(session, ifcfg, name);
    
    if (!is_dhcp) {
        // STATIC adresses
        sr_val_t *values = NULL;
        size_t count = 0;
        int rc = SR_ERR_OK;
        xpath = ifipv6xpath + "/address/ip";
        rc = sr_get_items(session, &xpath[0u], &values, &count);
        if (handle_sr_return(rc) == OK) {
            for (size_t i = 0; i < count; i++){
                //printf("IPv6 ip = %s\n", (&values[i])->data.string_val);

                sr_val_t *ipv6prefixlen = get_val(session, ifipv6xpath + "/address[ip='"+(string)(&values[i])->data.string_val+"']/prefix-length");
                
                // prepare output of addr + prefix len / netmask
                string addr = (string)(&values[i])->data.string_val;
                if (ipv6prefixlen != NULL) {
                    addr += "/" + to_string(ipv6prefixlen->data.uint8_val);
                }

                // it is possible to have more addres, need to create entry allowing duplicate key
                ini_table_create_entry_duplicate(ifcfg, "Network", "Address", &addr[0u]);

                sr_free_val(ipv6prefixlen);
            }
            sr_free_values(values, count);
        }
    }
    
    // create ARP cache entries defined by ipv{4|6}/neighbor*
    create_arp_cache_entries(session, name, 6);
    
    // duplicite address detection
    sr_val_t *ipv6detectdup = get_val(session, ifipv6xpath + "/dup-addr-detect-transmits");
    if (ipv6detectdup != NULL) {
        string detectdup = to_string(ipv6detectdup->data.uint32_val);
        ini_table_create_entry(ifcfg, "Network", "IPv6DuplicateAddressDetection", &detectdup[0u]);
    }
}
    

/*******************************************************************************/
/* 
 * Create interface
 */
static void create_interface(sr_session_ctx_t *session, char *name) {
    printf("Creating interface %s\n", name);
    char dst[PATH_MAX_LEN];
    sprintf(dst, "%s/%s.%s", DSTPATH, name, IFEXT);
    printf("Ouput file = %s\n", dst);

    string xpath = "";

    sr_val_t *enabled = get_val(session, "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/enabled");
    //printf("Enabled = %s\n", enabled->data.bool_val ? "true" : "false");

    sr_val_t *type = get_val(session, "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/type");
    //printf("Type %d %d = %s\n", type->type, SR_IDENTITYREF_T, type->data.identityref_val);

    sr_val_t *description = get_val(session, "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/description");
    string sdesc = "; " + (string) description->data.string_val;

    // proceed only to enabled and known interface type
    if (enabled->data.bool_val && strcmp("iana-if-type:ethernetCsmacd", type->data.identityref_val) == 0) {

        // prepare dict for output config
        ini_table_s* ifcfg = ini_table_create();
        ini_table_create_entry(ifcfg, "Match", &sdesc[0u], "");
        ini_table_create_entry(ifcfg, "Match", "Name", name);

        sr_val_t *ipv4enabled = get_val(session, "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/ietf-ip:ipv4/enabled");
        // iface has ipv4 enabled
        if (ipv4enabled != NULL && ipv4enabled->data.bool_val) {
            interface_ipv4(session, ifcfg, name);
        }
        sr_free_val(ipv4enabled);

        sr_val_t *ipv6enabled = get_val(session, "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/ietf-ip:ipv6/enabled");
        // iface has ipv6 enabled
        if (ipv6enabled != NULL && ipv6enabled->data.bool_val) {
            interface_ipv6(session, ifcfg, name);
        }
        sr_free_val(ipv6enabled);
        
        // if at least one routing is enabled
        if ((ipv4enabled != NULL && ipv4enabled->data.bool_val) || (ipv6enabled != NULL && ipv6enabled->data.bool_val)) {
            set_dns(session, ifcfg, name);
            set_gateway(session, ifcfg, name);
        }

        // write cfg to file
        ini_table_write_to_file(ifcfg, dst);
        ini_table_print(ifcfg);
        ini_table_destroy(ifcfg);

    }

    sr_free_val(enabled);
    sr_free_val(type);
    sr_free_val(description);
}

/*******************************************************************************/
static void print_current_config(sr_session_ctx_t *session) {
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char select_xpath[XPATH_MAX_LEN];
    snprintf(select_xpath, XPATH_MAX_LEN, "/ietf-interfaces:*//*");

    rc = sr_get_items(session, select_xpath, &values, &count);
    if (handle_sr_return(rc) == ERR) return;

    for (size_t i = 0; i < count; i++){
        sr_print_val(&values[i]);
    }
    sr_free_values(values, count);
}

/*******************************************************************************/
static void apply_current_config(sr_session_ctx_t *session) {
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    printf("-------------------------------------------------\n");
    string xpath = "/ietf-interfaces:interfaces/interface/name";

    rc = sr_get_items(session, &xpath[0u], &values, &count);
    if (handle_sr_return(rc) == ERR) return;

    for (size_t i = 0; i < count; i++){
        create_interface(session, (&values[i])->data.string_val);
    }
    sr_free_values(values, count);
}
/*******************************************************************************/
static int ifstats_dataprovider_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    //syslog(LOG_DEBUG, "ifstats_dataprovider_cb");
    //printf("ifstats_dataprovider_cb called XP: %s\n", xpath);
    
    ///sys/class/net/
    // inspirace zde https://github.com/CESNET/netopeer/blob/e27e01de053b296e2cacb406b76bef7b6b11f94c/transAPI/cfginterfaces/iface_nm(unused).c
    
    sr_val_t *v = NULL;
    int rc = SR_ERR_OK;
    
    if (sr_xpath_node_name_eq(xpath, "interface")) {
        // funguje dotaz napr:  ./srgetxpath "/ietf-interfaces:interfaces-state/interface[name='eth0']//*"
        cout << "IFACE XP: " << xpath << endl;
        
        rc = sr_new_values(4, &v);
        if (SR_ERR_OK != rc) return rc;
        
        // TODO: reflect real state!!!
        sr_val_set_xpath(&v[0], "/ietf-interfaces:interfaces-state/interface[name='eth0']/type");
        sr_val_set_str_data(&v[0], SR_IDENTITYREF_T, "ethernetCsmacd");

        sr_val_set_xpath(&v[1], "/ietf-interfaces:interfaces-state/interface[name='eth0']/oper-status");
        sr_val_set_str_data(&v[1], SR_ENUM_T, "down");

        sr_val_set_xpath(&v[2], "/ietf-interfaces:interfaces-state/interface[name='eth1']/type");
        sr_val_set_str_data(&v[2], SR_IDENTITYREF_T, "iana-if-type:ethernetCsmacd");

        sr_val_set_xpath(&v[3], "/ietf-interfaces:interfaces-state/interface[name='eth1']/oper-status");
        sr_val_set_str_data(&v[3], SR_ENUM_T, "up");
        
        *values = v;
        *values_cnt = 4;

        
    } else if (sr_xpath_node_name_eq(xpath, "statistics")) {
        // NE funguje dotaz napr:  ./srgetxpath "/ietf-interfaces:interfaces-state/interface[name='eth0']/statistics//*"
        cout << "STATS XP: " << xpath << endl;
        
        int fields = 14;
        rc = sr_new_values(fields, &v);
        if (SR_ERR_OK != rc) return rc;
        
        printf("%s/%s\n", xpath, "discontinuity-time");
        
        int i = 0;
        // this is probably unknow value
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "discontinuity-time");
        sr_val_set_str_data(&v[i], SR_STRING_T, "2018-07-01T00:00:00.42Z");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "in-octets");
        sr_val_set_str_data(&v[i], SR_UINT64_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "in-unicast-pkts");
        sr_val_set_str_data(&v[i], SR_UINT64_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "in-broadcast-pkts");
        sr_val_set_str_data(&v[i], SR_UINT64_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "in-multicast-pkts");
        sr_val_set_str_data(&v[i], SR_UINT64_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "in-discards");
        sr_val_set_str_data(&v[i], SR_UINT32_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "in-errors");
        sr_val_set_str_data(&v[i], SR_UINT32_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "in-unknown-protos");
        sr_val_set_str_data(&v[i], SR_UINT32_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "out-octets");
        sr_val_set_str_data(&v[i], SR_UINT64_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "out-unicast-pkts");
        sr_val_set_str_data(&v[i], SR_UINT64_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "out-broadcast-pkts");
        sr_val_set_str_data(&v[i], SR_UINT64_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "out-multicast-pkts");
        sr_val_set_str_data(&v[i], SR_UINT64_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "out-discards");
        sr_val_set_str_data(&v[i], SR_UINT32_T, "42");
        
        i++;
        sr_val_build_xpath(&v[i], "%s/%s", xpath, "out-errors");
        sr_val_set_str_data(&v[i], SR_UINT32_T, "42");
        
        *values = v;
        *values_cnt = fields;
        
        cout << "prepared " << fields << " elements" << endl;
        return SR_ERR_OK;
        
    } else {
        cout << "GENERAL XP: " << xpath << endl;
        
        *values = NULL;
        values_cnt = 0;
    }
    
    return SR_ERR_OK;
}
/*******************************************************************************/
