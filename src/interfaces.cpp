/**
 * @author Martin Slapak <slapak@cesnet.cz>
 *
 * @copyright
 * Copyright 2018 CESNET a.l.e.
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

#define XPATH_MAX_LEN 256
#define PRIORITY 0 // greater numbers mean later called callback
#define OK 1
#define ERR 0
#define DSTPATH "/etc/systemd/network"
#define IFEXT "network"
#define PATH_MAX_LEN 256

static int handle_sr_return(int rc, string xpath = "") {
    if (SR_ERR_NOT_FOUND == rc) {
        syslog(LOG_DEBUG, "NOT FOUND error %s : %s\n", &xpath[0u], sr_strerror(rc));
        printf("NOT FOUND error %s : %s\n", &xpath[0u], sr_strerror(rc));
        return ERR;
    } else if (SR_ERR_OK != rc) {
        syslog(LOG_DEBUG, "GENERIC error %s : %s\n", &xpath[0u], sr_strerror(rc));
        printf("GENERIC error %s : %s\n", &xpath[0u], sr_strerror(rc));
        return ERR;
    } else {
        return OK; // no error
    }
}

static sr_val_t *get_val(sr_session_ctx_t *session, string xpath) {
    int rc = SR_ERR_OK;
    sr_val_t *data = NULL;
    rc = sr_get_item(session, &xpath[0u], &data);
    handle_sr_return(rc, xpath);
    return data;
}

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
    
    // ugly temporary hack to determine DHCP - DHCP is used when description starts with "DHCP"
    bool is_dhcp = (sdesc.substr(2,4).compare("DHCP") == 0);
    
    // proceed only to enabled and known interface type
    if (enabled->data.bool_val && strcmp("iana-if-type:ethernetCsmacd", type->data.identityref_val) == 0) {
        // shortcut for xpath queries
        string ifipv4xpath = "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/ietf-ip:ipv4";
        
        // prepare dict for output config
        ini_table_s* ifcfg = ini_table_create();
        ini_table_create_entry(ifcfg, "Match", &sdesc[0u], "");
        ini_table_create_entry(ifcfg, "Match", "Name", name);
        
        sr_val_t *ipv4enabled = get_val(session, ifipv4xpath + "/enabled");
        //if (ipv4enabled != NULL) printf("IPv4 enabled = %s\n", ipv4enabled->data.bool_val ? "true" : "false");
        
        // FIX: default je true
        // iface has ipv4 enabled
        if (ipv4enabled != NULL && ipv4enabled->data.bool_val) {
        
            sr_val_t *ipv4forward = get_val(session, ifipv4xpath + "/forwarding");
            //printf("IPv4 forward = %s\n", ipv4forward->data.bool_val ? "true" : "false");
            if (ipv4forward->data.bool_val) ini_table_create_entry(ifcfg, "Network", "IPForward", "ipv4");
            
            sr_val_t *ipv4mtu = get_val(session, ifipv4xpath + "/mtu");
            //printf("IPv4 mtu = %d\n", ipv4mtu->data.uint16_val);
            string mtu = to_string(ipv4mtu->data.uint16_val);
            if (ipv4mtu != NULL) ini_table_create_entry(ifcfg, "Link", "MTUBytes", &mtu[0u]);
            
            if (is_dhcp) {
                // DHCP
                ini_table_create_entry(ifcfg, "Network", "DHCP", "ipv4");
            } else {
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
                        //printf("IPv4 prefixlen = %d\n", ipv4prefixlen->data.uint8_val);
                        
                        // TODO: also netmask keyword is possible
                        
                        string addr = (string)(&values[i])->data.string_val + "/" + to_string(ipv4prefixlen->data.uint8_val);
                        // it is possible to have more addres, need to create entry allowing duplicate key
                        ini_table_create_entry_duplicate(ifcfg, "Network", "Address", &addr[0u]);
                        
                        // TODO: Gateway DNS
                        // ini_table_create_entry(ifcfg, "Network", "Gateway", "");
                        // ini_table_create_entry(ifcfg, "Network", "DNS", "");
                        
                        sr_free_val(ipv4prefixlen);
                    }
                    sr_free_values(values, count);
                }
            }            
            
            // TODO: get also neighbor* -> ip, link-layer-address

            sr_free_val(ipv4forward);
            sr_free_val(ipv4mtu);
        }
        sr_free_val(ipv4enabled);
        
        
        string ifipv6xpath = "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/ietf-ip:ipv6";
        sr_val_t *ipv6enabled = get_val(session, ifipv6xpath + "/enabled");
        if (ipv6enabled != NULL) printf("IPv6 enabled = %s\n", ipv6enabled->data.bool_val ? "true" : "false");
        
        // FIX: default je true
        // iface has ipv6 enabled
        if (ipv6enabled != NULL && ipv6enabled->data.bool_val) {
            // TODO: ipv6
        }
        sr_free_val(ipv6enabled);
                    
        // write cfg to file
        ini_table_write_to_file(ifcfg, dst);
        ini_table_print(ifcfg);
        ini_table_destroy(ifcfg);

    }
    
    sr_free_val(enabled);
    sr_free_val(type);
    sr_free_val(description);
}

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
