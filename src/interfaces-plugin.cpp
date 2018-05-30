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

#ifdef __cplusplus
extern "C"
{
#endif

// your functions here for the header
#include "sysrepo.h"
#include "sysrepo/values.h"
#include "config.h"

#ifdef __cplusplus
}
#endif

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <string>
#include <iostream>

using namespace std;

volatile int exit_application = 0;

#define APP "SR_PLUGIN_ietf-interfaces"
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

static void print_change(sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val) {
    switch(op) {
    case SR_OP_CREATED:
        if (NULL != new_val) {
           printf("CREATED: ");
           sr_print_val(new_val);
        }
        break;
    case SR_OP_DELETED:
        if (NULL != old_val) {
           printf("DELETED: ");
           sr_print_val(old_val);
        }
    break;
    case SR_OP_MODIFIED:
        if (NULL != old_val && NULL != new_val) {
           printf("MODIFIED: ");
           printf("old value ");
           sr_print_val(old_val);
           printf("new value ");
           sr_print_val(new_val);
        }
    break;
    case SR_OP_MOVED:
        if (NULL != new_val) {
            printf("MOVED: %s after %s", new_val->xpath, NULL != old_val ? old_val->xpath : NULL);
        }
    break;
    }
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
    
    // proceed only to enabled and known interface type
    if (enabled->data.bool_val && strcmp("iana-if-type:ethernetCsmacd", type->data.identityref_val) == 0) {
        // shortcut for xpath queries
        string ifipv4xpath = "/ietf-interfaces:interfaces/interface[name='"+(string)name+"']/ietf-ip:ipv4";
        
        // prepare dict for output config
        ini_table_s* ifcfg = ini_table_create();
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
                    
                    // possible origins: other, static, dhcp, link-layer (stateless IPv6), random -- see rfc7277
                    sr_val_t *ipv4origin = get_val(session, ifipv4xpath + "/address[ip='"+(string)(&values[i])->data.string_val+"']/origin");
                    if (ipv4origin != NULL) printf("IPv4 origin = %s\n", ipv4origin->data.string_val);
                    
                     if (ipv4origin == NULL || strcmp(ipv4origin->data.string_val, "static") == 0) {
                        // static is default
                        string addr = (string)(&values[i])->data.string_val + "/" + to_string(ipv4prefixlen->data.uint8_val);
                        // it is possible to have more addres, need to create entry allowing duplicate key
                        ini_table_create_entry_duplicate(ifcfg, "Network", "Address", &addr[0u]);
                    } else if (ipv4origin != NULL && strcmp(ipv4origin->data.string_val, "dhcp") == 0) {
                        // DHCP
                        ini_table_create_entry(ifcfg, "Network", "DHCP", "ipv4");
                    } else {
                        printf("Not implemented.");
                    }
                    
                    // TODO: Gateway DNS
                    // ini_table_create_entry(ifcfg, "Network", "Gateway", "");
                    // ini_table_create_entry(ifcfg, "Network", "DNS", "");
                    
                    sr_free_val(ipv4origin);
                    sr_free_val(ipv4prefixlen);
                }
                sr_free_values(values, count);
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

const char *ev_to_str(sr_notif_event_t ev) {
    switch (ev) {
        case SR_EV_VERIFY:
            return "verify";
        case SR_EV_APPLY:
            return "apply";
        case SR_EV_ABORT:
        default:
            return "abort";
    }
}

static int module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx) {
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char change_path[XPATH_MAX_LEN] = {0,};


    printf("\n\n ========== Notification  %s =============================================", ev_to_str(event));
    if (SR_EV_APPLY == event) {
        printf("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n");
        print_current_config(session);
    }

    printf("\n\n ========== CHANGES: =============================================\n\n");


    snprintf(change_path, XPATH_MAX_LEN, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, change_path , &it);
    if (handle_sr_return(rc) == ERR) {
        printf("Get changes iter failed for xpath %s", change_path);
        goto cleanup;
    }

    while (SR_ERR_OK == (rc = sr_get_change_next(session, it, &oper, &old_value, &new_value))) {
        print_change(oper, old_value, new_value);
        sr_free_val(old_value);
        sr_free_val(new_value);
    }
    printf("\n\n ========== END OF CHANGES =======================================\n\n");


cleanup:
    sr_free_change_iter(it);

    return SR_ERR_OK;
}

static void sigint_handler(int signum) {
    exit_application = 1;
}

static void cleanup(sr_conn_ctx_t *connection, sr_session_ctx_t *session, sr_subscription_ctx_t *subscription) {
    if (NULL != subscription)   sr_unsubscribe(session, subscription);
    if (NULL != session)        sr_session_stop(session);
    if (NULL != connection)     sr_disconnect(connection);
}

static int init_session(sr_conn_ctx_t **connection, sr_session_ctx_t **session) {
    int rc = SR_ERR_OK;
    
    rc = sr_connect(APP, SR_CONN_DEFAULT, connection);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
        cleanup(*connection, *session, NULL);
        return 0;
    }
    rc = sr_session_start(*connection, SR_DS_STARTUP, SR_SESS_DEFAULT, session);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
        cleanup(*connection, *session, NULL);
        return 0;
    }

    return 1;
}

int main(int argc, char **argv) {
    sr_conn_ctx_t           *connection = NULL;
    sr_session_ctx_t        *session = NULL;
    sr_subscription_ctx_t   *subscription = NULL;
    int rc = SR_ERR_OK;

    ini_table_s* config = ini_table_create();
    ini_table_create_entry(config, "Section", "one", "two");
    ini_table_create_entry(config, "Dalsi", "; comment", "");
    ini_table_create_entry(config, "Dalsi", "key", "val");
    ini_table_create_entry(config, "Dalsi", "k", "42");
    ini_table_write_to_file(config, "test.ini");
    ini_table_destroy(config);


    printf("Application will watch for changes in ietf-interfaces\n");
    
    if (init_session(&connection, &session)) {
       
        printf("\n\n ========== READING STARTUP CONFIG: ==========\n\n");
        print_current_config(session);
        apply_current_config(session);

        // pripadne: int sr_subtree_change_subscribe(...)
        rc = sr_module_change_subscribe(session, "ietf-interfaces", module_change_cb, NULL, PRIORITY, SR_SUBSCR_DEFAULT, &subscription);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error by sr_module_change_subscribe: %s\n", sr_strerror(rc));
            cleanup(connection, session, subscription);
            return rc;
        }

        /* loop until ctrl-c is pressed / SIGINT is received */
        signal(SIGINT, sigint_handler);
        signal(SIGPIPE, SIG_IGN);
        while (!exit_application) {
            sleep(666);
        }
    }
    
    cleanup(connection, session, subscription);
    printf("Bye.\n");

    return rc;
}


