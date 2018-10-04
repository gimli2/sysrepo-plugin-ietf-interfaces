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

#include "sysrepo.h"
#include "sysrepo/values.h"

#ifdef __cplusplus
}
#endif

#include <syslog.h>

using namespace std;

#include "interfaces.cpp"

//1. variant: #define syslog(priority, ...) printf(__VA_ARGS__)
//2. variant
// ## __VA_ARGS__ is black magic that allows you to use this macro also with static strings without variables 
#define MYLOG(fmt, ...) { \
  syslog(LOG_DEBUG, fmt, ## __VA_ARGS__); \
  printf(fmt, ## __VA_ARGS__); \
}

extern "C" {

static int module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx) {
    MYLOG("configuration has changed. Event=%s", event==SR_EV_APPLY?"apply":event==SR_EV_VERIFY?"verify":"unknown");

    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char change_path[XPATH_MAX_LEN] = {0,};

    // handle only APPLY event
    if (SR_EV_APPLY == event) {
        // create full configuration from sysrepo val
        apply_current_config(session);
    
        snprintf(change_path, XPATH_MAX_LEN, "/%s:*", module_name);
        rc = sr_get_changes_iter(session, change_path , &it);
        if (handle_sr_return(rc) == ERR) {
            MYLOG("Get changes iter failed for xpath %s", change_path);
            goto cleanup;
        }
        
        sr_xpath_ctx_t xp_ctx = {0};
        while (SR_ERR_OK == (rc = sr_get_change_next(session, it, &oper, &old_value, &new_value))) {
            // when deleting whole interface node, we need to remove proper configuration file
            char cfg_delete_fn[PATH_MAX_LEN];
            cfg_delete_fn[0] = '\0';
                        
            if (SR_OP_DELETED == oper && old_value != NULL) {
                // is node interface?
                char *nodetype = sr_xpath_node(old_value->xpath, "interface", &xp_ctx);
                sr_xpath_recover(&xp_ctx); // sr_xpath_node modified context
                //MYLOG("nodetype = %s.\n", nodetype);
                
                // match only fisrt 9 chars...
                if (nodetype != NULL && 0 == strncmp(nodetype, "interface", 9) ) {    
                    // check that current element is string "name"
                    if ( (old_value->type == SR_STRING_T) && 0 == strcmp(sr_xpath_node_name(old_value->xpath), "name") ) {
                        sprintf(cfg_delete_fn, "%s/%s.%s", DSTPATH, old_value->data.string_val, IFEXT);
                        
                        MYLOG("There is a redundant config file to deletion: %s\n", cfg_delete_fn);
                        
                        if ( remove(cfg_delete_fn) != 0 ) {
                            MYLOG("Error deleting file %s.\n", cfg_delete_fn);
                        } else {
                            MYLOG("File %s successfully deleted.\n", cfg_delete_fn);
                        }
                    }
                        
                }
            }
            
            sr_free_val(old_value);
            sr_free_val(new_value);
        }
    }

cleanup:
    sr_free_change_iter(it);
    return SR_ERR_OK;
}

/*
int exec_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx) {
    syslog(LOG_DEBUG, "exec_rpc_cb called");
    
    //system((const char*)private_ctx);
    //system(private_ctx);  
    return SR_ERR_OK;
}
*/

/* Registers for providing of operational data under given xpath. */  
int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx) {
    sr_subscription_ctx_t *subscription = NULL;
    sr_subscription_ctx_t *subscription_oper = NULL;
    int rc = SR_ERR_OK;
    int r;

    // changes
    rc = sr_module_change_subscribe(session, "ietf-interfaces", module_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    // operational data
    rc = sr_dp_get_items_subscribe(session, "/ietf-interfaces:interfaces-state", ifstats_dataprovider_cb, NULL, SR_SUBSCR_DEFAULT, &subscription_oper);
    if (SR_ERR_OK != rc) goto error;

    /*
    rc = sr_rpc_subscribe(session, "/ietf-system:system-restart", exec_rpc_cb, (void *)"shutdown -r now", SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;
    */

    syslog(LOG_DEBUG, "plugin initialized successfully with destination %s", DSTPATH);
    r = mkpath(DSTPATH, 0755);
    if (r == 0) {
        syslog(LOG_DEBUG, "DSTDIR %s created successfuly.", DSTPATH);
    } else if (r == EEXIST) {
        syslog(LOG_DEBUG, "DSTDIR %s already exists.", DSTPATH);
    } else {
        syslog(LOG_DEBUG, "mkpath returned = %d", r);
    }
    

    apply_current_config(session);

    /* set subscription as our private context */
    // how to preserve both of them?
    *private_ctx = subscription;

    return SR_ERR_OK;

error:
    syslog(LOG_ERR, "plugin initialization failed: %s", sr_strerror(rc));
    if (subscription != NULL) sr_unsubscribe(session, subscription);
    if (subscription_oper != NULL) sr_unsubscribe(session, subscription_oper);
    return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx) {
    /* subscription was set as our private context */
    sr_unsubscribe(session, (sr_subscription_ctx_t *)private_ctx);
    syslog(LOG_DEBUG, "plugin cleanup finished");
}

}
