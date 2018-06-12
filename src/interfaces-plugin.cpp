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

extern "C" {

static int module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx) {
    syslog(LOG_DEBUG, "configuration has changed. Event=%s", event==SR_EV_APPLY?"apply":event==SR_EV_VERIFY?"verify":"unknown");
    printf("configuration has changed. Event=%s\n", event==SR_EV_APPLY?"apply":event==SR_EV_VERIFY?"verify":"unknown");
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
    int rc = SR_ERR_OK;

    rc = sr_module_change_subscribe(session, "ietf-interface", module_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    rc = sr_dp_get_items_subscribe(session, "/ietf-interface:interfaces-state", ifstats_dataprovider_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    /*
    rc = sr_rpc_subscribe(session, "/ietf-system:system-restart", exec_rpc_cb, (void *)"shutdown -r now", SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;
    */

    syslog(LOG_DEBUG, "plugin initialized successfully");


    print_current_config(session);
    apply_current_config(session);

    /* set subscription as our private context */
    *private_ctx = subscription;

    return SR_ERR_OK;

error:
    syslog(LOG_ERR, "plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx) {
    /* subscription was set as our private context */
    sr_unsubscribe(session, (sr_subscription_ctx_t *)private_ctx);
    syslog(LOG_DEBUG, "plugin cleanup finished");
}

}
