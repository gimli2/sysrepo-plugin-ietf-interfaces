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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include "sysrepo.h"
#include "sysrepo/values.h"
#include "config.h"

volatile int exit_application = 0;

#define APP "SR_PLUGIN_ietf-interfaces"
#define XPATH_MAX_LEN 100
#define PRIORITY 0 // greater numbers mean later called callback

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

static void print_current_config(sr_session_ctx_t *session, const char *module_name) {
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char select_xpath[XPATH_MAX_LEN];
    snprintf(select_xpath, XPATH_MAX_LEN, "/%s:*//*", module_name);

    rc = sr_get_items(session, select_xpath, &values, &count);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_get_items: %s", sr_strerror(rc));
        return;
    }
    for (size_t i = 0; i < count; i++){
        sr_print_val(&values[i]);
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
        print_current_config(session, module_name);
    }

    printf("\n\n ========== CHANGES: =============================================\n\n");


    snprintf(change_path, XPATH_MAX_LEN, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, change_path , &it);
    if (SR_ERR_OK != rc) {
        printf("Get changes iter failed for xpath %s", change_path);
        goto cleanup;
    }

    while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
                &oper, &old_value, &new_value))) {
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
    char *module_name = "ietf-interfaces";

    ini_table_s* config = ini_table_create();
    ini_table_create_entry(config, "Section", "one", "two");
    ini_table_create_entry(config, "Dalsi", "; comment", "");
    ini_table_create_entry(config, "Dalsi", "key", "val");
    ini_table_create_entry(config, "Dalsi", "k", "42");
    ini_table_write_to_file(config, "test.ini");


    printf("Application will watch for changes in %s\n", module_name);
    
    if (init_session(&connection, &session)) {
       
        printf("\n\n ========== READING STARTUP CONFIG: ==========\n\n");
        print_current_config(session, module_name);

        // pripadne: int sr_subtree_change_subscribe(...)
        rc = sr_module_change_subscribe(session, module_name, module_change_cb, NULL, PRIORITY, SR_SUBSCR_DEFAULT, &subscription);
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

