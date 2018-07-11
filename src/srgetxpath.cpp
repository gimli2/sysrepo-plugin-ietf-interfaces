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

#ifdef __cplusplus
extern "C"
{
#endif

#include "sysrepo.h"
#include "sysrepo/values.h"

#ifdef __cplusplus
}
#endif

#include <stdio.h>
#include <unistd.h>

using namespace std;

volatile int exit_application = 0;

#define APP "SR_PLUGIN_ietf-interfaces"

#include "interfaces.cpp"

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
    rc = sr_session_start(*connection, SR_DS_RUNNING, SR_SESS_DEFAULT, session);
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
    
    
    if (init_session(&connection, &session)) {
       
        if (argc < 2) {
            cleanup(connection, session, subscription);
            cout << "Usage: " << argv[0] << " XPATH\n" << endl;
            return rc;
        } else {
            cout << "XPATH: " << argv[1] << endl;
            
            sr_val_t *values = NULL;
            size_t count = 0;
            rc = sr_get_items(session, argv[1], &values, &count);
            if (handle_sr_return(rc) == ERR) {
                //cout << "ERROR during retrieving XPATH = " << argv[1] << endl;
            } else {
                cout << "======================================================" << endl;
                for (size_t i = 0; i < count; i++){
                    sr_print_val(&values[i]);
                }
                cout << "======================================================" << endl;
                sr_free_values(values, count);
            }
            
            /*
            sr_val_t *value = NULL;
            sr_val_iter_t *iter = NULL;
            rc = SR_ERR_OK;
 
            // "/ietf-interfaces:interfaces-state/interface//*"
            
            rc = sr_get_items_iter(session, argv[1], &iter);
            if (SR_ERR_OK != rc) {
                cout << "nenasli" << endl;
            }
            cout << "neco se naslo" << endl;
            while (SR_ERR_OK == sr_get_item_next(session, iter, &value)) {
                cout << "val = " << endl;
                sr_print_val(value);
                sr_free_val(value);
            }
            sr_free_val_iter(iter);
            */
        }    
    }
    
    cleanup(connection, session, subscription);
    printf("Bye.\n");

    return rc;
}


