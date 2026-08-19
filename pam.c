#include "_cgo_export.h"
#include <security/pam_appl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


// Rewrite of github.com/msteinert/pam implementation for learning purposes.
// The end result should basically be the same (hopefully not a copy!)

extern char* conversationCallback(int style, char* msg, void* appdata);

int pam_conv_call(
    int num_msg,
    const struct pam_message **msg,
    struct pam_response **resp,
    void *appdata_ptr
) {

    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) 
        return PAM_CONV_ERR;
    
    *resp = calloc(num_msg, sizeof **resp);
    if (!*resp) // Unable to alocate the response buffer
        return PAM_BUF_ERR;


    bool pam_error = false;
    for (size_t i = 0; i < num_msg; ++i) {
        // I call the PAM Conversation GO function that is auto exported.
        // It also dynamically generates a struct through CGO since it returns 2 values -> struct

        // result.r0 holds the string msg, whereas r1 holds the status code.

        struct goPAMConv_return result = goPAMConv(msg[i]->msg_style, (char *)msg[i]->msg, (uintptr_t)appdata_ptr);
        if (result.r1 != PAM_SUCCESS) {
            pam_error = true;
            break;
        }

        (*resp)[i].resp = result.r0;

    }

    // In msteinert's code this is done through a goto, however for now I am avoiding using goto.
    // Personal choice.

    if (pam_error) {
        // If theres an error, we need to make sure we free everything, as the transaction is over
        // We need to free responses that were already collected.

        // To properly clean and free we go through the actual, non-garbage fields and clean+free them
        // Then we clean+free the entirety of the response array

        for (size_t i = 0; i<num_msg; ++i) {
            if ((*resp)[i].resp) {
                memset((*resp)[i].resp, 0, strlen((*resp)[i].resp)); // Set to 0 to avoid having credentials as allocatable memory
                free((*resp)[i].resp);

            }
        }

        // Now we free resp since its cleaned up
        memset(*resp, 0, num_msg * sizeof *resp); // The size corresponds to the calloc call
        free(*resp);

        *resp = NULL; // Avoid dangling pointer
        return PAM_CONV_ERR;
    }

    return PAM_SUCCESS;

}


// Create a PAM conversation with a matching conversation call that performs our desired logic
// and uses the pointer of appdata_ptr to pass credentials.
struct pam_conv make_conv(void *appdata_ptr) {
    struct pam_conv conv;
    conv.conv = pam_conv_call;
    conv.appdata_ptr = appdata_ptr;
    return conv;
}


// Similar to the above, however this INITIALIZES a given pam_conv struc, instead of creating and returning one.
// At the end of the day, its the same thing, just different was of initializing.
void init_conv(struct pam_conv *conv, uintptr_t appdata_ptr) {
    conv->conv = pam_conv_call;
    conv->appdata_ptr = (void *) appdata_ptr;
}