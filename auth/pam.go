package auth

/*
#cgo CFLAGS: -Wall -Wno-unused-variable -std=c99
#cgo LDFLAGS: -ldl -lpam

#include <dlfcn.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef PAM_BINARY_PROMPT
#define BINARY_PROMPT_IS_SUPPORTED 1
#else
#include <limits.h>
#define PAM_BINARY_PROMPT INT_MAX
#define BINARY_PROMPT_IS_SUPPORTED 0
#endif


// Initialization functions
void init_conv(struct pam_conv *conv, uintptr_t appdata_ptr);
struct pam_conv make_conv(void *appdata_ptr);

// Grabbed this from msteinert's code. Unsure what it does yet.
typedef int (*pam_start_confdir_fn)(const char *service_name, const char *user, const struct pam_conv *pam_conversation, const char *confdir, pam_handle_t **pamh);


*/

import "C"


// *************** PAM CONVERSATION *******************

// In this use-case, the Style will always be PromptEchoOff as we are inputting a password
// We do not need BinaryConversation, we use a normal Conversation

// goPAMConv should, in theory, only handle the normal Conversation case, and there will be no
// binary style.

// ****************************************************
// *************** PAM TRANSACTION ********************

// Define the struct and transaction methods

// The methods they receive a cStatus int. We are keeping this for traceabilithy

// ****************************************************
// *************** HELPER FUNCTIONS *******************

// Start is required. It is enough to implement a start without ConfDir
// Handle only the case where confDir is not configured

// ****************************************************
// ******************* PAM ITEMS **********************

// Define flags ? Maybe not. Try to pass pre-defined, hardcoded flags as they interests us
// Additionally, only interested in Authenticate and AcctMgmt
// Just in case: valid flags are Silent and DisallowNullAuthtok

// ****************************************************
