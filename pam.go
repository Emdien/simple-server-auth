package main

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

void init_conv(struct pam_conv *conv, uintptr_t appdata_ptr);
struct pam_conv make_conv(void *appdata_ptr);
typedef int (*pam_start_confdir_fn)(const char *service_name, const char *user, const struct pam_conv *pam_conversation, const char *confdir, pam_handle_t **pamh);

*/
import "C"

import (
	"runtime/cgo"
	"sync/atomic"
	"unsafe"
)

// *************** PAM CONVERSATION *******************

// In this use-case, the Style will always be PromptEchoOff as we are inputting a password
// We do not need BinaryConversation, we use a normal Conversation

// goPAMConv should, in theory, only handle the normal Conversation case, and there will be no
// binary style.

type Style int

const (
	PromptEchoOff Style = C.PAM_PROMPT_ECHO_OFF
	PromptEchoOn Style = C.PAM_PROMPT_ECHO_ON // This shouldn't be needed in our use-case
)

// Interface for objects that can be used as conversation callbacks during PAM auth
type ConversationHandler interface {
	// Receives a style and a message string.
	// Returns a response string.
	RespondPAM(Style, string) (string, error)
}


// Adapter to wrap ConversationHandler function to allow for closures to be passed
type ConversationFunc func(Style, string) (string, error)

func (f ConversationFunc) RespondPAM(s Style, msg string) (string, error) {
	return f(s, msg)
}

// This goes into the shim in pam.c as an exported func

//export goPAMConv
func goPAMConv(s C.int, msg *C.char, c C.uintptr_t) (*C.char, C.int) {

	var resp string
	var err error

	value := cgo.Handle(c).Value()
	style := Style(s)

	var handler ConversationHandler

	if cb, ok := value.(ConversationHandler); ok {
		handler = cb
	}

	if handler == nil {
		return nil, C.int(C.PAM_CONV_ERR)
	}

	resp, err = handler.RespondPAM(style, C.GoString(msg))
	
	if err != nil {
		return nil, C.int(C.PAM_CONV_ERR)
	}

	return C.CString(resp), C.PAM_SUCCESS
	
}

// ****************************************************
// *************** PAM TRANSACTION ********************

// Define the struct and transaction methods

type Transaction struct  {
	handle 		atomic.Pointer[unsafe.Pointer]
	conv 		atomic.Pointer[*C.struct_pam_conv]
	lastStatus	*atomic.Int32
	callback 	cgo.Handle
}


// Cleans up the PAM handle and deletes the callback function

func (t *Transaction) End() error {
	handle := t.handle.Swap(nil)
	if handle == nil {
		return nil
	}


	defer t.callback.Delete()
	
	// t.handle.Swap returns a pointer to a unsafe.Pointer
	// To be able to cast it to a pam_handle_t pointer, we:
	// 1. Dereference handle with *handle
	// 2. Cast it to a pointer of pam_handle_t with (*C.pam_handle_t)(...)
	return t.handleStatus(C.pam_end((*C.pam_handle_t)(*handle), C.int(t.lastStatus.Load())))

}

func (t *Transaction) handleStatus(convStatus C.int) error {
	t.lastStatus.Store(int32(convStatus))
	if status := Error(convStatus); status != C.PAM_SUCCESS {
		return status
	}
	return nil
}




// The methods they receive a cStatus int. We are keeping this for traceabilithy

// ****************************************************
// *************** HELPER FUNCTIONS *******************

// Start is required. It is enough to implement a start without ConfDir
// Handle only the case where confDir is not configured

func StartTransaction(service, user string, handler ConversationHandler) (*Transaction, error) {
	return start_pam_transaction(service, user, handler)
}

func StartTransactionFunc(service, user string, handler func(Style, string) (string, error)) (*Transaction, error) {
	return start_pam_transaction(service, user, ConversationFunc(handler))
}

func start_pam_transaction(service, user string, handler ConversationHandler) (*Transaction, error) {

	transaction := &Transaction{
		conv: atomic.Pointer[*C.struct_pam_conv]{},
		callback: cgo.NewHandle(handler),
	}

	C.init_conv(transaction.conv.Load(), C.uintptr_t(transaction.callback))

	return transaction, nil


}

// ****************************************************
// ******************* PAM ITEMS **********************

// Define flags ? Maybe not. Try to pass pre-defined, hardcoded flags as they interests us
// Additionally, only interested in Authenticate and AcctMgmt
// Just in case: valid flags are Silent and DisallowNullAuthtok

// ****************************************************
