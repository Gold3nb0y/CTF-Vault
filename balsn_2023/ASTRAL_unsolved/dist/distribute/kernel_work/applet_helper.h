#ifndef applet_helper
#define applet_helper

#include <stddef.h>
#include <stdint.h>
#include "syscall.h"
#include "applet.h"
#include "appletStructs.h"
#include "lib.h"
typedef uint8_t u8;


//uint64_t digestGenerateHelper(uint64_t codeLen, uint8_t *code, uint8_t *n, uint8_t *e, uint8_t *nonce, uint8_t *digest);

void unregisterApplet(APPLET_ID aid, u8* user_sig);

APPLET_ID register_applet(uint64_t code_len, uint8_t* code, uint8_t* userN, uint8_t* userE, uint8_t* sig);

void invoke_applet(APPLET_ID aid, uint64_t size, u8* data, APPLET_RECEIPT* recpt);


#endif
