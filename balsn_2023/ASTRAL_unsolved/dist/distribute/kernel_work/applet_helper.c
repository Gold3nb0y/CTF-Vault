#include "applet_helper.h"
#include "const.h"
#include <openssl/sha.h>


//uint64_t digestGenerateHelper(uint64_t codeLen, uint8_t *code, uint8_t *n, uint8_t *e, uint8_t *nonce, uint8_t *digest) {
//    uint8_t payload[DIGEST_PAYLOAD_SIZE_MAX];
//    if (n != NULL) {
//        memcpy_local(payload, n, SIGNATURE_SIZE);
//    } else {
//        mset(payload, '\0', SIGNATURE_SIZE);
//    }
//    if (e != NULL) {
//        memcpy_local(&payload[SIGNATURE_SIZE], e, SIGNATURE_SIZE);
//    } else {
//        mset(&payload[SIGNATURE_SIZE], '\0', SIGNATURE_SIZE);
//    }
//    if (nonce != NULL) {
//        memcpy_local(&payload[SIGNATURE_SIZE * 2], nonce, SIGNATURE_SIZE);
//    } else {
//        mset(&payload[SIGNATURE_SIZE * 2], '\0', SIGNATURE_SIZE);
//    }
//    memcpy_local(&payload[SIGNATURE_SIZE * 3], code, codeLen);
//    SHA256(payload, SIGNATURE_SIZE * 3 + codeLen, digest);
//    return SUCCESS;
//}
void unregisterApplet(APPLET_ID aid, u8* user_sig) {
  APPLET_UNREGISTER_REQ req;
  //uint8_t output[DIGEST_SIZE * 2 + 1];
  req.id = aid;
  memcpy_local(req.userSignature, user_sig, SIGNATURE_SIZE);
  if (appletUnregister(&req) == SYS_FAIL) {
    puts("applet unregister failed");
  } else {
    printStr("unregister succeeded, applet id : ");
    printNum(req.id);
    puts("");
  }
  return;
}

APPLET_ID register_applet(uint64_t code_len, uint8_t* code, u8* userN, u8* userE, uint8_t* sig) {
  APPLET_REGISTER_REQ req;
  APPLET_ID aid;
  mset((u8*)&req, 0, sizeof(APPLET_REGISTER_REQ));
  req.applet.codeLen = code_len;
  if (req.applet.codeLen > APPLET_SIZE_MAX) {
    puts("applet size too large");
    return FAIL;
  }
  if ((req.applet.code = malloc(req.applet.codeLen)) == NULL) {
    abort("applet registration code allocation failed");
  }
  memcpy_local(req.applet.code, code, code_len);
  memcpy_local(req.userPubkeyN, userN, SIGNATURE_SIZE);
  memcpy_local(req.userPubkeyE, userE, SIGNATURE_SIZE);
  mset(req.userNonce, 0, SIGNATURE_SIZE);
  memcpy_local(req.authoritySignature, sig, SIGNATURE_SIZE);
  if (appletRegister(&req, &aid) == SYS_FAIL) {
    puts("applet registration failed");
  } else {
    printStr("registration succeeded, applet id : ");
    printNum(aid);
    puts("");
    //recordStatistics(stat, 1);
  }
  free(req.applet.code);
  return aid;
}

void invoke_applet(APPLET_ID aid, uint64_t size, u8* data, APPLET_RECEIPT* recpt){
    APPLET_INVOKE_REQ req;
    req.id = aid;
    req.arg.dataLen = size;
    req.arg.data = data;
    if(appletInvoke(&req, recpt) == SYS_FAIL){
        puts("failed to invoke applet");
    }
    else{
        printStr("invoke success; recipt : ");
        printNum(recpt->task);
        puts("");
    }
}
