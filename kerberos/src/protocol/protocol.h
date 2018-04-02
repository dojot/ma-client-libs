#ifndef KERBEROS_PROTOCOL_
#define KERBEROS_PROTOCOL_

#include <stdio.h>
#include <stdint.h>

/* This defines must be directly manipulated by the generators if they need to be modified */
#define SHARED_KEY_LENGTH         32
#define TAG_LEN                   16
#define SESSION_ID_LENGTH         32


uint8_t kerberos_protocol_init(const char* urlRequestAS,
                               const char* urlRequestAP,
                               const uint8_t *appId,
                               size_t appIdSize,
                               const uint8_t *serverId,
                               size_t serverIdSize,
                               const uint8_t *sharedKey,
                               size_t sharedKeySize,
                               void** pContext);

uint8_t kerberos_protocol_deinit(void** pContext);

uint8_t kerberos_protocol_execute_handshake(void* pContext);

uint8_t kerberos_protocol_is_mutual_authenticated(void* pContext);

uint8_t kerberos_protocol_get_session_id(void* pContext,
                                         size_t sessionIdSize,
                                         uint8_t* sessionId);


#endif /* KERBEROS_PROTOCOL_ */
