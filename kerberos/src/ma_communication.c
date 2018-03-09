#include "ma_communication.h"

#include <pthread.h>
#include <curl/curl.h>

#include "logger/logger.h"
#include "ma_comm_error_codes.h"
#include "crypto/codes.h"

typedef struct SCommContext {
	uint8_t isSecureChannelEnabled;
	uint8_t initCurl;
	void* pKerberosContext;
} CommContext;

static int initialized = 0;
static CommContext internalContext;

void initCommContext(CommContext *pContext) {
	pContext->isSecureChannelEnabled = 0;
	pContext->initCurl = 0;
	pContext->pKerberosContext = NULL;
}

uint8_t ma_communication_init(uint8_t initCurl,
							  uint8_t enableLogger,
							  uint8_t enableSecureChannel,
							  const char* urlRequestAS,
							  const char* urlRequestAP,
							  const uint8_t *appId,
							  size_t appIdSize,
							  const uint8_t *serverId,
							  size_t serverIdSize,
							  const uint8_t *sharedKey,
							  size_t sharedKeySize) {
	int8_t result = 0;

	if ( (!urlRequestAS) || (!urlRequestAS) ) {
		return MA_COMM_INVALID_PARAMETER;
	}

	if (enableLogger) {
		logger_enable();
	}

	if (initialized) {
		LOG("You cannot call init twice\n");
		return MA_COMM_INVALID_STATE;
	}

	initCommContext(&internalContext);

	internalContext.initCurl = initCurl;
	internalContext.isSecureChannelEnabled = enableSecureChannel;
	result = kerberos_protocol_init(urlRequestAS,
								    urlRequestAP,
									appId,
									appIdSize,
									serverId,
									serverIdSize,
									sharedKey,
									sharedKeySize,
								    &internalContext.pKerberosContext);
	if (result != 0) {
		LOG("Error to initialize kerberos context\n");
		return MA_COMM_INVALID_STATE;
	}

	if (internalContext.initCurl) {
		curl_global_init(CURL_GLOBAL_ALL);
	}

	initialized = 1;
	LOG("MA comm initialized\n");
    return MA_COMM_SUCCESS;
}

uint8_t ma_communication_deinit() {
	if (!initialized) {
		LOG("MA communication is not initialized\n");
		return MA_COMM_INVALID_STATE;
	}

	if (internalContext.initCurl) {
		curl_global_cleanup();
	}

	kerberos_protocol_deinit(&internalContext.pKerberosContext);

	LOG("MA comm deinitialized\n");
	return MA_COMM_SUCCESS;
}

uint8_t ma_communication_send(const char *url,
							  const char** headers,
							  const size_t numHeaders,
							  unsigned char* content,
							  size_t contentSize,
							  unsigned char** pResponse,
							  size_t *responseSize) {

	int32_t result = 0;
	uint8_t* pContentToSend = content;
	size_t contentToSendSize = contentSize;
	if ((!url) || (!content) || (!responseSize) ) {
		LOG("Invalid parameter\n");
		return MA_COMM_INVALID_PARAMETER;
	}

	if (!initialized) {
		LOG("MA communication is not initialized\n");
		return MA_COMM_INVALID_STATE;
	}

	if (!kerberos_protocol_is_mutual_authenticated(internalContext.pKerberosContext)) {
		LOG("The application is not mutual authenticated\n");
		result = kerberos_protocol_execute_handshake(internalContext.pKerberosContext);
		if (result != MA_COMM_SUCCESS) {
			LOG("Fail to execute kerberos handshake. Error %d\n", result);
			return MA_COMM_INVALID_STATE;
		}
	} else {
		LOG("The application is mutual authenticated\n");
	}

	if (internalContext.isSecureChannelEnabled) {
		LOG("Ciphering the content\n");
		uint8_t *cipherContent = NULL;
		size_t cipherContentSize = 0;
		//encrypt
		result = encryptTo(NULL,
						   0,
						   content,
						   contentSize,
						   &cipherContent,
						   &cipherContentSize);
		if (result != SUCCESSFULL_OPERATION) {
			LOG("Fail to encrypt content\n");
			return MA_COMM_INVALID_STATE;
		}
		pContentToSend = cipherContent;
		contentToSendSize = cipherContentSize;
	}

	uint8_t* pResponseAux = NULL;
	size_t responseSizeAux = 0;

	LOG("Sending the message\n");

	result = send_message(url,
						  headers,
						  numHeaders,
						  pContentToSend,
						  contentSize,
						  &pResponseAux,
						  &responseSizeAux);
	if (internalContext.isSecureChannelEnabled) {
		free(pContentToSend);
	}
	if (result != SUCCESSFULL_OPERATION) {
		LOG("Fail to send message\n");
		return MA_COMM_INVALID_STATE;
	}

	LOG("response size: %d\n", responseSizeAux);
	size_t i = 0;
	LOG("--- begin response ---\n");
	for (i = 0; i < responseSizeAux; ++i) {
		LOG("%c", pResponse[i]);
	}
	LOG("\n--- End response ---\n");

	if ( (internalContext.isSecureChannelEnabled) && (responseSizeAux > 0) ) {
		LOG("Deciphering the response\n");
		uint8_t *plainContent = NULL;
		size_t plainContentSize = 0;
		// decrypt
		result = decryptTo(NULL,
						   0,
						   pResponseAux,
						   responseSizeAux,
						   &plainContent,
						   &plainContentSize);
		free(pResponseAux);
		if (result != SUCCESSFULL_OPERATION) {
			LOG("Fail to decrypt response\n");
			return MA_COMM_INVALID_STATE;
		}
		pResponseAux = plainContent;
		responseSizeAux = plainContentSize;
	}

	*pResponse = pResponseAux;
	*responseSize = responseSizeAux;

	return MA_COMM_SUCCESS;
}
