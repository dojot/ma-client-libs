#ifndef KERBEROS_SRC_MA_COMMUNICATION_H_
#define KERBEROS_SRC_MA_COMMUNICATION_H_

/**
 * @brief This library is a wrapper for libcurl + kerberos. It abstracts the
 * mutual authentication and encryption details and uses the libcurl to send
 * the desired requests.
 */

#include <stdint.h>
#include <stdlib.h>
#include <curl/curl.h>

//HTTP methods
#define    HTTP_METHOD_DELETE "DELETE"
#define    HTTP_METHOD_PUT "PUT"
#define    HTTP_METHOD_GET "GET"
#define    HTTP_METHOD_POST "POST"

/**
 * @brief Initializes the library and configures it. It must be called
 * before any call to ma_communication_send function.
 * @param[in] initCurl indicates if the library should initialize the libcurl
 *               and take care about it. (0 to false, non-zero otherwise)
 * @param[in] enableLogger indicates if the library should log in default output.
 *               (0 to false, non-zero otherwise)
 * @param[in] enableSecureChannel indicates if the library should use the secure
 *               channel to encrypt/decrypt messages. (0 to false, non-zero otherwise)
 * @param[in] urlRequestAS a C string that represents the URL to call the requestAS
 * @param[in] urlRequestAP a C string that represents the URL to call the requestAP
 * @param[in] appId a vector with the current application id
 * @param[in] appIdSize the application id size, it must be 16
 * @param[in] serverId a vector with the server id
 * @param[in] serverIdSize the server id size, it must be 16
 * @param[in] sharedKey a vector with the shared key
 * @param[in] sharedKeySize the shared key size, it must be 32
 * @return 0 on success, otherwise non-zero
 * @warning: you MUST NOT use the logger enabled in production mode, it prints
 * sensitive information
 */
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
                              size_t sharedKeySize);

/**
 * @brief Deinitializes the library. It's wise to call it on your shutdown flow
 * to free the allocated resources.
 * @return 0 on success, otherwise non-zero
 */
uint8_t ma_communication_deinit();

/**
 * @brief Sends a message and waits for the answer. Internally it checks if
 * the kerberos handshake is done, if not, it makes the handshake. It also
 * encrypts the request and decrypts the result.
 * @param[in] url the URL target to send the message
 * @param[in] httpMethod the HTTP desirable, you can use the HTTP_METHOD_ defines
 * @param[in] headers a pointer to a libcurl header structure
 * @param[in] content the message's content
 * @param[in] contentSize the message context's size
 * @param[out] httpStatusCode the HTTP status code
 * @param[out] response the response to your message
 * @param[out] responseSize the responses's size
 * @return 0 on success, otherwise non-zero
 * @warning: it is user responsibility to clean the 'content' pointer, the
 * library does not make it.
 * @warning: the library take control of the header pointer, you do not
 * need to take care of it anymore.
 */
uint8_t ma_communication_send(const char *url,
                              char * httpMethod,
                              struct curl_slist **headers,
                              unsigned char* content,
                              size_t contentSize,
                              uint32_t *httpStatusCode,
                              unsigned char** pResponse,
                              size_t *responseSize);

#endif /* KERBEROS_SRC_MA_COMMUNICATION_H_ */
