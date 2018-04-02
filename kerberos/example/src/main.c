#include <stdio.h>
#include <stdint.h>
#include <json.h>

#include "ma_communication.h"

#define SHARED_KEY { 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, \
                     0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, \
                     0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, \
                     0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}

#define APP_ID     { 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, \
                     0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef }

#define SERVER_ID  { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, \
                     0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 }

#define MAX_URL_SIZE 256

#define USERNAME "admin"
#define PASSWORD "admin"

#define DOJOT "http://localhost:8000"
#define KERBEROS_REQUEST_AP DOJOT "/kerberos/requestAP"
#define KERBEROS_REQUEST_AS DOJOT "/kerberos/requestAS"
#define AUTH DOJOT "/auth"

void dump(char* data, size_t len) {
    size_t i = 0;
    for (i = 0; i < len; ++i) {
        printf("%c", data[i]);
    }
    printf("\n");
}

uint32_t init() {
    uint32_t result = 0;
    uint8_t secureChannelEnabled = 1;
    uint8_t isLoggerEnabled = 1;
    uint8_t initCurl = 1;
    uint8_t appId[] = APP_ID;
    uint8_t serverId[] = SERVER_ID;
    uint8_t sharedKey[] = SHARED_KEY;
    char reqAS[MAX_URL_SIZE];
    char reqAP[MAX_URL_SIZE];
    sprintf(reqAS, KERBEROS_REQUEST_AS);
    sprintf(reqAP, KERBEROS_REQUEST_AP);

    result = ma_communication_init(initCurl,
                                   isLoggerEnabled,
                                   secureChannelEnabled,
                                   reqAS,
                                   reqAP,
                                   appId,
                                   sizeof(appId),
                                   serverId,
                                   sizeof(serverId),
                                   sharedKey,
                                   sizeof(sharedKey));
    if (result != 0) {
        printf("MA-Communication initialization failed.\n");
        return 1;
    }

    return 0;
}

uint32_t login(char **jwt) {
    char targetURL[MAX_URL_SIZE];
    uint32_t result = 0;
    unsigned char *response = NULL;
    size_t responseLength = 0;
    struct curl_slist *headers = NULL;
    unsigned char content[1024];
    int contentSize = 0;
    uint32_t httpStatusCode = 0;

    sprintf(targetURL, AUTH);
    headers = curl_slist_append(headers, "Content-Type:application/json");
    contentSize = sprintf(content,
                          "{"
                             "\"username\": \"" USERNAME "\","
                             "\"passwd\": \"" PASSWORD "\""
                          "}");

    struct json_object *pJsonObj = NULL;

    result = ma_communication_send(targetURL,
                                   HTTP_METHOD_POST,
                                   &headers,
                                   content,
                                   contentSize,
                                   &httpStatusCode,
                                   &response,
                                   &responseLength);
    if (result != 0) {
        printf("MA-Communication send failed.\n");
        return 1;
    }
    if (responseLength > 0) {
        dump(response, responseLength);
        if (httpStatusCode == 200) {
            pJsonObj = json_tokener_parse(response);
            struct json_object *pObj = NULL;
            json_object_object_get_ex(pJsonObj, "jwt", &pObj);
            *jwt = malloc(json_object_get_string_len(pObj) + 1);
            sprintf(*jwt, "%s", json_object_get_string(pObj));
        }
        free(response);
    } else {
        printf("empty response\n");
    }

    return 0;
}

int main(void) {

    int8_t result = 0;
    char *jwt = NULL;

    result =  init();
    if (result != 0) {
        return 1;
    }

    result = login(&jwt);
    if (result == 0) {
        printf("jwt: %s", jwt);
    }

    ma_communication_deinit();

    return 0;
}
