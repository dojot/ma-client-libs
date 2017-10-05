#include "communication.h"

#include <curl/curl.h>
#include <stdio.h>

size_t receive_reply(void *ptr, size_t size, size_t nmemb, void *stream){
    size_t totalSize = size * nmemb;

    processReply(totalSize, (uint8_t*)ptr);
    return totalSize;
}

/*
 * Sends binary data to the Kerberos service.
 * Upon receipt of a reply, the callback method specified in loader.addEventListener is called
 */
void send_message(uint8_t* encodedInput, size_t encodedLength, uint8_t* host, uint8_t* path)
{
    CURLcode res;
    size_t urlLen = strlen((char*)host) + strlen((char*)path);
    char* url = (char*) malloc(sizeof(char) * (urlLen + 1));
    if(url == NULL){
        return;
    }
    strcpy(url, host);
    strcat(url, path);

    CURL *curl = curl_easy_init();
    if(!curl){
        return;
    }

    struct curl_slist *slist = NULL;
    slist = curl_slist_append(slist, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encodedInput);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_reply);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(slist);

}
