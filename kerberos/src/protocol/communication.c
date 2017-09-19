#include "communication.h"

#include <curl/curl.h>
#include <stdio.h>

size_t receive_reply(void *ptr, size_t size, size_t nmemb, void *stream){
    size_t totalSize = size * nmemb;
    printf("receive_reply: size = %d, nmemb = %d\n", size, nmemb);
    int i = 0;
/*    char c;*/
/*    for(i = 0; i < totalSize; i++){*/
/*        c = *((char*)ptr + (sizeof(char) * i));*/
/*        printf("%c", c);*/
/*    }*/
/*    printf("\n");*/
    
    uint8_t u;
    for(i = 0; i < totalSize; i++){
        u = *((uint8_t*)ptr + (sizeof(uint8_t) * i));
        printf("%02x", u);
    }
    printf("\n");

    processReply(totalSize, (uint8_t*)ptr);
    return totalSize;
}

/*
 * Sends binary data to the Kerberos service.
 * Upon receipt of a reply, the callback method specified in loader.addEventListener is called
 */
void send_message(uint8_t* encodedInput, size_t encodedLength, char* host, char* path)
{
    printf("send_message()\n");
    
    CURL *curl;
    CURLcode res;
    size_t urlLen = strlen(host) + strlen(path);
    char* url = (char*) malloc(sizeof(char) * (urlLen + 1));
    if(url == NULL){
        return;
    }
    strcpy(url, host);
    strcat(url, path);

    curl = curl_easy_init();
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

/*	char* template ="processReply = Module.cwrap('processReply', null, ['number', 'number']);"*/
/*			"processError = Module.cwrap('processError', null, []);"*/
/*			"var xhr = new XMLHttpRequest();"*/
/*			"xhr.open('POST', 'host' + 'path', true);"*/
/*			"xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');"*/
/*			"xhr.responseType = 'arraybuffer';"*/
/*			"xhr.onerror = function(e) { processError(); };"*/
/*			"xhr.onload = function(e) {"*/
/*				" var reply = new Uint8Array(xhr.response); "*/
/*				" var nReplyBytes = reply.length * reply.BYTES_PER_ELEMENT;"*/
/*				" var replyPtr = Module._malloc(nReplyBytes);"*/
/*				" var replyHeap = new Uint8Array(Module.HEAPU8.buffer, replyPtr, nReplyBytes);"*/
/*				" replyHeap.set(new Uint8Array(reply.buffer));"*/
/*				" processReply(reply.length, replyHeap.byteOffset);"*/
/*				" Module._free(replyHeap.byteOffset);};"*/
/*			"var uInt8Array = new Uint8Array('data');"*/
/*			"try{xhr.send(uInt8Array.buffer);} catch(exception) { processError();}";*/
/*	char* code = malloc(sizeof(char) * (strlen(template) + 1));*/
/*	strcpy(code, template);*/
/*	code = updateCode(code, "'host'", host, 1);*/
/*	code = updateCode(code, "'path'", path, 1);*/
/*	code = updateCode(code, "'data'", encodeAsArray(encodedLength, encodedInput), 0);*/
/*	emscripten_run_script(code);*/
}
