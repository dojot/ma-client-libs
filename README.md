# ma-client-libs

The libraries in this repository provide a way to perform mutual authentication functions. To do this, 3 steps must be followed:

1. Library initialization with URLs from the server
2. Register a callback function
3. Call the mutual authentication function

## Library initialization

The initialization process informs the library the URLs it will use when performing mutual authentication.

**Initialize Kerberos**
```c
errno_t initializeKerberos(uint8_t* host, uint8_t hostLength, uint8_t* uriRequestAS, uint8_t requestASLength, uint8_t* uriRequestAP, uint8_t requestAPLength)
```
|Argument|Description|
|---|---|
|host|host main URL|
|hostLength| Size of host URL string|
|uriRequestAS| RequestAS API endpoit|
|requestASLength| Size of requestAS string|
|uriRequestAP|requestAP API endpoint|
|requestAPLength|Size of requestAP string|

The following code shows an example of how the function can be used:
```c
char* host = "http://localhost:8000/";
char* reqAS = "kerberos/requestAS";
char* reqAP = "kerberos/requestAP";

errno_t ret = initializeKerberos(host, strlen(host), reqAS, strlen(reqAS), reqAP, strlen(reqAP));
```

## Register callback

While the mutual authentication process is performed the library communicates with the server and verifies the received data. If some error occurs during this process, the library will use an error callback function.

This error callback function is implemented by the library user an must be registered before the authentication process. The function can contain error handling or logging code, e.g.

**Set Callback**
```c
errno_t setCallback(void (*callback)(int))
```

The following code shows an example of how the callback can be created and registered:
```c
void errorCallback(int err){
    // Error handling and logging code
}

errno_t ret = setCallback(&errorCallback);
```

## Call Mutual Authentication function

After setting the server URLs and registering the callback function, the library is ready to perform the mutual authentication process.

**Execute Kerberos Handshake**
```c
errno_t executeKerberosHandshake()
```

The following code shows an example of how the function can be used:
```c
errno_t ret = executeKerberosHandshake();
```
