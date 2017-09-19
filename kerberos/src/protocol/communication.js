processReply = Module.cwrap('processReply', null, ['number', 'number']);
processError = Module.cwrap('processError', null, []);
var xhr = new XMLHttpRequest();
xhr.open('POST', 'host' + 'path', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.responseType = 'arraybuffer';

xhr.onerror = function(e) { processError(); };

xhr.onload = function(e) {
	 var reply = new Uint8Array(xhr.response);
	 var nReplyBytes = reply.length * reply.BYTES_PER_ELEMENT;
	 var replyPtr = Module._malloc(nReplyBytes);
	 var replyHeap = new Uint8Array(Module.HEAPU8.buffer, replyPtr, nReplyBytes);
	 replyHeap.set(new Uint8Array(reply.buffer));
	 processReply(reply.length, replyHeap.byteOffset);
	 Module._free(replyHeap.byteOffset);};
var uInt8Array = new Uint8Array('data');
try{xhr.send(uInt8Array.buffer);} catch(exception) { processError();}
