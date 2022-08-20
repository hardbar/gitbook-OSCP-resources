# Excel

## VBA Application Launcher

We can launch applications outside of VBA with the "Shell" function. The function takes two arguments, first, the application to launch, and second, the "WindowStyle" of the launched application. We can use the "vbHide" or "0" value to launch a hidden application. Note, the application may not open in a window, however, it is visible as a child process with any process viewer/explorer utility such as procexp/64 from sysinternals.

Create a new macro, call it "mymacro" or any arbitrary name. When the VB editor opens, select "ThisWorkbook" under the excel objects section in the project tree view. Make sure "Workbook" is selected in the first dropdown list and "Open" in the second. Then paste in the code below and save and exit. This will run once the "Enable" button has been clicked.

```vba
Private Sub Workbook_Open()
    Dim str As String
    str = "cmd.exe"
    Shell str, 0
End Sub
```













