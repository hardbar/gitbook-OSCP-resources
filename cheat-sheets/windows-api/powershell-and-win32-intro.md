# PowerShell & Win32 Intro

PowerShell cannot natively interact with the Win32 APIs. The .NET framework allows for the use of C# from within PowerShell, where we can declare and import the required Win32 APIs using the "DllImportAttribute" class.





## Function Prototype to C# Method Signature

Translating the data types from C to C# can be done using Microsoft's Platform Invocation Services (P/Invoke). The P/Invoke APIs are contained in the "System" and "System.Runtime.InteropServices" namespaces which must be imported as part of the source code.

The following website documents the translations for the most commonly used Win32 APIs.

{% embed url="http://www.pinvoke.net/" %}

The site not only provides the data type conversions, but also the method signature for the relevant function prototype. A method signature is a unique identification of a method for the C# compiler. The signature consists of the method name and the type (value, reference, output) of each of its parameters including the return type.

Below is the function prototype for the "MessageBox" API which is contained within the "User32.dll" library file.

```c
int MessageBox(
  HWND    hWnd,
  LPCTSTR lpText,
  LPCTSTR lpCaption,
  UINT    uType
);
```

A quick search for "MessageBox" in the "User32" module on [http://www.pinvoke.net/](http://www.pinvoke.net/) provides the following C# method signature.

```csharp
[DllImport("user32.dll", SetLastError = true, CharSet= CharSet.Auto)]
public static extern int MessageBox(IntPtr hWnd, String text, String caption, uint type);
```

To use this, we need to create a class which will import the the signature using the "DllImport" attribute

```csharp
using System;
using System.Runtime.InteropServices;

public static class User32
{
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern bool MessageBox(
            IntPtr hWnd,     /// Parent window handle 
            String text,     /// Text message to display
            String caption,  /// Window caption
            int options);    /// MessageBox type
}
```







