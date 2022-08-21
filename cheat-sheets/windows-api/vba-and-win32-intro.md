# VBA & Win32 Intro

## Key Concepts

### Passing by Value

You pass an argument by value by specifying the "ByVal" keyword for the corresponding parameter in the procedure definition. When you use this passing mechanism, Visual Basic copies the value of the underlying programming element into a local variable in the procedure. The procedure code does not have any access to the underlying element in the calling code.

### Passing by Reference

You pass an argument by reference by specifying the "ByRef" keyword for the corresponding parameter in the procedure definition. When you use this passing mechanism, Visual Basic gives the procedure a direct reference to the underlying programming element in the calling code.

## Calling Windows APIs with VBA

Use a "Declare" statement to declare a reference to an external procedure in a dynamic-link library (DLL). The statement should include the name of the function, the DLL it resides in, the argument data types and the return value data types.

## Data Type Conversion Table

The function arguments described in the MSDN documentation are native C types. In order for us to use the function in VBA, we need to convert the native types to their corresponding VBA data types.

The table below provides a mapping of c data types to their corresponding VBA data types.

> Source: [https://www.codingdomain.com/visualbasic/win32api/datatypes/](https://www.codingdomain.com/visualbasic/win32api/datatypes/)

|       C data type       |                 Declare as                 |                                  Description                                  |
| :---------------------: | :----------------------------------------: | :---------------------------------------------------------------------------: |
|        BYTE, CHAR       |           ByVal variable As Byte           |                          A single byte in the memory                          |
|           BOOL          |           ByVal variable As Long           |                     Long that should have the value 1 or 0                    |
|           ATOM          |          ByVal variable As Integer         |                   An expression that evaluates to an Integer                  |
|          SHORT          |          ByVal variable As Integer         |          An 16 bit value, like the integer type used in Visual Basic          |
|           INT           |           ByVal variable As Long           |                            A 32 bits integer value                            |
|           LONG          |           ByVal variable As Long           |                                Synonym for INT                                |
|           WORD          |          ByVal variable As Integer         |           An integer value, or two (bit wise concatenated) BYTES \*           |
|          DWORD          |           ByVal variable As Long           |             A long value, or two (bit wise concatenated) WORDS \*             |
|           UINT          |           ByVal variable As Long           |              A 32 bits integer that can't have values below 0 \*              |
| LPARAM, WPARAM, LRESULT |           ByVal variable As Long           |       Synonym for INT, used in some cases to describe the expected value      |
|         COLORREF        |           ByVal variable As Long           |   Synonym for INT; A simple RGB color code; but not like OLE\_COLOR does \*   |
|  HWND, HDC, HMENU, etc. |           ByVal variable As Long           | Synonym for INT; used in some cases to describe the expected value (a handle) |
|  LPDWORD, LPINT, LPUINT |              variable As Long              |                     Long Pointer to the data type after LP                    |
|          LPWORD         |             variable As Integer            |                             Long Pointer to a WORD                            |
|          LPRECT         |              variable As RECT              |                     Long Pointer to a Type RECT structure                     |
|           LP\*          |             variable As (type)             |              Long Pointer to a variable, structure or function \*             |
|      LPSTR, LPCSTR      |          ByVal variable As String          |              A String variable, Visual Basic converts the values              |
|          LPVOID         |               variable As Any              |                 Any variable (use ByVal when passing a string)                |
|           NULL          | <p>As Any or<br>ByVal variable As Long</p> |          Only supply ByVal Nothing, ByVal 0& or vbNullString as value         |
|           VOID          |                Sub procedure               |             Not applicable; void means empty, nothing, nada, nope             |

## Example 1

In this example, we'll use the "GetUserNameA" and "GetComputerNameA" functions from the Win32 API to retrieve the name of the user associated with the current thread, and the NetBIOS name of the computer. After retrieving the data, we'll display it in a message box using the VBA "MsgBox" function.

In order to use these functions, we will need to consult the documentation for each on MSDN (see Resources section for links).&#x20;

### Step 1: Building the "Declare" statement

To build the statement, we need the following information

* the function prototypes
* the converted argument and return value data types
* the DLL containing the function

#### GetUserNameA:

Here is the function prototype:

```csharp
BOOL GetUserNameA(
  [out]     LPSTR   lpBuffer,
  [in, out] LPDWORD pcbBuffer
);
```

Here is the converted types:

> In C, LPSTR is a pointer to a string. In VBA, the String object also holds a pointer to a string. For this reason, we can pass the argument by value because the types match.\
> LPSTR --> ByVal lpBuffer as String
>
> In C, LPDWORD is a reference (pointer) to a DWORD, which is the maximum size of a buffer that will contain a string. In this case, we convert it to a VBA Long data type and pass it by reference to obtain a pointer.\
> LPDWORD --> ByRef pcbBuffer as Long
>
> In C, the return type is a Boolean, which can be translated into a Long in VBA.\
> BOOL --> As Long

The DLL that contains this function:

> GetUserNameA --> Advapi32.dll

Using all the above information, we can build the "Declare" statement as follows:

```vba
Private Declare Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef pcbBuffer As Long) As Long
```

#### GetComputerNameA

Here is the function prototype:

```csharp
BOOL GetComputerNameA(
  [out]     LPSTR   lpBuffer,
  [in, out] LPDWORD nSize
);
```

Here is the converted types:

> LPSTR --> ByVal lpBuffer as String
>
> LPDWORD --> ByRef nSize as Long
>
> BOOL --> As Long

The DLL that contains this function:

> GetComputerNameA --> Kernel32.dll

Using all the above information, we can build the "Declare" statement as follows:

```vba
Private Declare Function GetComputerName Lib "Kernel32.dll" Alias "GetComputerNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long
```

{% hint style="info" %}
The Declare statements must be placed outside the function or subroutine in VBA.
{% endhint %}

### Step 2: Defining the Variables for the imported function

Next, we need to define the variables to use with the imported functions, which includes, the return value (Long), the output buffer, and the size of the output buffer.

```vba
Dim result1 As Long
Dim outBuff1 As String * 256
Dim buffSize1 As Long
buffSize1 = 256

Dim result2 As Long
Dim outBuff2 As String * 256
Dim buffSize2 As Long
buffSize2 = 256
```

### Step 3: Calling the imported functions

Call the functions with the relevant parameters.

```vba
result1 = GetUserName(outBuff1, buffSize1)

result2 = GetComputerName(outBuff2, buffSize2)
```

### Step 4: Finding the length of the returned string

Before we can print the result, we need to find the string length, since we don't know how long the returned strings will be (username & computername).&#x20;

In C, strings are terminated with a null byte character, and so we can use this to determine the string length. To do so, we use the "InStr" function which takes 3 arguments, the starting location, the string to search, and the search character (the null byte). This will return the location of the null byte. If we subtract 1 from that value, we'll have the length of the string.

```vba
strlen1 = InStr(1, outBuff1, vbNullChar) - 1
  
strlen2 = InStr(1, outBuff2, vbNullChar) - 1
```

### Step 5: Display the results in Message Box

The code below will display the user name in the first box and the computer name in the second box.

```vba
MsgBox Left$(outBuff1, strlen1)
MsgBox Left$(outBuff2, strlen2)
```

### The Full Code:

```vba
Private Declare Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long
Private Declare Function GetComputerName Lib "Kernel32.dll" Alias "GetComputerNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long

Function macro1()
  'get the user name
  Dim result1 As Long
  Dim outBuff1 As String * 256
  Dim buffSize1 As Long
  buffSize1 = 256
  Dim strlen1 As Long
  result1 = GetUserName(outBuff1, buffSize1)
  strlen1 = InStr(1, outBuff1, vbNullChar) - 1

  'get the computer name
  Dim result2 As Long
  Dim outBuff2 As String * 256
  Dim buffSize2 As Long
  buffSize2 = 256
  Dim strlen2 As Long
  result2 = GetComputerName(outBuff2, buffSize2)
  strlen2 = InStr(1, outBuff2, vbNullChar) - 1

  'display in message boxes
  MsgBox Left$(outBuff1, strlen1)
  MsgBox Left$(outBuff2, strlen2)

End Function

Sub NewMacro()
    macro1
End Sub
```



## Resources

{% embed url="https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/declare-statement" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/visual-basic/language-reference/data-types/" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/visual-basic/programming-guide/language-features/procedures/differences-between-passing-an-argument-by-value-and-by-reference" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/visual-basic/programming-guide/language-features/data-types/value-types-and-reference-types" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcomputernamea" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/framework/interop/interop-marshalling" %}



