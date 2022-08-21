# VBA

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
|           BOOL          |           ByVal variable As Long           |                 Long that's that should have the value 1 or 0                 |
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

## Example

In this example, we'll use the "GetUserName" and "GetComputerName" functions to retrieve the name of the user associated with the current thread, and the computer hostname. After retrieving the data, we'll display it in a "MessageBox".

In order to use these functions, we will need to consult the documentation for each on MSDN (see Resources section for links).&#x20;

### Step 1: Building the "Declare" statement

To build the statement, we need the following information

* the function prototypes
* the converted argument and return value data types
* the DLL containing the function

#### GetUserName:

Here is the function prototype:

```csharp
BOOL GetUserNameA(
  [out]     LPSTR   lpBuffer,
  [in, out] LPDWORD pcbBuffer
);
```

Here is the converted types:

> In C, LPSTR is a pointer to a string. In VBA, the String object also holds a pointer to a string. For this reason, we can pass the argument by value because the types match.
>
> LPSTR --> ByVal as String
>
> LPDWORD -->&#x20;

GetComputerName function prototype:

```csharp
BOOL GetComputerNameA(
  [out]     LPSTR   lpBuffer,
  [in, out] LPDWORD nSize
);
```

We will also need to know which DLL these functions reside in, which is also available in the function's documentation.

> GetUserName --> Advapi32.dll\
> GetComputerName --> Kernel32.dll















## Resources

{% embed url="https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/declare-statement" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/visual-basic/language-reference/data-types/" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/visual-basic/programming-guide/language-features/procedures/differences-between-passing-an-argument-by-value-and-by-reference" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcomputernamea" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/framework/interop/interop-marshalling" %}



