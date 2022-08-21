# Windows API

## Overview

The Windows API (Win32 API) is the name given by Microsoft to the core set of application programming interfaces available in Windows operating systems. They are dynamic-link libraries (DLLs) that are part of the operating system.

Windows APIs do not use managed code, do not have built-in type libraries, and use data types that are different than those used with Visual Studio. Because of these differences, and because Windows APIs are not COM objects, interoperability with Windows APIs and the .NET Framework is performed using platform invoke, or PInvoke. Platform invoke is a service that enables managed code to call unmanaged functions implemented in DLLs.

You can use PInvoke in Visual Basic by using either the "Declare" statement or applying the "DllImport" attribute to an empty procedure.

Windows API calls were an important part of Visual Basic programming in the past, but are seldom necessary with Visual Basic .NET. Whenever possible, you should use managed code from the .NET Framework to perform tasks, instead of Windows API calls.

## Argument and Data Type Declarations&#x20;

The data types supported by Windows are used to define function return values, function and message parameters, and structure members. They define the size and meaning of these elements.

Declaring the arguments and their data types can be challenging because the data types that Windows uses do not correspond to Visual Studio data types.

Visual Basic does a lot of the work for you by converting arguments to compatible data types, a process called marshaling. You can explicitly control how arguments are marshalled by using the "MarshalAsAttribute" attribute defined in the "System.Runtime.InteropServices" namespace.

## Windows API Constants&#x20;

Some arguments are combinations of constants. You can determine the numeric value of these constants by examining the #define statements in the relevant header (.h) file.&#x20;

The numeric values are generally shown in hexadecimal, so you may want to use a calculator to add them and convert to decimal. Although you can use the decimal result directly, it is better to declare these values as constants in your application and combine them using the "Or" operator.

### Declare constants for Windows API calls&#x20;

1. Consult the documentation for the Windows function you are calling. Determine the name of the constants it uses and the name of the .h file that contains the numeric values for these constants.
2. Use a text editor, such as Notepad, to view the contents of the header (.h) file, and find the values associated with the constants you are using.
3. Add equivalent "Const" statements to your class or module to make these constants available to your application.

## Function Prototypes

A function prototype or function interface is a declaration of a function that specifies the function’s name and type signature (arity, data types of parameters, and return type), but omits the function body. While a function definition specifies how the function does what it does (the "implementation"), a function prototype merely specifies its interface, i.e. what data types go in and come out of it.























## Resources

{% embed url="https://docs.microsoft.com/en-gb/windows/win32/apiindex/windows-api-list?redirectedfrom=MSDN" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/framework/interop/consuming-unmanaged-dll-functions" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types" %}

