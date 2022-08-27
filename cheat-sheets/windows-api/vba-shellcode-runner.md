# VBA Shellcode Runner

{% hint style="danger" %}
This page is incomplete
{% endhint %}



A shellcode runner is a piece of code that executes shellcode in memory.

## Overview

Overview of requirements to build a VBA shellcode runner in a VBA macro that executes in memory:

1. Declare the Win32 API functions.
2. Declare the relevant variables to use with the functions.
3. Declare and instantiate a variable to hold the shellcode.
4. Call VirtualAlloc to create space in memory for the shellcode.
5. Call RtlMoveMemory to put the shellcode into the memory using a For loop.
6. Call CreateThread to execute the shellcode in memory.

## Win32 APIs

The most common approach is to use the following three Win32 APIs from Kernel32.dll:&#x20;

> VirtualAlloc --> allocate unmanaged memory that is readable, writable and executable
>
> RtlMoveMemory --> copy the shellcode into the newly allocated memory
>
> CreateThread --> create a new execution thread in the process to execute the shellcode

Usage of the these APIs is described below.

{% hint style="warning" %}
Insert diagrams depicting the Win32 API usage for the above APIs
{% endhint %}

{% hint style="danger" %}
In order for a payload to execute, it needs to target the correct architecture. Verify the OS architecture as well as the application architecture to avoid potentially crashing a target system. For example, Office 2016 installs as 32-bit by default, even when installed on a 64-bit system.
{% endhint %}

## Variables



## Shellcode

Generate the shellcode with "msfvenom" and output it in the "vbapplication" format. To avoid closing the target application when the shellcode exits, use the "EXITFUNC" option with a value of "thread".



