# PowerShell Shellcode Runner



A shellcode runner is a piece of code that executes shellcode in memory.



{% hint style="danger" %}
This page is incomplete
{% endhint %}

## Overview

Overview of requirements to build a PowerShell shellcode runner in VBA macro that executes in memory:

1. Declare the Win32 API functions.
2. Declare the relevant variables to use with the functions.
3. Declare and instantiate a variable to hold the shellcode.
4. Call VirtualAlloc to create space in memory for the shellcode.
5. Call RtlMoveMemory to put the shellcode into the memory using a For loop.
6. Call CreateThread to execute the shellcode in memory.



### Steps:

1. Create a VBA macro with code to download a PowerShell script which contains the staging shellcode and run it in memory.
2. Launch the PowerShell script as a child process of the Office application. Under a default configuration, the child process will remain even id the Office application is closed.

















