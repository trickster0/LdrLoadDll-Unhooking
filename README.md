# LdrLoadDll-Unhooking
LdrLoadDll Unhooking

This is a proof of concept of bypassing(unhooking) the hook of potential EDRs, in using an unhooked version of LdrLoadDll to load DLLs.  
This is basically a reroute of the initial instruction of LdrLoadDll that will be executed in private memory and then reroute back into the normal code of LdrLoadDll,  
Which is better for OPSEC since, all the calls looks like they are coming directly from the NTDLL anyway.  
Why did I make this? Certain NTDLL export functions do not follow the SYSCALL procedure, hence this specific function like a few others need to be handled in a different manner.
