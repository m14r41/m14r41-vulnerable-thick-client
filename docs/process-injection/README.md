# Process Injection — Full Writeups

Deep-dive writeups for the seven process-injection challenges in M14R41 Vulnerable Thick Client.
Each one walks through: concept, discovery, copy-paste build + run, impact demonstrations (pop calc + reverse shell), and a secure-code fix.

| # | Technique | Writeup |
|---|---|---|
| 13 | CreateRemoteThread + LoadLibrary | [13-create-remote-thread.md](13-create-remote-thread.md) |
| 14 | QueueUserAPC injection | [14-apc-injection.md](14-apc-injection.md) |
| 15 | Process hollowing | [15-process-hollowing.md](15-process-hollowing.md) |
| 16 | Reflective DLL loading | [16-reflective-dll.md](16-reflective-dll.md) |
| 17 | .NET Assembly.Load injection | [17-dotnet-assembly-load.md](17-dotnet-assembly-load.md) |
| 18 | Thread hijacking (SetThreadContext) | [18-thread-hijacking.md](18-thread-hijacking.md) |
| 19 | No anti-debug / debugger-flip | [19-no-anti-debug.md](19-no-anti-debug.md) |

## How to use

1. Spin up MVTC in an isolated VM (see the main README for setup).
2. Launch the app, log in, and let it idle in the background.
3. Pick a technique and follow its writeup end to end.
4. First shot: confirm the sentinel string gets exfiltrated (that's the challenge).
5. Second shot: swap the DLL payload for `calc.exe` or a reverse shell to demonstrate real-world impact to a stakeholder.

Reusable payload sources (pop-calc + reverse shell, both EXE and DLL, with pre-built x64 binaries) are published at:

**https://github.com/m14r41/PayloadEverything/tree/main/thick-client/payload**

## For authorized testing only

These writeups are complete attacker-side chains. Use them in an isolated VM against the lab, inside a CTF, or on a scope you own or were explicitly authorized to test. Nothing here is for use against systems you don't control.
