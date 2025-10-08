# Brute Ratel C4 v2.1.2 (Retrace) 

# Functionality

## Core Evasion and Execution
- **Syscall Everything**: Bypasses EDR with direct system calls.
- **EDR Hook Avoidance**: Evades EDR hooks and monitoring.
- **Debugger Detection**: Detects EDR/AV monitoring.
- **In-Memory Execution**: Loads executables, DLLs, BOFs, PowerShell in memory.
- **Process Injection**: Uses WinAPI/NTAPI/syscalls for injection.
- **Memory Allocation**: Manages memory for shellcode/DLLs.
- **Token Stealing**: Steals tokens for privilege escalation.
- **LoadLibrary Proxying**: Routes DLL loading via legit functions.
- **Egress Evasion**: Uses legitimate services for C2.
- **Process Mitigation**: Applies stealth policies.

## Post-Exploitation
- **Command Execution**: Executes remote code.
- **Port Scanning**: Scans port ranges.
- **Screenshot Capture**: Captures screenshots.
- **Keystroke Logging**: Logs keystrokes.
- **Process Manipulation**: Lists, creates, kills processes.
- **File Operations**: Uploads/downloads/executes files.
- **Credential Harvesting**: Dumps credentials.
- **Shellcode Deployment**: Runs shellcode in memory.
- **DLL Loading**: Loads reflective DLLs.
- **EnumChildWindows**: Sets up shellcode execution.

## Networking and Proxy
- **SOCKS Proxy**: Supports SOCKS4a/5 with UDP/DNS.
- **Socksbridge**: Bridges traffic via DLLs.
- **HTTP/SMB/TCP Listeners**: Generates C2 payloads.
- **C2 Configuration**: Manages IPs, ports, encryption.

## UI and Automation
- **MITRE ATT&CK Graph**: Maps commands to ATT&CK.
- **Click Script**: Automates command sequences.
- **COFFExec**: Executes COFF files.
- **Payload Profiler**: Generates x86/x64 payloads.
- **Commander UI**: Enhances metadata display.

## Additional Features
- **One-Time Auth**: Secures C2 handshakes.
- **Dynamic IOCs**: Creates unique attack indicators.
- **Open-Source Integration**: Converts BOFs to functions.
- **x86 Support**: Full feature parity with x64.

**Interested?** Contact me on Telegram at https://t.me/x7xip2 and we can find the best price for each other.
