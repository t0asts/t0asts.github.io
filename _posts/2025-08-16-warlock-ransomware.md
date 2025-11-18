---
layout: post
title:  "Warlock Group: We're only here for SharePoint and the Lamborghinis"
permalink: warlock-ransomware
---

![Site](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/warlocksite.png)  

- [Overview](#overview)
- [IOCs](#iocs)
- [Initial Inspection](#initial-inspection)
- [Safety Check](#safety-check)
- [Emptying Recycle Bin](#emptying-recycle-bin)
- [Prepare Target Drives](#prepare-target-drives)
- [Impair Defenses](#impair-defenses)
- [WOW Check](#wow-check)
- [Delete VSS Snapshots](#delete-vss-snapshots)
- [Worker Thread Setup](#worker-thread-setup)
- [Query Target Drives](#query-target-drives)
- [File Encryption Process](#file-encryption-process)
- [Dropping Ransom Note](#dropping-ransom-note)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Acknowledgment](#acknowledgment)

## Overview

In this post I'm going over my analysis of a Warlock ransomware sample, a family that has emerged as a result of the recent on-prem SharePoint chained RCE vulnerability ("ToolShell") that has become a fan favorite of threat groups, a notable one being [Storm-2603](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/#storm-2603), who are compromising internet-facing on-prem SharePoint servers, and deploying the Warlock ransomware (via software deployment GPO) once they have moved laterally throughout target environments. I am not covering the deserialization or path traversal SharePoint vulnerabilities in post (yet), so for more info about those I recommend heading to [Kaspersky's post](https://securelist.com/toolshell-explained/117045/).  

## IOCs

The sample analyzed in this post is a 32-bit Windows console app executable.

**Group Sites:**   
[hxxp://elqfbcx5nofwtqfookqml7ltx2g6q6tmddys6e25vgu3al2meim6cbqd[.]onion](https://www.virustotal.com/gui/url/31884aaf95592f1bd55d589916ef490e332c32dff722e536cea8e1331cfe5d8f)  
[hxxp://zfytizegsze6uiswodhbaalyy5rawaytv2nzyzdkt3susbewviqqh7yd[.]onion](https://www.virustotal.com/gui/url/5e2420bf60f0d86f6483c85eb80214f13c061f455434ecba6612f89afb8b3ce3)  

**SHA-256:**  
[da8de7257c6897d2220cdf9d4755b15aeb38715807e3665716d2ee761c266fdb](https://www.virustotal.com/gui/file/da8de7257c6897d2220cdf9d4755b15aeb38715807e3665716d2ee761c266fdb)

## Initial Inspection

Getting started, I dropped the binary straight into [DIE](https://github.com/horsicq/Detect-It-Easy) (Detect It Easy) and lucky for me, this sample was NOT packed or obfuscated with a commercial software protector (presumably dropped by a loader or initial stage that is packed/obfuscated), so time to open it in [IDA](https://hex-rays.com/).

![DIE](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/die.png)  
***Figure 1: Detect It Easy***  

Skipping past the CRT setup to the main function, the first thing the ransomware does is detach the console window, to hide execution from the user (very subtle).

![HideConsole](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/hideconsole.png)  
***Figure 2: Hide Console Window***  

## Safety Check

The computer name is retrieved and checked against a hardcoded hostname (potentially to avoid infecting the developer or affiliates), but this build appears to have the placeholder hostname. If the hostname of the target system matches the whitelisted entry, execution is halted. If the hostname is unable to be retrieved, the hostname check is skipped.

![WhitelistHostCheck](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/whitelisthostcheck.png)  
***Figure 3: Whitelisted Host Check***  

## Emptying Recycle Bin

The actual malicious code is now fired off now. First the shutdown priority is set to delay termination in the event of a system shutdown, and the system recycle bin is cleared silently (no confirmation, no progress indicator, no sound).

![ShutdownParamClearBin](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/shutdownparamclearbin.png)  
***Figure 4: Set Shutdown Params and Clear Recycle Bin***  

## Prepare Target Drives

Next, the list of NTFS volumes is queried, and any volume that is unmapped is assigned one, so the ransomware can access and encrypt non-system drives for maximum impact.

![MountVolumesToLetters](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/mountvolumestoletter.png)  
***Figure 5: Mount Unmapped Volumes to Unused Drive Letters***  

## Impair Defenses

To prevent interference during the encryption process, backup software and security software services are stopped, starting with dependent services, and eventually the main list of target services. Services that are already stopped or pending shutdown are skipped to avoid infinite service control request looping.

![TargetServices](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/targetservices.png)  
***Figure 6: Targeted Services***  

![KillServices_1](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/killservices1.png)  
![KillServices_2](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/killservices2.png)  
***Figures 7-8: Security and Backup Services Stopped***  

With services terminated, processes related to security software, backup software, database software, and productivity software are also terminated. This serves to release file locks held by these processes, and to avoid interruption by AV or EDR software when encrypting files.

![TargetProcesses](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/targetprocesses.png)  
***Figure 9: Target Processes***  

![KillProcesses](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/killprocesses.png)  
***Figure 10: Security and Backup Processes Terminated***  

## WOW Check

If the ransomware process is running under `WOW64` (Windows-On-Windows 64), which it will if run on a 64-bit version of Windows (the binary is 32-bit), `WOW64` file system redirection is temporarily disabled, so the ransomware can access the `System32` folder, and avoid being redirected to the `SysWOW64` folder.

## Delete VSS Snapshots

To hinder recovery efforts, all VSS snapshots are enumerated and forcibly deleted through `COM` instead of the much noisier `vssadmin` or `wmic` equivalents, to avoid leaving command line argument activity behind. 

![DeleteVSSSnapshots](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/deletesnapshots.png)  
***Figure 11: Disable WOW64 FS Redirection and Delete VSS Snapshots***  

## Worker Thread Setup

Before encrypting files, the local processors on the target host are queried and multiplied by eight, to determine how many worker threads the ransomware will create.

![CreateWorkers](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/createworkers.png)  
***Figure 12: Create Worker Threads***  

The worker threads will now wait for batches of target paths for encryption.

## Query Target Drives

Each drive mapped to a drive letter is queried for the drive type, to exclude those that are CD-ROM "drives" and any drives that point to an invalid volume, to avoid erroring out when processing paths for the worker threads.

![QueryDriveType](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/querydrives.png)  
***Figure 13: Query Drive Type***  

For the remaining applicable drives, the directory structure is recursively walked starting from the root to create batches of files that will be handled by the worker threads for encryption. Any files or directories that match against hardcoded exclusion lists for extensions and path names will be skipped from being added to the file batches.

![ExcludedItems](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/excludeditems.png)  
***Figure 14: Excluded Files and Directories***  

![ExcludedExtensions](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/excludedextensions.png)  
***Figure 15: Excluded Extensions***  

![EnumerateDirectory_1](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/enumdirectory1.png)  
![EnumerateDirectory_2](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/enumdirectory2.png)  
***Figures 16-17: Walking Directory Structure***  

In addition to drives, any accessible SMB shares are enumerated and processed to ensure files on shares are also added to the batches for encryption.

![EnumerateShares](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/enumshares.png)  
***Figure 18: Enumerate Shares***  

## File Encryption Process

For each batch of files (~50), worker threads begin the file encryption process. Each file in the batch is renamed to include `.x2anylock` trailing the original extension. If during the renaming process a file is locked, the offending process will be forcibly terminated.

![AppendExtension_1](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/addextension1.png)  
![AppendExtension_2](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/addextension2.png)  
***Figures 19-20: Append Group Extension***  

![KillLockingProcess](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/terminatelockingprocess.png)  
***Figure 21: Terminate Locking Processes***  

Every file uses a per-file symmetric ChaCha key derived via X25519 elliptic curve Diffie-Hellman exchange between a newly generated ephemeral private key on the target host and an embedded 32 byte public key. The 32 byte shared secret is hashed using SHA-256 to produce the 32 byte content key. The 8 byte nonce is the first 8 bytes of SHA-256 (key). The file is then encrypted (either in place when `-e` is passed as an argument, or after appending the extension `.x2anylock`), and a footer containing the ephemeral public key + 16-byte hash result (`SHA-256(iv)[:16]`) + fixed 32 byte marker is appended so the decryptor can recompute the key for file recovery.

![EncryptFiles_1](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/encryptfiles1.png)  
![EncryptFiles_2](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/encryptfiles2.png)  
![EncryptFiles_3](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/encryptfiles3.png)  
![EncryptFiles_4](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/encryptfiles4.png)  
***Figures 22-25: File Encryption***  

![PublicKey](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/attackerpublickey.png)  
***Figure 26: Embedded Public Key***  

## Dropping Ransom Note

The embedded ransom note is dropped alongside encrypted files throughout the duration of the process.

![DropRansomNote_1](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/dropnote1.png)  
![DropRansomNote_2](https://raw.githubusercontent.com/t0asts/t0asts.github.io/refs/heads/main/_media/warlock/dropnote2.png)  
***Figures 27-28: Drop Ransom Note***  

As the encryption for the file batches completes successfully, the worker threads will be killed off and the ransomware process is terminated.  

Overall nothing new nothing special.

## MITRE ATT&CK Mapping

- Collection (TA0009)  
    - T1005: Data from Local System  
- Defense Evasion (TA0005)  
    - T1562: Impair Defenses  
        - T1562.001: Disable or Modify Tools  
- Discovery (TA0007)  
    - T1007: System Service Discovery  
    - T1057: Process Discovery  
    - T1063: Security Software Discovery  
    - T1082: System Information Discovery  
    - T1083: File and Directory Discovery  
    - T1135: Network Share Discovery  
    - T1518: Software Discovery  
        - T1518.001: Security Software Discovery  
- Execution (TA0002)  
    - T1059: Command and Scripting Interpreter  
    - T1106: Native API  
    - T1129: Shared Modules  
- Impact (TA0040)  
    - T1486: Data Encrypted for Impact  
    - T1489: Service Stop  
    - T1490: Inhibit System Recovery  

## Acknowledgment 

That's all Folks!  

If I made any mistakes please let me know!  


