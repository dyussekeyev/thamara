# THAMARA - Threat Hunting with AMSI and YARA

Thamara is a set of tools that allows a security analyst to detect malware using YARA rules.

## Description

During my job at the government security operations centre, I realized the lack of tools that will help defeat specific malware used in targeted attacks. Due to limited spread, antivirus software often does not detect targeted malware. Discovering such malware using TTP and host/network artefacts is challenging and time-consuming for threat hunters compared with traditional signature-based detection. At the same time, malware sample submission does not guarantee that matching signatures will appear. Moreover, it is often impossible to share the samples because they are closely related to the victim. That's why simple tools are needed to conduct signature-based scanning using industry-recognized YARA syntax.

Since Windows 10, malware detection capabilities have already been provided to developers as Antimalware Scan Interface (AMSI). Its primary purpose is to defeat fileless malware and offer a simple antivirus interface to third-party developers for scanning various entities (blobs or strings). The main disadvantage of such an approach is that if the program does not utilize the AMSI interface, it cannot be used to detect memory-only malware. Considering all system processes, we might observe that only a few processes use AMSI capabilities.

That's why forced scanning might help improve system security. This method is implemented in my pet project, a THAMARA. It uses Microsoft Detours to hook several functions often used in malware and related to data processing (ReadProcessMemory, VirtualFree, etc.). After intercepting the code execution, it initializes and calls the AMSI interface to scan corresponding data storages (blobs, buffers, etc.). This simple approach is designed to improve system protection against malware.

## Architecture

THAMARA consists of several components:

1. **AmsiScanner** - DLL that is implemented as the provider of the antimalware product (see also [IAntimalwareProvider](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider)). The buffers/blobs are scanned using the [YARA](https://github.com/VirusTotal/yara) static library.

     Rules are stored in the following file:

     ```
     C:\ProgramData\Thamara\rules.yar
     ```

     The following file stores detections:

     ```
     C:\ProgramData\Thamara\amsi.log
     ```

3. **AmsiForcedScanner** - DLL is to be injected into the monitored process to intercept the certification of the WinAPI function and forward transmitted data into AmsiScanner. The hooking capabilities are provided by the [Microsoft Detours](https://github.com/microsoft/Detours) static library. The list of hooked functions is below:

     ```
     NtWriteVirtualMemory
     NtReadVirtualMemory
     RtlDecompressBuffer
     RtlCompressBuffer
     ```

4. **AmsiInjector** - executable that enumerates existing processes and injects AmsiForcedScanner into each (in progress).

5. **AmsiTest** - executable that provides testing of compiled libraries.

## Demo

### First Early Demo

[![THAMARA - First Early Demo](https://img.youtube.com/vi/Eh9EsSAsQEA/hqdefault.jpg)](https://www.youtube.com/watch?v=Eh9EsSAsQEA)

## Installation

1. Use Microsoft Visual Studio 2022 to build the solution.

2. Create a directory

     ```
     C:\ProgramData\Thamara
     ```

3. Copy following files into above directory:

     ```
     AmsiProvider64.dll
     AmsiForcedScanner64.dll
     AmsiTest.exe
     ```

4. Create the file:

     ```
     C:\ProgramData\Thamara\rules.yar
     ```

     with following content:

     ```
     rule AmsiTestRule {
	     strings:
		     $str1 = { FE ED BA BE }
		     $str2 = { DE AD C0 DE }
		     $str3 = { FA CE B0 0C }
	     condition:
		     all of them
     }
     ```

5. Start **cmd.exe** with administrator privileges and enter following command:

     ```
     regsvr32 C:\ProgramData\Thamara\AmsiProvider64.dll
     ```

6. Start **AmsiTest.exe**

7. Open using a **text viewer/editor** the following file:

     ```
     C:\ProgramData\Thamara\amsi.log
     ```

     You should see something like this:

     ```
     datetime="2024.03.20 20:11:30.660" appName="C:\ProgramData\Thamara\AmsiTest.exe" contentName="NtReadVirtualMemory (forced)" rule_id="AmsiTestRule" sha1="efb3d4fed013c67e11c97f5edbd8e116eef8e0ef"
     datetime="2024.03.20 20:11:30.672" appName="C:\ProgramData\Thamara\AmsiTest.exe" contentName="NtWriteVirtualMemory (forced)" rule_id="AmsiTestRule" sha1="efb3d4fed013c67e11c97f5edbd8e116eef8e0ef"
     datetime="2024.03.20 20:11:30.678" appName="AmsiTest" contentName="Native Amsi Test" rule_id="AmsiTestRule" sha1="efb3d4fed013c67e11c97f5edbd8e116eef8e0ef"
     datetime="2024.03.20 20:11:30.684" appName="C:\ProgramData\Thamara\AmsiTest.exe" contentName="RtlCompressBuffer (forced)" rule_id="AmsiTestRule" sha1="efb3d4fed013c67e11c97f5edbd8e116eef8e0ef"
     datetime="2024.03.20 20:11:30.689" appName="C:\ProgramData\Thamara\AmsiTest.exe" contentName="RtlDecompressBuffer (forced)" rule_id="AmsiTestRule" sha1="efb3d4fed013c67e11c97f5edbd8e116eef8e0ef"
     ```
     
9. Disable AMSI Provider using following command with administrator privileges:

     ```
     regsvr32 /u C:\ProgramData\Thamara\AmsiProvider64.dll
     ```

## Contributing

The best way you may contribute is to test software and suggest feature requests.

Please feel free to open an issue for discussing the changes.

## License

[MIT](https://choosealicense.com/licenses/mit/)
