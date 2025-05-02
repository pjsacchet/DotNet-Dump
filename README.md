# DotNet-Dump
## Description
Dump password hashes and other useful info via .NET

## Design
This piece of rudimentary malware will be packaged with PsExec (from sysinternals) along with a batch script that will run the program. The CONOP is as follows:
- User downloads packaged/zipped files onto target computer
- Upon unzipping, our batch file will execute, executing:
  -  Our dotnet binary as SYSTEM via PsExec and
  -  Our python file to parse the contents 

## Execution
Upon execution, this program will:
- Survey the target for indications that Windows Defender is running and is active
  - If it is, it will try to mitigate/disable it via registry actions
    - If this fails, we exit
- Start parsing the registry, specifically the SAM hive for user related passowrd hashes 
- Program will dump password information to file; batch script will then feed this information into follow on script
- Dump passwords to final output file; cleanup and exit 

## Password Hashes
Plain password hashes (NTLM) on Windows are stored and retrieved via the following steps:
- Obtian the bootkey
  - This is really just a concatenation of four registry keys:
    - HKEY_LOCAL_MACHINE\SYSTEM\ControlSet%03d\Control\Lsa where %03d is the current control set (HKEY_LOCAL_MACHINE\SYSTEM\Select\Current)
      - HKEY_LOCAL_MACHINE\SYSTEM\ControlSet%03d\Control\Lsa\JD
      - HKEY_LOCAL_MACHINE\SYSTEM\ControlSet%03d\Control\Lsa\Skew1
      - HKEY_LOCAL_MACHINE\SYSTEM\ControlSet%03d\Control\Lsa\GBG
      - HKEY_LOCAL_MACHINE\SYSTEM\ControlSet%03d\Control\Lsa\Data
    - We also need HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\F for calculation things 
- Enumerate all user accounts stored in HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users (these are RIDs for each user)
  - Obtain the 'V' key for each user 
  - Use bootkey to decrypt password hashes 

## Payload
The payload itself will be a zipped folder, including four things:
  - Our bat file which will run our dotnet program and python parsing file
  - PsExec to execute in a SYSTEM context
  - Our dotnet executable
  - Our python file (compiled as a executable)
    - You can build python files as executables via pyinstaller.exe --onefile -w <filename.py>

## Indicators of Compromise (IOCs)
- rundll32.exe spawn with suspicious dll loaded in memory
- rundll32.exe running with SYSTEM privileges 

## References:
- https://github.com/fortra/impacket
  - Specifically, the secretsdump.py files 

## Wishlist
- Survey target for signs of Windows Defender; attempt to disable it 
