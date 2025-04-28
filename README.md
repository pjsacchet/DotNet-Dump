# DotNet-Dump
## Description
Dump password hashes and other useful info via .NET

## Design
This piece of rudimentary malware will be packaged with PsExec (from sysinternals) along with a batch script that will run the program. The CONOP is as follows:
- User downloads packaged/zipped files onto target computer
- Upon unzipping, our batch file will execute, loading our dll via rundll32 and executing that process as SYSTEM via PsExec

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
  - Can be found under HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\F
- Enumerate all user accounts stored in HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users (these are RIDs for each user)
  - Obtain the 'V' key for each user 
  - Use bootkey to decrypt password hashes 

## Indicators of Compromise (IOCs)
- rundll32.exe spawn with suspicious dll loaded in memory
- rundll32.exe running with SYSTEM privileges 

## References:
- https://github.com/fortra/impacket
  - Specifically, the secretsdump.py files 

## Wishlist
- Survey target for signs of Windows Defender; attempt to disable it 
