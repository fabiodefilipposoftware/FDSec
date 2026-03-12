# FDSec
## A sort of Antivirus🦠 for Windows

[![License](https://img.shields.io/badge/license-GPv3-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-windows-green.svg)

I am trying to create an Antivirus too.

## ⚠️WARNING⚠️:

Read and check the code before compiling and running it in production (Virtual Machine)!
## How to use it:

1. Create a new project in Visual Studio;
2. Paste the code inside Program.cs;
3. <strong>READ</strong> and <strong>CHECK</strong> the code;
4. Compile it and execute the binary!
5. (optional) download and unzip [radare2](https://github.com/radareorg/radare2) in FDSec folder (copy the 'bin', 'include', 'lib' and 'share' folders as showed below);

|<strong>FDSec folder</strong>|
|:----------:|
|bin\ |
|include\ |
|lib\ |
|share\ |
|fdsec.exe |


I suggest Framework 4.7 or higher!

1. Scan processes in loop:
```
C:\fdsec_folder> .\fdsec.exe
```

2. Scan a file then exit:
```
C:\fdsec_folder> .\fdsec.exe suspicious-file.exe
```

3. Scan recursively a folder then exit:
```
C:\fdsec_folder> .\fdsec.exe .\folder\
```


## Features
- scan processes in loop;
- Arbitrary scan single file;
- recursive scan folder;
- scan remote ip connections in loop;
- automatic exclusion from legittimate software (by whitelist hashes);
- (optional) radare2 scanner for dangerous functions;

## Technologies
- blacklist and whitelist of sha256 hashes;
- signatures;
- blacklist of malicious ip;
- dangerous functions;
