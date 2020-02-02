
# VirtualBox Hardened Loader
## VirtualBox Hardened VM detection mitigation loader

# System Requirements

x64 Windows 7/8/8.1/10;

VirtualBox 6.1.2 and later versions.

For version below VirtualBox 6.1 please use older release of this loader.

+ For versions 6.0.x use loader version 1.10.0
(https://github.com/hfiref0x/VBoxHardenedLoader/releases/tag/v1.10.0)

+ For versions 5.2.x use loader version 1.9.0 
(https://github.com/hfiref0x/VBoxHardenedLoader/releases/tag/v1.9.0)

+ For versions 5.1.x use loader version 1.8.0 or 1.8.2
(https://github.com/hfiref0x/VBoxHardenedLoader/releases/tag/v1.8.2)

+ For versions 5.0.0, 5.0.2, 5.0.8, 5.0.10, 5.0.12 use loader version 1.7.1
(https://github.com/hfiref0x/VBoxHardenedLoader/releases/tag/v1.7.1)

Loader designed only for x64 Windows.

Administrative privilege is required.

# Warning
Binary files (ACPI tables, BIOS roms), batch scripts from loader version 1.9+ are NOT compatible with VirtualBox 5.1 and below.

# Installation and use guide

TBD


# Build 

Project comes with full source code.
In order to build from source you need:
1) Microsoft Visual Studio 2019 for loader build.
2) Windows Driver Kit 8.1/10 and later versions for driver build.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General): 
  * v120 for Visual Studio 2013;
  * v140 for Visual Studio 2015; 
  * v141 for Visual Studio 2017;
  * v142 for Visual Studio 2019.
* For v140 and above set Target Platform Version (Project->Properties->General):
  * If v140 then select 8.1;
  * If v141/v142 then select 10. 


# Project Contents

**Tsugumi - monitoring driver, x64** 

Purpose: patch VirtualBox dlls in runtime.

**Zekamashi - application, x64**

Purpose: load Tsugumi monitoring driver, stop monitoring. Type loader /? in command line to view built-in help about supported commands and their syntax.

Since 1.8 version loader has integrated patch generator and it will attempt to generate patch table for currently installed VirtualBox version.


# Linux support

https://github.com/hfiref0x/VBoxHardenedLoader/blob/master/Binary/linux.md


# Support and donations

VBoxHardenedLoader is Free Software and is made available free of charge.
Your donation, which is purely optional, supports project development and maintaining.
If you like the software, you can consider donation which you can do anonymously using the following BTC address

* 3DU68VrwZYHVSYXenQMG123utkYrFGms3b

# Authors

(c) 2014 - 2020 VBoxHardenedLoader Project
