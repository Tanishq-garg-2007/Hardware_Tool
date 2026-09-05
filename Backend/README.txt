Firmware Extraction Tool
========================

This tool allows you to extract and analyze information from firmware binary files. It supports the extraction of SquashFS filesystems, ZIP archives, U-Boot version strings, and uImage headers. Additionally 5 new vulnerabilities has been added.



New Features Added

1. Extract SquashFS File System: Extract SquashFS file systems from firmware binaries.

2. Extract ZIP Archives: Extract ZIP archived data embedded in firmware binaries.

3. Show U-Boot Version: Display U-Boot version strings with creation date.

4. Show uImage Header Info: Display uImage header information, including OS, CPU Architecture, Image Type, Compression Type, and creation  date.

5. Identify File Signatures: Signature-based identification of file types.

6. Identify Third-Party Libraries: Identify third-party libraries used by ELF files which might have known vulnerabilities.

7. Examine Symbol Table: Identify dangerous functions and deprecated APIs in ELF files.
 
8. Search Hardcoded SSH Keys: Search for embedded private SSH keys that could grant unauthorized access.

9. Identify Web Command Injection Vulnerabilities: Analyze web interfaces for command injection vulnerabilities.

10.Identifies potential command injection vulnerabilities in web interface files.

11.Searches for outdated or weak cryptographic algorithms implemented within the firmware files.

12.Checks for weak or predictable encryption keys within the firmware files.

13.Scans for default or easily guessable credentials in configuration and script files.

14.Performs entropy analysis on the provided firmware file to identify sections with high or low entropy, indicating potential compressed or encrypted data.





Requirements
 
1. Python3 and above

2. unsquashfs utility 
    
    	sudo apt-get install squashfs-tools
    
3. unzip utility(if not there)

	sudo apt-get install unzip

4. pyelftools Python package:

	sudo pip3 install pyelftools
	
5.  for generating the interactive plot for entropy analysis 

	sudo pip install plotly

	
How to Run

do chmod 777 *
	
1. To Show Information

	python3 FirmAudit.py {path/firmware.bin file} -info
	
	
	Identified Information
	
	OS:
	OpenBSD, NetBSD, FreeBSD, 4.4BSD, Linux, SVR4, Esix, Solaris, Irix, 
	SCO, Dell, NCR, LynxOS, VxWorks, pSOS, QNX, U-Boot, RTEMS, ARTOS, Unity, 
	INTEGRITY, OSELAS

	Architecture:
	Alpha, ARM, Intel x86, IA64, MIPS, Nios, PowerPC, IBM S390, SuperH, SPARC, 
	M68K, Nios II, Blackfin, AVR32, STMicroelectronics

	Image Type:
	Standalone Program, OS Kernel Image, OS Kernel, Root Filesystem Image, Ramdisk Image, 
	Multi-File Image, Firmware Image, Script File, File System Image, RAMDisk Image

	Compression Type:
	none, gzip, bzip2, lzma

	
2. To Extract and Analyze

	python3 FirmAudit.py {path/firmware.bin file}
		
The extracted files can be found in the {firmware_name}_extracted directory.

The analysis report can be found in the {firmware_name}_testout.txt file.


3. To See Entropy Analysis

	python3 FirmAudit.py {path/firmware.bin file} -E
	
	
	for variable Block size 

	python3 FirmAudit.py {path/firmware.bin file} -B  {Block_size}


The entropy.txt files can be found in the {firmware_name}_entropy directory.

The entropy graphical analysis report can be found in the {firmware_name}_entropy.html file.

	
   


