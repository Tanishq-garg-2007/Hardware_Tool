#!/usr/bin/env python3

import os
import sys
import subprocess
from squashfs_utils import read_binary, find_squashfs, interpret_squashfs_header, find_zip, get_zip_details, find_uboot_version, find_uimage_headers

class FirmwarePart:
    def __init__(self, name, offset, size):
        self.name = name
        self.offset = offset
        self.size = size

def create_output_dir(firmware_file):
    base_name = os.path.basename(firmware_file)
    output_dir = os.path.splitext(base_name)[0] + '_extracted'
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def run_unsquashfs(part_name, output_dir):
    result = subprocess.run(['unsquashfs', '-d', os.path.join(output_dir, 'squashfs_out'), part_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        print(f"Successfully unpacked Squashfs filesystem to '{os.path.join(output_dir, 'squashfs_out')}'")
    else:
        print(f"Failed to unpack Squashfs filesystem: {result.stderr.decode()}")

def run_unzip(part_name, output_dir):
    result = subprocess.run(['unzip', '-d', os.path.join(output_dir, 'zip_out'), part_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"Unzip stdout: {result.stdout.decode()}")
    print(f"Unzip stderr: {result.stderr.decode()}")
    if result.returncode == 0:
        print(f"Successfully unpacked ZIP archive to '{os.path.join(output_dir, 'zip_out')}'")
    else:
        print(f"Failed to unpack ZIP archive: {result.stderr.decode()}")

if len(sys.argv) < 3:
    print("Usage: script.py <unpack|pack|info> <firmware file>")
    sys.exit(1)

action = sys.argv[1]
firmware_file = sys.argv[2]

# Read the binary content of the firmware file
content = read_binary(firmware_file)
firmware_size = len(content)

# Initialize firmware parts list
firmware_parts = []

# Find Squashfs filesystem
squashfs_offset, squashfs_hex = find_squashfs(content)
if squashfs_offset is not None:
    # Interpret the header
    size, inodes, blocksize, creation_time = interpret_squashfs_header(content, squashfs_offset)
    
    # Calculate the size of the Squashfs partition
    squashfs_size = firmware_size - squashfs_offset
    
    # Create a firmware part for the Squashfs filesystem
    firmware_parts.append(FirmwarePart("squashfs", squashfs_offset, squashfs_size))

# Find ZIP archive
zip_offset, zip_size = find_zip(content)
if zip_offset is not None:
    # Create a firmware part for the ZIP archive
    firmware_parts.append(FirmwarePart("archive.zip", zip_offset, zip_size))

# Find U-Boot version
uboot_offset, uboot_hex, uboot_version = find_uboot_version(content)
if uboot_offset is not None:
    uboot_info = (uboot_offset, uboot_hex, f"U-Boot version string, \"{uboot_version}\"")
else:
    uboot_info = None

# Find uImage headers
uimage_headers = find_uimage_headers(content)

if action == "-u":
    # Create output directory
    output_dir = create_output_dir(firmware_file)
    
    with open(firmware_file, "rb") as f:
        for part in firmware_parts:
            part_path = os.path.join(output_dir, part.name)
            with open(part_path, "wb") as outfile:
                f.seek(part.offset, 0)
                data = f.read(part.size)
                outfile.write(data)
                print(f"Wrote {part.name} - {hex(len(data))} bytes")
                
            if part.name == "squashfs":
                # Run unsquashfs command to unpack the Squashfs filesystem
                run_unsquashfs(part_path, output_dir)
            elif part.name == "archive.zip":
                # Run unzip command to unpack the ZIP archive
                run_unzip(part_path, output_dir)
    
elif action == "pack":
    with open(firmware_file, "wb") as f:
        for part in firmware_parts:
            with open(part.name, "rb") as infile:
                data = infile.read()
                f.write(data)
                padding = (part.size - len(data))
                print(f"Wrote {part.name} - {hex(len(data))} bytes")
                print(f"Padding: {hex(padding)}")
                f.write(b'\x00' * padding)

elif action == "-i":
    print(f"{'DECIMAL':<12} {'HEXADECIMAL':<12} {'DESCRIPTION'}")
    print(f"{'-'*12} {'-'*12} {'-'*80}")
    
    info_entries = []

    if squashfs_offset is not None:
        info_entries.append((squashfs_offset, squashfs_hex, f"Squashfs filesystem, {size} inodes, blocksize: {inodes} bytes, little endian,\n{'':<12} {'':<12} "))
        
    if uboot_offset is not None:
        info_entries.append((uboot_offset, uboot_hex, uboot_info[2]))
        
    if zip_offset is not None:
        zip_details = get_zip_details(content, zip_offset)
        for offset, compressed_size, uncompressed_size, filename in zip_details:
            info_entries.append((offset, hex(offset), f"Zip archive data,\n{'':<12} {'':<12} compressed size: {compressed_size}, uncompressed size: {uncompressed_size}, name: {filename}"))

    for header in uimage_headers:
        info_entries.append((header[0], header[1], f"uImage header, header size: 64 bytes, header CRC: {hex(header[2])},\n{'':<12} {'':<12} created: {header[3]}, image size: {header[4]} bytes, Data Address: {hex(header[5])}, Entry Point: {hex(header[6])}, data CRC: {hex(header[7])},\n{'':<12} {'':<12} OS: {header[8]}, CPU: {header[9]}, image type: {header[10]}, compression type: {header[11]}, image name: \"{header[12]}\""))

    # Sort info_entries by the offset (first element of the tuple)
    info_entries.sort()

    for entry in info_entries:
        print(f"{entry[0]:<12} {entry[1]:<12} {entry[2]}")

else:
    print("Invalid action. Use 'unpack', 'pack', or 'info'.")
    sys.exit(1)

