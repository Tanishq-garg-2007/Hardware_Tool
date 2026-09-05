import struct
import datetime
from uimage_lookup_tables import os_map, arch_map, image_type_map, compression_map

def read_binary(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def find_squashfs(content):
    # Squashfs magic number for little endian
    squashfs_magic = b'hsqs'
    for offset in range(len(content) - len(squashfs_magic)):
        if content[offset:offset + len(squashfs_magic)] == squashfs_magic:
            return offset, hex(offset)
    return None, None

def interpret_squashfs_header(content, offset):
    # Squashfs header starts right after the magic number
    header_offset = offset + 4  # magic number is 4 bytes
    header_format = '<I4xI4xI4xI'  # Correctly extract size, inodes, blocksize, and creation_time
    size, inodes, blocksize, creation_time = struct.unpack_from(header_format, content, header_offset)
    creation_time = datetime.datetime.utcfromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
    return size, inodes, blocksize, creation_time

def find_zip(content):
    # ZIP file signature (local file header) is 0x50 0x4B 0x03 0x04
    zip_signature = b'PK\x03\x04'
    zip_end_signature = b'PK\x05\x06'
    start_offset = None
    end_offset = None
    
    for offset in range(len(content) - len(zip_signature)):
        if content[offset:offset + len(zip_signature)] == zip_signature:
            start_offset = offset
            break
    
    for offset in range(len(content) - len(zip_end_signature), 0, -1):
        if content[offset:offset + len(zip_end_signature)] == zip_end_signature:
            end_offset = offset + 22  # end of central directory record length
            break
    
    if start_offset is not None and end_offset is not None:
        return start_offset, end_offset - start_offset
    
    return None, None

def get_zip_details(content, offset):
    # Simple parser for local file headers within the ZIP archive
    zip_signature = b'PK\x03\x04'
    details = []
    
    while offset < len(content) - len(zip_signature):
        if content[offset:offset + len(zip_signature)] != zip_signature:
            break
        offset += 4
        (version, flags, compression, mod_time, mod_date,
         crc32, compressed_size, uncompressed_size, filename_len,
         extra_len) = struct.unpack_from('<HHHHHIIIHH', content, offset)
        offset += 26
        filename = content[offset:offset + filename_len].decode('utf-8')
        offset += filename_len + extra_len
        details.append((offset - 30, compressed_size, uncompressed_size, filename))
        offset += compressed_size
    
    return details

def find_uboot_version(content):
    uboot_magic = b'U-Boot'
    for offset in range(len(content) - len(uboot_magic)):
        if content[offset:offset + len(uboot_magic)] == uboot_magic:
            end = content.find(b'\x00', offset)  # Assuming null-terminated string
            version_str = content[offset:end].decode('ascii')
            return offset, hex(offset), version_str
    return None, None, None

def find_uimage_headers(content):
    uimage_magic = b'\x27\x05\x19\x56'  # uImage magic number
    headers = []

    for offset in range(len(content) - 64):  # uImage header is 64 bytes
        if content[offset:offset + 4] == uimage_magic:
            header = struct.unpack_from('>IIIIIIIBBBB32s', content, offset)
            header_crc = header[1]
            timestamp = datetime.datetime.utcfromtimestamp(header[2]).strftime('%Y-%m-%d %H:%M:%S')
            data_size = header[3]
            data_address = header[4]
            entry_point = header[5]
            data_crc = header[6]
            os_type = os_map.get(header[7], 'Unknown')
            arch = arch_map.get(header[8], 'Unknown')
            image_type = image_type_map.get(header[9], 'Unknown')
            compression = compression_map.get(header[10], 'Unknown')
            name = header[11].rstrip(b'\x00').decode("ascii", errors="replace")
            headers.append((offset, hex(offset), header_crc, timestamp, data_size, data_address, entry_point, data_crc, os_type, arch, image_type, compression, name))
    
    return headers

def find_lzma(content):
    lzma_entries = []
    lzma_signature = b'\x5D\x00\x00\x80\x00'  # Typical LZMA properties header

    for offset in range(len(content) - len(lzma_signature)):
        if content[offset:offset + len(lzma_signature)] == lzma_signature:
            properties = content[offset]
            dict_size = struct.unpack_from('<I', content, offset + 1)[0]
            uncompressed_size = struct.unpack_from('<Q', content, offset + 5)[0]
            lzma_entries.append((offset, hex(offset), properties, dict_size, uncompressed_size))
    
    return lzma_entries

