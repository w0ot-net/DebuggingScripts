#!/usr/bin/env python3
"""
Base parser for PostScript stack objects
"""

import gdb
import struct
from ps_types import get_ps_type_name, get_permissions

def parse_stack_object(addr, debug=False):
    """Parse a single stack object (16 bytes for 64-bit)
    
    Structure:
    First qword: only low 4 bytes matter
      Byte 0: type
      Byte 1: perms  
      Bytes 2-3: length
      Bytes 4-7: IGNORED (high 4 bytes)
    Second qword: value/pointer
    """
    try:
        inferior = gdb.selected_inferior()
        obj_data = inferior.read_memory(addr, 16)
        
        first_qword = struct.unpack('<Q', obj_data[0:8])[0]
        second_qword = struct.unpack('<Q', obj_data[8:16])[0]
        
        # Only use low 4 bytes of first qword
        low_dword = first_qword & 0xFFFFFFFF
        
        # Extract fields from low dword
        type_byte = low_dword & 0xFF                    # Byte 0
        perms = (low_dword >> 8) & 0xFF                 # Byte 1
        length = (low_dword >> 16) & 0xFFFF             # Bytes 2-3
        
        type_name = get_ps_type_name(type_byte)
        perms_str = get_permissions(perms)
        
        if debug:
            print(f"  DEBUG @ {addr:#x}: raw={first_qword:#018x} {second_qword:#018x}")
            print(f"    type={type_name}({type_byte:#x}) perms={perms_str}({perms:#x}) len={length}")
        
        result = {
            'type': type_name,
            'type_byte': type_byte,
            'perms': perms_str,
            'perms_raw': perms,
            'length': length,
            'value': second_qword,
            'raw_first': first_qword,
            'address': addr  # Store the object's own address
        }
        
        return result
        
    except Exception as e:
        return {'error': str(e)}