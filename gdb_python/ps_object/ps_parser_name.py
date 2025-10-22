#!/usr/bin/env python3
"""
Parser for PostScript name objects
"""

import gdb
import struct
from ps_parser_string import read_string_value

def read_name_value(name_ptr):
    """Read a NAME object's string value from a pointer
    
    NAME structure (16 bytes for 64-bit):
    0x00: length (only low 4 bytes matter)
    0x08: pointer to string
    
    Args:
        name_ptr: Pointer to the NAME structure
    
    Returns:
        String representation of the name
    """
    try:
        inferior = gdb.selected_inferior()
        
        name_struct = inferior.read_memory(name_ptr, 16)
        
        first = struct.unpack('<Q', name_struct[0:8])[0]
        string_ptr = struct.unpack('<Q', name_struct[8:16])[0]
        
        # Only use low 4 bytes for length
        length = first & 0xFFFFFFFF
        
        if string_ptr and length > 0 and length < 0x1000:
            return read_string_value(string_ptr, length)
        else:
            return f"<invalid name @ {name_ptr:#x}>"
            
    except Exception as e:
        return f"<error reading name: {e}>"