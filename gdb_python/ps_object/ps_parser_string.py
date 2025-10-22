#!/usr/bin/env python3
"""
Parser for PostScript string objects
"""

import gdb

def read_string_value(addr, length):
    """Read a string value from memory
    
    Args:
        addr: Address of the string in memory
        length: Length of the string
    
    Returns:
        String representation of the data
    """
    try:
        inferior = gdb.selected_inferior()
        if length > 1024:
            return f"<string too long: {length} bytes>"
        if length == 0:
            return ""
        
        data = inferior.read_memory(addr, min(length, 64))
        
        result = ""
        for i in range(min(length, 64)):
            b = data[i] if isinstance(data[i], int) else ord(data[i])
            if 32 <= b <= 126:
                result += chr(b)
            else:
                result += f"\\x{b:02x}"
                
        if length > 64:
            result += "..."
            
        return result
    except Exception as e:
        return f"<error reading string: {str(e)}>"