#!/usr/bin/env python3
"""
PostScript type definitions and helper functions
"""

# PostScript object type constants
PS_TYPE_NAMES = {
    0x00: "INTEGER",
    0x01: "FLOAT", 
    0x02: "BOOLEAN",
    0x05: "NAME",
    0x07: "OPERATOR",
    0x09: "MARK",
    0x0a: "NULL",
    0x23: "ARRAY",      # 35 decimal
    0x24: "STRING",     # 36 decimal
    0x26: "DICTIONARY", # 38 decimal
    0x28: "FILTER",     # 40 decimal
    0x2D: "PACKEDARRAY", # 45 decimal
}

def get_ps_type_name(type_val):
    """Get the name of a PostScript type from its byte value"""
    if not isinstance(type_val, int):
        type_val = ord(type_val)
    base_type = type_val & 0x3F
    return PS_TYPE_NAMES.get(base_type, f"UNKNOWN({base_type:#x})")

def get_permissions(perms_byte):
    """Convert permission byte to human-readable string"""
    if not isinstance(perms_byte, int):
        perms_byte = ord(perms_byte)
    perms = []
    if perms_byte & 0x01:
        perms.append("EXEC")
    if perms_byte & 0x02:
        perms.append("WRITE") 
    if perms_byte & 0x04:
        perms.append("READ")
    return "|".join(perms) if perms else "NONE"