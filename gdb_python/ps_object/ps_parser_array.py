#!/usr/bin/env python3
"""
Parser for PostScript array objects
"""

import gdb
from ps_parser_base import parse_stack_object

def parse_array_raw(array_ptr, length, format_func):
    """Parse an array structure - array of stack objects
    
    Args:
        array_ptr: Pointer to the array in memory
        length: Number of elements in the array
        format_func: Function to format objects for display
    """
    try:
        inferior = gdb.selected_inferior()
        
        elements = []
        
        for i in range(min(length, 10)):
            elem_addr = array_ptr + (i * 16)
            elem = parse_stack_object(elem_addr)
            elem_str = format_func(elem)
            elements.append(elem_str)
        
        if length > 10:
            elements.append(f"... ({length - 10} more elements)")
        
        return elements
        
    except Exception as e:
        return [f"<error: {str(e)}>"]