#!/usr/bin/env python3
"""
GDB script to calculate format string positional parameter index for syslog.
Usage: source this script in GDB, then run: 
  - calc_printf_index(0xaddress) to get index
  - calc_printf_index(5) to get stack address for index 5
"""

import gdb
import sys

def calc_printf_index(target):
    """
    Calculate the format string positional parameter index for a given stack address,
    or calculate the stack address for a given index.
    
    Args:
        target: Either a stack address (hex string or int) or an index (small int)
    
    Returns:
        Either the format string index or the stack address
    """
    
    # Determine if input is an index or an address
    if isinstance(target, str):
        # Check if it's a hex address or just a number
        if target.startswith('0x') or any(c in target.lower() for c in 'abcdef'):
            is_address = True
            target_value = int(target, 16)
        else:
            # It's a decimal number - check if it looks like an index
            target_value = int(target)
            # Indices are typically < 1000, addresses are typically huge
            is_address = target_value > 0xffff  # If bigger than 64k, probably an address
    else:
        target_value = int(target)
        is_address = target_value > 0xffff
    
    try:
        # Get current stack pointer
        sp = int(gdb.parse_and_eval("$sp"))
        
        # The va_list structure points to sp+0xd0 as the first vararg location
        first_vararg_addr = sp + 0xd0
        
        if is_address:
            # Address to index conversion
            offset_from_first = target_value - first_vararg_addr
            
            if offset_from_first < 0:
                print(f"Error: Target address before first vararg")
                return None
            
            if offset_from_first % 8 != 0:
                # Round down to nearest 8-byte boundary
                offset_from_first = (offset_from_first // 8) * 8
            
            # Calculate the index (1-based for format strings)
            index = (offset_from_first // 8) + 1
            
            print(index)
            return index
        else:
            # Index to address conversion
            index = target_value
            if index < 1:
                print(f"Error: Index must be >= 1")
                return None
            
            # Calculate the stack address for this index
            offset = (index - 1) * 8
            stack_addr = first_vararg_addr + offset
            
            print(f"0x{stack_addr:x}")
            return stack_addr
        
    except Exception as e:
        print(f"Error: {e}")
        return None

def find_stack_index(target_addr_str):
    """Wrapper function that can be called from GDB command line"""
    return calc_printf_index(target_addr_str)

# Register as a GDB command
class PrintfIndexCommand(gdb.Command):
    """Calculate format string index for a stack address in syslog"""
    
    def __init__(self):
        super(PrintfIndexCommand, self).__init__("printf-index", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        args = arg.strip()
        if not args:
            print("Usage: printf-index <stack_address | index>")
            return
        
        calc_printf_index(args)

# Register the command
PrintfIndexCommand()

print("Printf index calculator loaded: printf-index <address>")