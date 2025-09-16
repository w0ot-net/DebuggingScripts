#!/usr/bin/env python
"""
py_break.py - GDB plugin for setting breakpoints using module name matching
Usage: bpy <module_name>+<offset>
Example: bpy plugin_server+0x100
"""

import gdb
import re

class PyBreak(gdb.Command):
    """Set breakpoints using module name matching
    
    Usage: bpy <module_name>+<offset>
    
    Examples:
        bpy plugin_server+0x100
        bpy libc+0x12345
        bpy ld-linux+0x5000
    """
    
    def __init__(self):
        super(PyBreak, self).__init__("bpy", gdb.COMMAND_BREAKPOINTS)
    
    def invoke(self, arg, from_tty):
        try:
            # Parse the argument
            if '+' not in arg:
                print("Error: Invalid format. Use: bpy <module_name>+<offset>")
                print("Example: bpy plugin_server+0x100")
                return
            
            parts = arg.strip().split('+')
            if len(parts) != 2:
                print("Error: Invalid format. Use: bpy <module_name>+<offset>")
                return
            
            search_name = parts[0].strip().lower()
            offset_str = parts[1].strip()
            
            # Parse offset (support both 0x and decimal)
            try:
                if offset_str.startswith('0x') or offset_str.startswith('0X'):
                    offset = int(offset_str, 16)
                else:
                    offset = int(offset_str, 10)
            except ValueError:
                print(f"Error: Invalid offset '{offset_str}'")
                return
            
            # Get memory mappings
            mappings = self.get_memory_mappings()
            if not mappings:
                print("Error: Could not retrieve memory mappings")
                return
            
            # Find matching modules (case insensitive substring match)
            matches = []
            for mapping in mappings:
                if not mapping['file']:
                    continue
                
                # Skip special sections like [heap], [stack], etc
                if mapping['file'].startswith('[') and mapping['file'].endswith(']'):
                    continue
                
                # Get just the filename for matching
                filename = mapping['file'].split('/')[-1].lower()
                
                # Case insensitive substring match
                if search_name in filename:
                    # Store the match with its length (for longest match wins)
                    match_exists = False
                    for i, (m, _) in enumerate(matches):
                        if m['file'] == mapping['file']:
                            match_exists = True
                            break
                    
                    if not match_exists:
                        matches.append((mapping, len(search_name)))
            
            if len(matches) == 0:
                print(f"Error: No module found containing '{search_name}'")
                print("Available modules:")
                unique_modules = set()
                for m in mappings:
                    if m['file'] and not m['file'].startswith('['):
                        unique_modules.add(m['file'].split('/')[-1])
                for mod in sorted(unique_modules):
                    print(f"  {mod}")
                return
            
            # Find the longest match(es)
            max_len = max(match[1] for match in matches)
            longest_matches = [m for m in matches if m[1] == max_len]
            
            # Check for ties
            if len(longest_matches) > 1:
                print(f"Error: Multiple modules match '{search_name}' with same length:")
                for match, _ in longest_matches:
                    print(f"  {match['file']}")
                print("Please be more specific")
                return
            
            # Get the winning match
            best_match = longest_matches[0][0]
            
            # Find the base address (first mapping for this module)
            module_path = best_match['file']
            base_addr = None
            
            for m in mappings:
                if m['file'] == module_path:
                    if base_addr is None or m['start'] < base_addr:
                        base_addr = m['start']
            
            if base_addr is None:
                print(f"Error: Could not find base address for module '{module_path}'")
                return
            
            # Calculate the breakpoint address
            bp_addr = base_addr + offset
            
            # Set the breakpoint
            try:
                bp = gdb.Breakpoint(f"*0x{bp_addr:x}")
                module_name = module_path.split('/')[-1]
                print(f"Breakpoint set at 0x{bp_addr:016x} ({module_name}+0x{offset:x})")
                print(f"  Base address: 0x{base_addr:016x}")
            except Exception as e:
                print(f"Error setting breakpoint: {e}")
                
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
    
    def get_memory_mappings(self):
        """Parse 'info proc mappings' output to get memory map"""
        mappings = []
        
        try:
            output = gdb.execute("info proc mappings", to_string=True)
            lines = output.strip().split('\n')
            
            # Skip header lines
            in_data = False
            for line in lines:
                if 'Start Addr' in line and 'End Addr' in line:
                    in_data = True
                    continue
                
                if not in_data:
                    continue
                
                # Parse mapping lines
                parts = line.split()
                if len(parts) < 5:
                    continue
                
                try:
                    start = int(parts[0], 16)
                    end = int(parts[1], 16)
                    size = parts[2]
                    offset = parts[3]
                    perms = parts[4]
                    
                    # File path might be missing or have spaces
                    file_path = ' '.join(parts[5:]) if len(parts) > 5 else None
                    
                    mappings.append({
                        'start': start,
                        'end': end,
                        'size': size,
                        'offset': offset,
                        'perms': perms,
                        'file': file_path
                    })
                except (ValueError, IndexError):
                    continue
                    
        except Exception as e:
            return []
        
        return mappings

# Register the command
PyBreak()
print("py_break.py loaded - use 'bpy <module>+<offset>' to set breakpoints")
print("Example: bpy plugin_server+0x100")