#!/usr/bin/env python
"""
py_break.py - GDB plugin for setting breakpoints using module name matching
Supports both loaded modules and pending breakpoints for unloaded libraries
Usage: bpy <module_name>+<offset>
Example: bpy plugin_server+0x100, bpy libc+0x12345
"""

import gdb
import re

class PendingBreakpoint:
    """Tracks pending breakpoints for unloaded modules"""
    def __init__(self, module_name, offset, search_name):
        self.module_name = module_name
        self.offset = offset
        self.search_name = search_name
        self.breakpoint = None
        self.resolved = False

class ModuleLoadHandler:
    """Handles module load events to resolve pending breakpoints"""
    def __init__(self, py_break_cmd):
        self.py_break_cmd = py_break_cmd
        self.enabled = False
        
    def enable(self):
        """Enable monitoring for module loads"""
        if not self.enabled:
            try:
                # Set a catchpoint for shared library events
                gdb.execute("catch load", to_string=True)
                self.enabled = True
            except:
                pass
    
    def check_pending(self):
        """Check if any pending breakpoints can now be resolved"""
        if not self.py_break_cmd.pending_breakpoints:
            return
        
        mappings = self.py_break_cmd.get_memory_mappings()
        resolved = []
        
        for pending in self.py_break_cmd.pending_breakpoints:
            if pending.resolved:
                continue
                
            # Check if the module is now loaded
            for mapping in mappings:
                if not mapping['file']:
                    continue
                    
                filename = mapping['file'].split('/')[-1].lower()
                if pending.search_name in filename:
                    # Find base address
                    module_path = mapping['file']
                    base_addr = None
                    
                    for m in mappings:
                        if m['file'] == module_path:
                            if base_addr is None or m['start'] < base_addr:
                                base_addr = m['start']
                    
                    if base_addr:
                        bp_addr = base_addr + pending.offset
                        try:
                            bp = gdb.Breakpoint(f"*0x{bp_addr:x}")
                            module_name = module_path.split('/')[-1]
                            print(f"Resolved pending breakpoint: 0x{bp_addr:016x} ({module_name}+0x{pending.offset:x})")
                            pending.breakpoint = bp
                            pending.resolved = True
                            resolved.append(pending)
                        except Exception as e:
                            print(f"Error setting resolved breakpoint: {e}")
                    break
        
        # Remove resolved breakpoints from pending list
        for r in resolved:
            self.py_break_cmd.pending_breakpoints.remove(r)

class PyBreak(gdb.Command):
    """Set breakpoints using module name matching
    
    Usage: bpy <module_name>+<offset>
    
    Examples:
        bpy plugin_server+0x100
        bpy libc+0x12345
        bpy ld-linux+0x5000
    
    If the module is not loaded, creates a pending breakpoint that will
    be set when the module is loaded.
    """
    
    def __init__(self):
        super(PyBreak, self).__init__("bpy", gdb.COMMAND_BREAKPOINTS)
        self.pending_breakpoints = []
        self.module_handler = ModuleLoadHandler(self)
        
        # Register event handlers
        gdb.events.stop.connect(self.on_stop)
        gdb.events.new_objfile.connect(self.on_new_objfile)
    
    def on_stop(self, event):
        """Called when execution stops"""
        self.module_handler.check_pending()
    
    def on_new_objfile(self, event):
        """Called when a new object file is loaded"""
        self.module_handler.check_pending()
    
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
                # Module not found - create pending breakpoint
                print(f"Module '{search_name}' not currently loaded")
                
                # Check for common library patterns
                common_libs = {
                    'libc': ['libc.so', 'libc-2.', 'libc.so.6'],
                    'libstdc++': ['libstdc++.so', 'libstdc++.so.6'],
                    'libpthread': ['libpthread.so', 'libpthread-2.'],
                    'libm': ['libm.so', 'libm-2.', 'libm.so.6'],
                    'ld': ['ld-linux', 'ld-2.', 'ld.so'],
                }
                
                suggestions = []
                for lib, patterns in common_libs.items():
                    for pattern in patterns:
                        if search_name in pattern.lower() or pattern.lower() in search_name:
                            suggestions.append(lib)
                            break
                
                if suggestions:
                    print(f"This might be a system library (similar to: {', '.join(set(suggestions))})")
                
                # Create pending breakpoint
                pending = PendingBreakpoint(search_name, offset, search_name)
                self.pending_breakpoints.append(pending)
                print(f"Created pending breakpoint for '{search_name}+0x{offset:x}'")
                print("It will be set automatically when the module is loaded")
                
                # Enable module load monitoring
                self.module_handler.enable()
                
                # Show currently loaded modules for reference
                print("\nCurrently loaded modules:")
                unique_modules = set()
                for m in mappings:
                    if m['file'] and not m['file'].startswith('['):
                        unique_modules.add(m['file'].split('/')[-1])
                for mod in sorted(unique_modules):
                    print(f"  {mod}")
                
                # Show pending breakpoints
                if len(self.pending_breakpoints) > 1:
                    print(f"\nPending breakpoints ({len(self.pending_breakpoints)} total):")
                    for p in self.pending_breakpoints:
                        status = "resolved" if p.resolved else "pending"
                        print(f"  {p.module_name}+0x{p.offset:x} [{status}]")
                
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
    
    def show_pending(self):
        """Show all pending breakpoints"""
        if not self.pending_breakpoints:
            print("No pending breakpoints")
        else:
            print(f"Pending breakpoints ({len(self.pending_breakpoints)} total):")
            for p in self.pending_breakpoints:
                status = "resolved" if p.resolved else "pending"
                print(f"  {p.module_name}+0x{p.offset:x} [{status}]")

class ShowPendingBreakpoints(gdb.Command):
    """Show pending module breakpoints"""
    
    def __init__(self, py_break_cmd):
        super(ShowPendingBreakpoints, self).__init__("bpy-pending", gdb.COMMAND_BREAKPOINTS)
        self.py_break_cmd = py_break_cmd
    
    def invoke(self, arg, from_tty):
        self.py_break_cmd.show_pending()

# Register the commands
py_break = PyBreak()
ShowPendingBreakpoints(py_break)

print("py_break.py loaded - use 'bpy <module>+<offset>' to set breakpoints")
print("Example: bpy plugin_server+0x100, bpy libc+0x12345")
print("Use 'bpy-pending' to show pending breakpoints")
print("Pending breakpoints will be set automatically when modules are loaded")