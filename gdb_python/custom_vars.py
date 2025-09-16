#!/usr/bin/env python
"""
custom_vars.py - Optimized GDB plugin for module base address variables
Creates $module_name variables for each loaded module
"""

import gdb
import re

class ModuleVariables:
    """Manager for module base address variables"""
    
    def __init__(self):
        self.module_vars = {}
        self.update_module_variables()
    
    def sanitize_var_name(self, name):
        """Convert module name to valid GDB variable name"""
        name = name.split('/')[-1]
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        if name and name[0].isdigit():
            name = '_' + name
        name = re.sub(r'_+', '_', name).rstrip('_')
        return name if name else 'unnamed'
    
    def get_memory_mappings(self):
        """Parse memory mappings efficiently"""
        module_bases = {}
        
        try:
            # Get all mappings at once
            output = gdb.execute("info proc mappings", to_string=True)
            
            # Process line by line
            for line in output.split('\n'):
                if '0x' not in line:
                    continue
                    
                parts = line.split(None, 5)
                if len(parts) < 6:
                    continue
                
                try:
                    start = int(parts[0], 16)
                    file_path = parts[5]
                    
                    # Skip special sections
                    if file_path[0] == '[':
                        continue
                    
                    # Track only the minimum address per module
                    if file_path not in module_bases or start < module_bases[file_path]:
                        module_bases[file_path] = start
                        
                except (ValueError, IndexError):
                    continue
                    
        except Exception:
            return {}
        
        return module_bases
    
    def update_module_variables(self):
        """Create/update GDB convenience variables for each module - OPTIMIZED"""
        module_bases = self.get_memory_mappings()
        if not module_bases:
            return
        
        # Clear old tracking
        self.module_vars.clear()
        var_names = set()
        
        # Use GDB's convenience variable API directly for speed
        for module_path, base_addr in module_bases.items():
            var_name = self.sanitize_var_name(module_path)
            
            # Handle duplicates
            original_name = var_name
            counter = 2
            while var_name in var_names:
                var_name = f"{original_name}_{counter}"
                counter += 1
            
            var_names.add(var_name)
            
            # Set convenience variable using GDB's Python API
            # This is MUCH faster than using gdb.execute()
            try:
                gdb.set_convenience_variable(var_name, base_addr)
                
                # Track for listing
                self.module_vars[var_name] = {
                    'address': base_addr,
                    'path': module_path,
                    'module': module_path.split('/')[-1]
                }
            except Exception as e:
                print(f"Warning: Could not create variable ${var_name}: {e}")
        
        if self.module_vars:
            print(f"Created {len(self.module_vars)} module variables (use 'ls_vars' to list)")
    
    def list_variables(self, pattern=None):
        """List module variables, optionally filtered by pattern"""
        if not self.module_vars:
            print("No module variables created yet")
            return
        
        # Filter efficiently
        if pattern:
            pattern_lower = pattern.lower()
            vars_to_show = {
                k: v for k, v in self.module_vars.items()
                if pattern_lower in k.lower() or pattern_lower in v['module'].lower()
            }
            
            if not vars_to_show:
                print(f"No variables matching '{pattern}'")
                return
        else:
            vars_to_show = self.module_vars
        
        # Display variables
        print(f"Module variables ({len(vars_to_show)} total):")
        print("-" * 70)
        
        for var_name in sorted(vars_to_show.keys()):
            info = vars_to_show[var_name]
            print(f"${var_name:<30} = 0x{info['address']:016x}  # {info['module']}")
        
        if pattern:
            print(f"\nFiltered by: '{pattern}'")
        
        print("\nExample usage:")
        if vars_to_show:
            first_var = sorted(vars_to_show.keys())[0]
            print(f"  x/10i ${first_var}+0x1000")
            print(f"  b *${first_var}+0x1234")

# Global instance
module_vars_manager = None

class ListVarsCommand(gdb.Command):
    """List module convenience variables"""
    
    def __init__(self):
        super(ListVarsCommand, self).__init__("ls_vars", gdb.COMMAND_DATA)
    
    def invoke(self, arg, from_tty):
        global module_vars_manager
        if not module_vars_manager:
            module_vars_manager = ModuleVariables()
        
        pattern = arg.strip() if arg else None
        module_vars_manager.list_variables(pattern)
    
    def complete(self, text, word):
        """Tab completion for variable patterns"""
        global module_vars_manager
        if not module_vars_manager:
            return []
        
        return [k for k in module_vars_manager.module_vars.keys() 
                if not word or k.startswith(word)]

class UpdateVarsCommand(gdb.Command):
    """Update module convenience variables"""
    
    def __init__(self):
        super(UpdateVarsCommand, self).__init__("update_vars", gdb.COMMAND_DATA)
    
    def invoke(self, arg, from_tty):
        global module_vars_manager
        if not module_vars_manager:
            module_vars_manager = ModuleVariables()
        else:
            module_vars_manager.update_module_variables()
        print("Module variables updated")

# Hook into events to auto-update on certain GDB events  
def on_new_objfile(event):
    """Update variables when new object files are loaded"""
    global module_vars_manager
    if module_vars_manager:
        module_vars_manager.update_module_variables()

# Register event handlers
try:
    gdb.events.new_objfile.connect(on_new_objfile)
except:
    pass

# Register commands
ListVarsCommand()
UpdateVarsCommand()

# Initialize on load - THIS CREATES THE VARIABLES AUTOMATICALLY
module_vars_manager = ModuleVariables()

print("custom_vars.py loaded")
print("  - Module variables created (e.g., $libc_so_6, $scsi_plugin_server)")
print("  - Use 'ls_vars' to list all variables")
print("  - Use 'ls_vars <pattern>' to filter variables")
print("  - Use 'update_vars' to refresh variables")