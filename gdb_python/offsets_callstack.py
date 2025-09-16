import gdb
import re
import bisect

class OffsetsCallstackCommand(gdb.Command):
    """Display callstack with offsets instead of absolute addresses"""
    
    def __init__(self):
        super(OffsetsCallstackCommand, self).__init__("offsets_callstack", gdb.COMMAND_USER)
        self.module_bases = {}
    
    def update_module_bases(self):
        """Parse memory mappings to find base address of each module"""
        self.module_bases = {}
        
        try:
            # Get memory mappings
            mappings = gdb.execute("info proc mappings", to_string=True)
            
            for line in mappings.split('\n'):
                # Skip header lines
                if 'Start Addr' not in line and 'Offset' in line:
                    continue
                    
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        start = int(parts[0], 16)
                        end = int(parts[1], 16)
                        
                        # Extract filename if present
                        filename = ' '.join(parts[5:]).strip()
                        
                        # Skip special sections
                        if not filename or (filename.startswith('[') and filename.endswith(']')):
                            continue
                        
                        # Track the lowest address for each module (base address)
                        if filename not in self.module_bases:
                            self.module_bases[filename] = {
                                'base': start,
                                'ranges': [(start, end)]
                            }
                        else:
                            # Update base if we found a lower address
                            self.module_bases[filename]['base'] = min(
                                self.module_bases[filename]['base'], 
                                start
                            )
                            # Add this range
                            self.module_bases[filename]['ranges'].append((start, end))
                            
                    except (ValueError, IndexError):
                        continue
            
        except Exception as e:
            print(f"Memory mapping failed: {e}")
    
    def find_module_for_address(self, addr):
        """Find which module contains the given address"""
        for filepath, info in self.module_bases.items():
            # Check if address falls in any range of this module
            for start, end in info['ranges']:
                if addr >= start and addr < end:
                    # Extract just the filename for display
                    filename = filepath.split('/')[-1]
                    return {
                        'name': filename,
                        'base': info['base'],
                        'filepath': filepath
                    }
        return None
    
    def get_disassembly(self, addr):
        """Get the disassembly at the given address"""
        try:
            result = gdb.execute(f"x/i {addr:#x}", to_string=True)
            parts = result.strip().split(':', 1)
            if len(parts) > 1:
                return parts[1].strip()
            return ""
        except:
            return ""
    
    def format_address_with_offset(self, addr):
        """Format address as module+offset"""
        module = self.find_module_for_address(addr)
        
        if module:
            offset = addr - module['base']
            return f"{module['name']}+0x{offset:x}"
        else:
            # No module found, show the address in a readable format
            if addr > 0x7fff00000000:
                # Likely stack address
                return f"[stack]+0x{addr & 0xffffffff:x}"
            elif addr < 0x1000000:
                # Low memory
                return f"[low]+0x{addr:x}"
            else:
                # Unknown mapping, show absolute
                return f"0x{addr:016x}"
    
    def invoke(self, arg, from_tty):
        # Update module base addresses
        self.update_module_bases()
        
        try:
            # Get the current frame
            frame = gdb.selected_frame()
            frame_num = 0
            
            # Iterate through all frames
            while frame:
                pc = frame.pc()
                
                # Format address with module+offset
                addr_str = self.format_address_with_offset(pc)
                
                # Get disassembly at this address
                disasm = self.get_disassembly(pc)
                
                # Format similar to GEF output
                if disasm:
                    print(f"[#{frame_num}] {addr_str} → {disasm}")
                else:
                    print(f"[#{frame_num}] {addr_str}")
                
                # Move to older frame
                try:
                    frame = frame.older()
                    frame_num += 1
                except:
                    break
                
                # Limit output to prevent excessive frames
                if frame_num >= 50:
                    print("[... additional frames truncated ...]")
                    break
                    
        except Exception as e:
            print(f"Error getting callstack: {e}")

# Register the command
OffsetsCallstackCommand()

print("offsets_callstack command loaded")