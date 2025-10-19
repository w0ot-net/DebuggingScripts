#!/usr/bin/env python
"""
search_stack.py - GDB script to search the entire stack for a pointer value
Usage: source search_stack.py
       search-stack 0xdeadbeef
       search-stack 0xdeadbeef --show-context
"""

import gdb
import sys
import struct

class SearchStack(gdb.Command):
    """Search the entire stack (from $sp to stack end) for a pointer value
    
    Usage: search-stack <pointer_value> [--show-context]
    
    Examples:
        search-stack 0xdeadbeef
        search-stack 0x0000fffffffffef8
        search-stack 0x4141414141414141 --show-context
    """
    
    def __init__(self):
        super(SearchStack, self).__init__("search-stack", gdb.COMMAND_DATA)
        self.pointer_size = None
        self.endianness = None
        self._init_arch_info()
    
    def _init_arch_info(self):
        """Initialize architecture-specific information"""
        try:
            # Get pointer size
            void_ptr_type = gdb.lookup_type('void').pointer()
            self.pointer_size = void_ptr_type.sizeof
            
            # Get endianness
            endian = gdb.execute("show endian", to_string=True)
            if "little" in endian.lower():
                self.endianness = "little"
            else:
                self.endianness = "big"
        except:
            # Fallback defaults
            self.pointer_size = 8  # 64-bit
            self.endianness = "little"
    
    def _get_stack_bounds(self):
        """Get the stack boundaries from /proc/[pid]/maps"""
        try:
            # Try to get from info proc mappings
            output = gdb.execute("info proc mappings", to_string=True)
            lines = output.split('\n')
            
            stack_start = None
            stack_end = None
            
            for line in lines:
                # Look for [stack] marker
                if '[stack]' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        # Start address is in parts[0], end in parts[1]
                        stack_start = int(parts[0], 16)
                        stack_end = int(parts[1], 16)
                        return stack_start, stack_end
            
            # If no [stack] found, try to find it heuristically
            # Look for a RW region containing current SP
            sp = int(gdb.parse_and_eval("$sp"))
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        start = int(parts[0], 16)
                        end = int(parts[1], 16)
                        perms = parts[4] if len(parts) > 4 else ""
                        
                        # Check if SP is in this region and it's RW
                        if start <= sp < end and 'r' in perms and 'w' in perms:
                            # This is likely the stack
                            return start, end
                    except (ValueError, IndexError):
                        continue
            
        except Exception as e:
            print(f"Error getting stack bounds: {e}")
        
        return None, None
    
    def _search_memory_chunked(self, start_addr, end_addr, search_value):
        """Search memory in chunks to avoid access errors"""
        matches = []
        chunk_size = 0x400  # 1KB chunks
        current = start_addr
        
        # Align to pointer size
        current = (current + self.pointer_size - 1) & ~(self.pointer_size - 1)
        
        while current < end_addr:
            # Calculate chunk end
            chunk_end = min(current + chunk_size, end_addr)
            
            # Try to search this chunk
            try:
                result = gdb.execute(f"find /g {current:#x}, {chunk_end:#x}, {search_value:#x}", 
                                   to_string=True)
                
                # Parse the results
                for line in result.split('\n'):
                    if line.strip() and '0x' in line and 'pattern found' not in line:
                        # Extract address from result
                        addr_str = line.strip()
                        if addr_str.startswith('0x'):
                            addr = int(addr_str, 16)
                            matches.append(addr)
            except gdb.error as e:
                # If this chunk fails, try smaller chunks or manual search
                if chunk_end - current > self.pointer_size:
                    # Try manual search for this chunk
                    chunk_matches = self._manual_search_chunk(current, chunk_end, search_value)
                    matches.extend(chunk_matches)
            
            current = chunk_end
        
        return matches
    
    def _manual_search_chunk(self, start_addr, end_addr, search_value):
        """Manually search a memory chunk when GDB's find fails"""
        matches = []
        current = start_addr
        
        # Align to pointer size
        current = (current + self.pointer_size - 1) & ~(self.pointer_size - 1)
        
        inferior = gdb.selected_inferior()
        
        while current < end_addr:
            try:
                # Read pointer-sized chunk
                data = inferior.read_memory(current, self.pointer_size)
                
                # Convert to integer
                if self.pointer_size == 8:
                    if self.endianness == "little":
                        value = struct.unpack('<Q', bytes(data))[0]
                    else:
                        value = struct.unpack('>Q', bytes(data))[0]
                else:
                    if self.endianness == "little":
                        value = struct.unpack('<I', bytes(data))[0]
                    else:
                        value = struct.unpack('>I', bytes(data))[0]
                
                # Check if it matches
                if value == search_value:
                    matches.append(current)
                
            except (gdb.MemoryError, gdb.error):
                # Skip inaccessible memory
                pass
            except Exception:
                # Skip on any other error
                pass
            
            current += self.pointer_size
        
        return matches
    
    def _show_context(self, address, lines_before=2, lines_after=2):
        """Show context around a match"""
        try:
            # Show memory around the match
            start = address - (lines_before * self.pointer_size)
            
            print(f"\nContext around {address:#x}:")
            for i in range(lines_before + lines_after + 1):
                addr = start + (i * self.pointer_size)
                try:
                    if self.pointer_size == 8:
                        result = gdb.execute(f"x/gx {addr:#x}", to_string=True)
                    else:
                        result = gdb.execute(f"x/wx {addr:#x}", to_string=True)
                    
                    # Highlight the match line
                    if addr == address:
                        print(f">>> {result.strip()} <<<")
                    else:
                        print(f"    {result.strip()}")
                except:
                    pass
        except Exception as e:
            print(f"Error showing context: {e}")
    
    def invoke(self, args, from_tty):
        """Main command handler"""
        args_list = args.strip().split()
        
        if not args_list:
            print("Usage: search-stack <pointer_value> [--show-context]")
            print("Example: search-stack 0xdeadbeef")
            return
        
        # Parse arguments
        show_context = "--show-context" in args_list
        if show_context:
            args_list.remove("--show-context")
        
        if not args_list:
            print("Error: No search value provided")
            return
        
        # Parse the search value
        search_str = args_list[0]
        try:
            if search_str.startswith("0x") or search_str.startswith("0X"):
                search_value = int(search_str, 16)
            else:
                search_value = int(search_str, 10)
        except ValueError:
            print(f"Error: Invalid search value '{search_str}'")
            return
        
        # Get current SP
        try:
            sp = int(gdb.parse_and_eval("$sp"))
        except:
            print("Error: Could not get current stack pointer")
            return
        
        # Get stack bounds
        stack_start, stack_end = self._get_stack_bounds()
        
        if stack_start is None or stack_end is None:
            print("Warning: Could not determine exact stack bounds")
            print("Using conservative search from $sp to $sp+8MB")
            stack_start = sp
            stack_end = sp + 0x800000  # 8MB default
        else:
            # Adjust start to current SP if it's within the stack
            if stack_start <= sp <= stack_end:
                stack_start = sp
            else:
                print(f"Warning: SP ({sp:#x}) is outside detected stack bounds")
        
        # Print search parameters
        print(f"Searching for: {search_value:#x}")
        print(f"Stack range: {stack_start:#x} to {stack_end:#x}")
        print(f"Range size: {(stack_end - stack_start) / 1024:.1f} KB")
        print(f"Architecture: {self.pointer_size * 8}-bit, {self.endianness}-endian")
        print("-" * 60)
        
        # Perform the search using chunked approach to avoid memory access errors
        print("Searching... (using chunked search to handle memory access limits)")
        matches = self._search_memory_chunked(stack_start, stack_end, search_value)
        
        # Remove duplicates and sort
        matches = sorted(list(set(matches)))
        
        # Display results
        if matches:
            print(f"\nFound {len(matches)} match(es):\n")
            for i, addr in enumerate(matches, 1):
                # Calculate offset from SP
                offset = addr - sp
                print(f"{i:3d}. {addr:#018x} (sp{offset:+#x})")
                
                # Show what's at that address
                try:
                    if self.pointer_size == 8:
                        cmd = f"x/gx {addr:#x}"
                    else:
                        cmd = f"x/wx {addr:#x}"
                    value = gdb.execute(cmd, to_string=True)
                    print(f"     => {value.strip()}")
                except:
                    pass
                
                # Show context if requested
                if show_context:
                    self._show_context(addr)
            
            print(f"\nTotal matches: {len(matches)}")
        else:
            print("\nNo matches found in the stack")
            print("Note: Some memory regions might be inaccessible")
            print("Try searching smaller ranges or use manual stepping")

# Register the command
SearchStack()
print("search-stack command loaded")
print("Usage: search-stack <pointer_value> [--show-context]")
print("Example: search-stack 0x0000fffffffffef8")