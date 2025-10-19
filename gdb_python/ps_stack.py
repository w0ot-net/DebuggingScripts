import gdb
import struct
import re

# ============================================================================
# WARNING: THESE OFFSETS ARE SPECIFIC TO YOUR BINARY VERSION!
# You MUST update these values for each different version of the binary.
# These are the offsets from the binary base address to the stack pointers.
# ============================================================================

"""
  stack_bottom_v1 = ps_stack_bottom_qword_4764F0;
  result = ps_stack_top_qword_4764F8;
  temp_value_v2 = ps_stack_top_qword_4764F8 - 16;
  if ( ps_stack_bottom_qword_4764F0 > (unsigned __int64)(ps_stack_top_qword_4764F8 - 16) )
"""
PS_STACK_BASE_OFFSET = 0x4764F0  # qword_4764F0 - stack bottom
PS_STACK_SP_OFFSET = 0x4764F8    # qword_4764F8 - stack top/pointer

# Global variables to cache the addresses (computed once)
_ps_sp_addr = None
_ps_base_addr = None
_base_addr = None

def get_ps_addresses():
    """Get the PS stack addresses, computing them only once"""
    global _ps_sp_addr, _ps_base_addr, _base_addr
    
    if _ps_sp_addr is None or _ps_base_addr is None:
        # Get base dynamically using GEF's new API
        vmmap = gef.memory.maps  # Use new GEF API
        _base_addr = None
        
        for entry in vmmap:
            if entry.path and 'thumb' in entry.path and entry.is_executable():
                _base_addr = entry.page_start
                break
                
        if not _base_addr:
            raise Exception("Could not find thumb base")
            
        # Calculate addresses only once
        _ps_base_addr = _base_addr + PS_STACK_BASE_OFFSET
        _ps_sp_addr = _base_addr + PS_STACK_SP_OFFSET
        
    return _base_addr, _ps_sp_addr, _ps_base_addr

class PSStackCommand(gdb.Command):
    """Visualize the PostScript operand stack"""
    
    def __init__(self):
        super(PSStackCommand, self).__init__("ps-stack", gdb.COMMAND_USER)
        self.ps_type_names = {
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
    
    def get_thumb_base(self):
        """Get thumb base address from vmmap"""
        try:
            # Use GEF's new API
            vmmap = gef.memory.maps  # Use new GEF API
            
            # Look for the first executable mapping of /usr/bin/thumb
            for entry in vmmap:
                if entry.path and 'thumb' in entry.path and entry.is_executable():
                    return entry.page_start
                    
            # Fallback: try to parse from current PC or known symbols
            return None
            
        except Exception as e:
            print(f"Error getting thumb base: {e}")
            return None
        
    def get_ps_type_name(self, type_val):
        # Ensure we're working with an integer
        if not isinstance(type_val, int):
            type_val = ord(type_val)
        base_type = type_val & 0x3F  # Mask off permission bits
        return self.ps_type_names.get(base_type, f"UNKNOWN({base_type:#x})")
    
    def get_permissions(self, perms_byte):
        # Ensure we're working with an integer
        if not isinstance(perms_byte, int):
            perms_byte = ord(perms_byte)
        perms = []
        # The permissions seem to be in the lower bits
        if perms_byte & 0x01:
            perms.append("EXEC")
        if perms_byte & 0x02:
            perms.append("WRITE") 
        if perms_byte & 0x04:
            perms.append("READ")
        return "|".join(perms) if perms else "NONE"
        
    def read_string_value(self, addr, length):
        try:
            # Read string bytes
            inferior = gdb.selected_inferior()
            # Ensure length is reasonable
            if length > 1024:
                return f"<string too long: {length} bytes>"
            if length == 0:
                return "()"
            data = inferior.read_memory(addr, min(length, 32))
            
            # Convert to string, handling non-printable chars
            result = ""
            for i in range(min(length, 32)):
                b = data[i] if isinstance(data[i], int) else ord(data[i])
                if 32 <= b <= 126:  # Printable ASCII
                    result += chr(b)
                else:
                    result += f"\\x{b:02x}"
                    
            if length > 32:
                result += "..."
                
            return f"({result})"
        except Exception as e:
            return f"<error: {str(e)}>"
    
    def read_name_value(self, addr, length):
        """Read a NAME type value - pointer points to a structure where string ptr is at offset 8"""
        try:
            inferior = gdb.selected_inferior()
            # Read the structure that addr points to
            # At offset 8 is the actual string pointer
            struct_data = inferior.read_memory(addr, 16)
            string_ptr = struct.unpack('<Q', struct_data[8:16])[0]
            
            # Now read the actual string
            return self.read_string_value(string_ptr, length)
        except Exception as e:
            # Fall back to showing raw bytes if structure reading fails
            return self.read_string_value(addr, length)
    
    def read_stack_entry(self, addr, inferior, show_top_marker=False):
        """Helper function to read and format a stack entry"""
        try:
            # Read 16-byte entry
            entry = inferior.read_memory(addr, 16)
            
            # Parse entry structure - 16 bytes total on 64-bit
            # First 8 bytes: type, perms, length, etc
            # Second 8 bytes: value (pointer for strings, actual value for others)
            
            first_qword = struct.unpack('<Q', entry[0:8])[0]
            second_qword = struct.unpack('<Q', entry[8:16])[0]
            
            # Extract fields from first qword
            type_byte = first_qword & 0xFF
            perms_byte = (first_qword >> 8) & 0xFF
            length = (first_qword >> 16) & 0xFFFF
            
            # Second qword is the value/pointer
            value = second_qword
            
            # Format output
            output = f"{addr:#x} "
            
            # Type and permissions
            type_name = self.get_ps_type_name(type_byte)
            output += f"TYPE: {type_name} ({type_byte:#x})"
            
            if perms_byte != 0:
                output += f" PERMS: {self.get_permissions(perms_byte)}"
            
            # Type-specific formatting
            if type_byte == 0x24:  # STRING
                output += f" LEN: {length} PTR: {value:#x}"
                # Try to read string if possible
                try:
                    string_val = self.read_string_value(value, length)
                    output += f" -> {string_val}"
                except:
                    pass
            elif type_byte == 0x00:  # INTEGER
                output += f" VALUE: {value}"
            elif type_byte == 0x01:  # FLOAT
                # Reinterpret as float
                float_bytes = struct.pack('<Q', value)
                float_val = struct.unpack('<d', float_bytes)[0]
                output += f" VALUE: {float_val}"
            elif type_byte == 0x02:  # BOOLEAN
                output += f" VALUE: {'true' if value else 'false'}"
            elif type_byte == 0x05:  # NAME
                output += f" LEN: {length} PTR: {value:#x}"
                # Try to read name string
                try:
                    name_val = self.read_name_value(value, length)
                    output += f" -> /{name_val}"
                except:
                    pass
            elif type_byte == 0x23:  # ARRAY
                output += f" LEN: {length} PTR: {value:#x}"
            else:
                output += f" VALUE: {value:#x}"
            
            if show_top_marker:
                output += " <- TOP"
                
            return output
            
        except Exception as e:
            return f"{addr:#x} <Error reading entry: {e}>"
    
    def invoke(self, arg, from_tty):
        above_below_show = 10
        try:
            # Get addresses (computed only once)
            base_addr, ps_sp_addr, ps_base_addr = get_ps_addresses()
            
            print(f"Using thumb base address: {base_addr:#x}")
            print(f"Reading stack pointer from: {ps_sp_addr:#x}")
            print(f"Reading base pointer from: {ps_base_addr:#x}")
            
            # Read the pointer values (8 bytes each on 64-bit)
            inferior = gdb.selected_inferior()
            ps_sp_bytes = inferior.read_memory(ps_sp_addr, 8)
            ps_base_bytes = inferior.read_memory(ps_base_addr, 8)
            
            ps_sp = struct.unpack('<Q', ps_sp_bytes)[0]
            ps_base = struct.unpack('<Q', ps_base_bytes)[0]
            
            print(f"\nPostScript Stack (SP: {ps_sp:#x}, Base: {ps_base:#x})")
            print("=" * 80)
            
            # Sanity check the pointers
            if ps_sp == 0 or ps_base == 0:
                print("ERROR: Null pointers detected!")
                return
                
            if ps_sp > 0xffffffffffff or ps_base > 0xffffffffffff:
                print("ERROR: Invalid pointer values!")
                print(f"Raw SP bytes: {ps_sp_bytes.hex()}")
                print(f"Raw Base bytes: {ps_base_bytes.hex()}")
                return
            
            # PostScript stack grows UP (SP increases when pushing)
            # SP points to the last item on the stack
            stack_empty = False
            if ps_sp >= ps_base:
                num_items = ((ps_sp - ps_base) // 16) + 1
                if ps_sp == ps_base:
                    print(f"Stack has 1 item")
                elif ps_sp > ps_base:
                    print(f"Stack has {num_items} items")
                else:
                    print("Stack is empty")
                print("=" * 80)
            elif ps_sp < ps_base:
                print("WARNING: Stack underflow detected!")
                print(f"SP is {ps_base - ps_sp} bytes below base")
                print("=" * 80)
                stack_empty = True
            
            # Always show 3 items above where SP would be
            above_items = []
            # For empty stack, show above ps_base
            reference_point = ps_sp if ps_sp >= ps_base else ps_base
            
            for i in range(1, above_below_show + 1):
                addr = reference_point + (i * 16)
                try:
                    entry = self.read_stack_entry(addr, inferior)
                    above_items.append(entry)
                except:
                    break
            
            # Print above items in reverse order (closest to top first)
            for item in reversed(above_items):
                print(item)
            
            if above_items:
                print("::TOP::")
            
            # Display stack contents - items are between Base and SP (inclusive)
            if ps_sp >= ps_base:
                entry_count = 0
                max_entries = 10000
                
                # Read from SP down to base (most recent first)
                # SP points to the last item, not the next free slot
                current = ps_sp
                while current >= ps_base and entry_count < max_entries:
                    entry = self.read_stack_entry(current, inferior, show_top_marker=(entry_count == 0))
                    print(entry)
                    entry_count += 1
                    current -= 16
                    
                if entry_count >= max_entries:
                    print(f"(Stopped after {max_entries} entries)")
            else:
                print("::STACK EMPTY::")
            
            # Always show bottom marker
            print("::BOTTOM::")
            
            # Show 3 items below the stack base
            for i in range(1, above_below_show + 1):
                addr = ps_base - (i * 16)
                try:
                    entry = self.read_stack_entry(addr, inferior)
                    print(entry)
                except:
                    break
                
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()

# Register command
PSStackCommand()

# Also create a command to show raw memory at stack locations
class PSStackRawCommand(gdb.Command):
    """Show raw memory at PostScript stack location"""
    
    def __init__(self):
        super(PSStackRawCommand, self).__init__("ps-stack-raw", gdb.COMMAND_USER)
        
    def invoke(self, arg, from_tty):
        try:
            # Get addresses (computed only once)
            base_addr, ps_sp_addr, ps_base_addr = get_ps_addresses()
            
            print(f"Stack pointer location: {ps_sp_addr:#x}")
            gdb.execute(f"x/2gx {ps_sp_addr:#x}")
            
            print(f"\nBase pointer location: {ps_base_addr:#x}")
            gdb.execute(f"x/2gx {ps_base_addr:#x}")
            
        except Exception as e:
            print(f"Error: {e}")

PSStackRawCommand()

print("PostScript stack visualizer loaded!")
print("Commands:")
print("  ps-stack     - Show current PostScript stack")
print("  ps-stack-raw - Show raw pointer values")
print("")
print("=" * 60)
print("WARNING: Stack pointer offsets are hardcoded for THIS binary!")
print(f"  PS_STACK_BASE_OFFSET = 0x{PS_STACK_BASE_OFFSET:X}")
print(f"  PS_STACK_SP_OFFSET   = 0x{PS_STACK_SP_OFFSET:X}")
print("Update these values if using a different binary version!")
print("=" * 60)