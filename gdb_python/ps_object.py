import gdb
import struct
import re

class PSObjectCommand(gdb.Command):
    """Recursively dump PostScript objects (dictionaries, arrays, etc.)"""
    
    def __init__(self):
        super(PSObjectCommand, self).__init__("ps-object", gdb.COMMAND_USER)
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
        self.debug = False
        self.hexdump = False
        
        # ANSI color codes
        self.colors = {
            'reset': '\033[0m',
            'header': '\033[95m',     # Magenta for dict header
            'padding': '\033[90m',    # Gray for padding
            'address': '\033[93m',    # Yellow for addresses
            'normal': '\033[0m'       # Reset
        }
        
        # Color pairs for key-value pairs (light/dark versions)
        self.color_pairs = [
            ('\033[38;5;209m', '\033[38;5;202m'),  # Light orange / Dark orange
            ('\033[38;5;117m', '\033[38;5;33m'),   # Light blue / Dark blue  
            ('\033[38;5;120m', '\033[38;5;28m'),   # Light green / Dark green
            ('\033[38;5;225m', '\033[38;5;165m'),  # Light pink / Dark pink
            ('\033[38;5;228m', '\033[38;5;136m'),  # Light yellow / Dark yellow
            ('\033[38;5;183m', '\033[38;5;97m'),   # Light purple / Dark purple
            ('\033[38;5;159m', '\033[38;5;30m'),   # Light cyan / Dark cyan
            ('\033[38;5;210m', '\033[38;5;124m'),  # Light red / Dark red
        ]
    
    def get_ps_type_name(self, type_val):
        if not isinstance(type_val, int):
            type_val = ord(type_val)
        base_type = type_val & 0x3F
        return self.ps_type_names.get(base_type, f"UNKNOWN({base_type:#x})")
    
    def get_permissions(self, perms_byte):
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
    
    def read_string_value(self, addr, length):
        """Read a string value from memory"""
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
    
    def hexdump_dictionary(self, dict_ptr, entries):
        """Display a colorized hex dump of the dictionary with annotations"""
        try:
            inferior = gdb.selected_inferior()
            
            print(f"\n{self.colors['address']}Hex dump of dictionary @ {dict_ptr:#x}:{self.colors['reset']}")
            print("-" * 80)
            
            # Mark regions in the hex dump
            regions = []
            pair_index = 0  # Track which color pair to use
            
            # Header region (0x00-0x27)
            regions.append((0x00, 0x28, 'header', 'Dictionary header', None))
            
            # Calculate the actual size needed based on parsed entries
            max_offset = 0x28  # Start with header size
            
            # Parse the dictionary to find actual entries and calculate size
            dict_header = inferior.read_memory(dict_ptr, 0x28)
            
            # Get entry count
            count_field = struct.unpack('<Q', dict_header[0x10:0x18])[0]
            count_low = count_field & 0xFFFFFFFF
            entry_count = count_low & 0xFF
            
            if entry_count == 0 or entry_count > 100:
                print(f"Invalid entry count: {entry_count}")
                return
            
            # First pass: scan to find the end of THIS dictionary's entries
            temp_data = inferior.read_memory(dict_ptr, min(8192, 0x28 + (entry_count * 100)))
            offset = 0x28
            entries_found = 0
            
            while entries_found < entry_count and offset + 16 <= len(temp_data):
                qword = struct.unpack('<Q', temp_data[offset:offset+8])[0]
                
                if (qword & 0xFFFFFFFF) == 0x00000002:
                    # Padding
                    offset += 8
                else:
                    # Check if this looks like a valid PostScript object
                    type_byte = qword & 0xFF
                    if type_byte in self.ps_type_names or (type_byte & 0x3F) in self.ps_type_names:
                        # Found a key - any PS object type can be a key
                        offset += 16  # Key
                        offset += 16  # Value
                        entries_found += 1
                        max_offset = offset  # Update max offset
                    else:
                        offset += 8
            
            # Now read just the amount we need
            dict_data = inferior.read_memory(dict_ptr, max_offset)
            
            # Second pass: mark regions for coloring
            offset = 0x28
            entries_found = 0
            
            while entries_found < entry_count and offset + 16 <= len(dict_data):
                qword = struct.unpack('<Q', dict_data[offset:offset+8])[0]
                
                if (qword & 0xFFFFFFFF) == 0x00000002:
                    regions.append((offset, offset+8, 'padding', f'Padding', None))
                    offset += 8
                else:
                    # Check if this looks like a valid PostScript object
                    type_byte = qword & 0xFF
                    if type_byte in self.ps_type_names or (type_byte & 0x3F) in self.ps_type_names:
                        # Found a key - parse it
                        obj = self.parse_stack_object(dict_ptr + offset)
                        
                        # Format key based on type
                        if obj['type'] == 'NAME':
                            key_desc = f"/{self.read_name_value(obj['value'])}"
                        elif obj['type'] == 'STRING':
                            key_desc = f"({self.read_string_value(obj['value'], obj['length'])})"
                        elif obj['type'] == 'INTEGER':
                            key_desc = f"{obj['value']}"
                        elif obj['type'] == 'ARRAY':
                            key_desc = f"[array:{obj['length']}]"
                        else:
                            key_desc = f"{obj['type']}"
                        
                        # Assign color pair for this key-value
                        color_pair = self.color_pairs[pair_index % len(self.color_pairs)]
                        
                        regions.append((offset, offset+16, 'key', f'Key: {key_desc} @ {dict_ptr+offset:#x}', color_pair[0]))
                        offset += 16
                        
                        # Next is value
                        if offset <= len(dict_data) - 16:
                            value_obj = self.parse_stack_object(dict_ptr + offset)
                            value_desc = self.format_object(value_obj, show_addr=False)
                            if len(value_desc) > 40:
                                value_desc = value_desc[:37] + "..."
                            regions.append((offset, offset+16, 'value', f'Value @ {dict_ptr+offset:#x}: {value_desc}', color_pair[1]))
                            offset += 16
                        
                        entries_found += 1
                        pair_index += 1  # Move to next color pair
                    else:
                        offset += 8
            
            # Print hex dump with colors - show as qwords in little-endian format
            for i in range(0, len(dict_data), 16):
                # Address
                print(f"{self.colors['address']}{dict_ptr+i:016x}:{self.colors['reset']} ", end="")
                
                # Two qwords per line
                for qword_idx in range(2):
                    start_idx = i + (qword_idx * 8)
                    if start_idx + 8 <= len(dict_data):
                        # Read 8 bytes and format as little-endian qword
                        qword_bytes = dict_data[start_idx:start_idx+8]
                        qword_val = struct.unpack('<Q', qword_bytes)[0]
                        
                        # Find color for this qword based on its start position
                        color = self.colors['normal']
                        annotation = ""
                        for start, end, region_type, desc, custom_color in regions:
                            if start <= start_idx < end:
                                if custom_color:
                                    color = custom_color
                                elif region_type in self.colors:
                                    color = self.colors[region_type]
                                annotation = desc
                                break
                        
                        print(f"{color}0x{qword_val:016x}{self.colors['reset']}", end="")
                    else:
                        print(" " * 18, end="")
                    
                    # Add space between qwords
                    if qword_idx == 0:
                        print(" ", end="")
                
                # Add annotation for this line
                for start, end, region_type, desc, custom_color in regions:
                    if start <= i < end:
                        if custom_color:
                            print(f"  {custom_color}<-- {desc}{self.colors['reset']}", end="")
                        else:
                            print(f"  {self.colors.get(region_type, self.colors['normal'])}<-- {desc}{self.colors['reset']}", end="")
                        break
                
                print()  # Newline
            
            print("-" * 80)
            
            # Print legend with color pairs
            print(f"\nLegend: {self.colors['header']}■ Header{self.colors['reset']} "
                  f"{self.colors['padding']}■ Padding{self.colors['reset']}")
            print("Key-Value pairs use rotating colors:")
            for i, (light, dark) in enumerate(self.color_pairs[:4]):
                print(f"  Pair {i+1}: {light}■ Key{self.colors['reset']} {dark}■ Value{self.colors['reset']}", end="")
                if i == 1:
                    print()
            if len(self.color_pairs) > 4:
                print(f"\n  ... and {len(self.color_pairs)-4} more color pairs")
            
        except Exception as e:
            print(f"Error creating hex dump: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
    
    def parse_stack_object(self, addr):
        """Parse a single stack object (16 bytes for 64-bit)
        
        Structure:
        First qword: only low 4 bytes matter
          Byte 0: type
          Byte 1: perms  
          Bytes 2-3: length
          Bytes 4-7: IGNORED (high 4 bytes)
        Second qword: value/pointer
        """
        try:
            inferior = gdb.selected_inferior()
            obj_data = inferior.read_memory(addr, 16)
            
            first_qword = struct.unpack('<Q', obj_data[0:8])[0]
            second_qword = struct.unpack('<Q', obj_data[8:16])[0]
            
            # Only use low 4 bytes of first qword
            low_dword = first_qword & 0xFFFFFFFF
            
            # Extract fields from low dword
            type_byte = low_dword & 0xFF                    # Byte 0
            perms = (low_dword >> 8) & 0xFF                 # Byte 1
            length = (low_dword >> 16) & 0xFFFF             # Bytes 2-3
            
            type_name = self.get_ps_type_name(type_byte)
            perms_str = self.get_permissions(perms)
            
            if self.debug:
                print(f"  DEBUG @ {addr:#x}: raw={first_qword:#018x} {second_qword:#018x}")
                print(f"    type={type_name}({type_byte:#x}) perms={perms_str}({perms:#x}) len={length}")
            
            result = {
                'type': type_name,
                'type_byte': type_byte,
                'perms': perms_str,
                'perms_raw': perms,
                'length': length,
                'value': second_qword,
                'raw_first': first_qword,
                'address': addr  # Store the object's own address
            }
            
            return result
            
        except Exception as e:
            return {'error': str(e)}
    
    def read_name_value(self, name_ptr):
        """Read a NAME object's string value from a pointer
        
        NAME structure (16 bytes for 64-bit):
        0x00: length (only low 4 bytes matter)
        0x08: pointer to string
        """
        try:
            inferior = gdb.selected_inferior()
            
            name_struct = inferior.read_memory(name_ptr, 16)
            
            first = struct.unpack('<Q', name_struct[0:8])[0]
            string_ptr = struct.unpack('<Q', name_struct[8:16])[0]
            
            # Only use low 4 bytes for length
            length = first & 0xFFFFFFFF
            
            if string_ptr and length > 0 and length < 0x1000:
                return self.read_string_value(string_ptr, length)
            else:
                return f"<invalid name @ {name_ptr:#x}>"
                
        except Exception as e:
            return f"<error reading name: {e}>"
    
    def parse_dictionary_raw(self, dict_ptr):
        """Parse a raw dictionary structure
        
        Dictionary layout:
        0x00: marker (0x...4d00 in low bytes)
        0x08: zeros
        0x10: count info (0x00020003 means 3 entries)
        0x18-0x20: zeros
        0x28: first key-value pair starts
        
        Entries are packed with 8-byte alignment, not 16-byte!
        Padding is 8 bytes (0x00000002), not 16!
        Keys can be ANY PostScript type, not just NAME!
        """
        try:
            inferior = gdb.selected_inferior()
            
            # Read dictionary header
            dict_header = inferior.read_memory(dict_ptr, 0x28)
            
            # Check dictionary marker (low 4 bytes)
            marker = struct.unpack('<Q', dict_header[0:8])[0]
            if ((marker & 0xFFFFFFFF) & 0xFFFF) != 0x4d00:
                if self.debug:
                    print(f"  DEBUG: Not a dict marker: {marker:#x}")
                return None
            
            # Get count from offset 0x10 - count is in byte 0 of low dword
            count_field = struct.unpack('<Q', dict_header[0x10:0x18])[0]
            count_low = count_field & 0xFFFFFFFF
            entry_count = count_low & 0xFF
            
            if entry_count == 0 or entry_count > 100:
                if self.debug:
                    print(f"  DEBUG: Invalid entry count: {entry_count}")
                return None
            
            if self.debug:
                print(f"  DEBUG: Dictionary @ {dict_ptr:#x} expects {entry_count} entries")
            
            # Read ALL the data we might need
            dict_size = min(8192, 0x28 + (entry_count * 100))
            dict_data = inferior.read_memory(dict_ptr, dict_size)
            
            entries = {}
            offset = 0x28
            entries_found = 0
            
            # Scan through 8-byte aligned data
            while entries_found < entry_count and offset + 32 <= len(dict_data):
                # Read 8 bytes at current offset
                qword = struct.unpack('<Q', dict_data[offset:offset+8])[0]
                
                # Check if this is an 8-byte padding (0x00000002)
                if (qword & 0xFFFFFFFF) == 0x00000002:
                    if self.debug:
                        print(f"    8-byte padding at {dict_ptr+offset:#x}")
                    offset += 8  # Only skip 8 bytes!
                    continue
                
                # Check if this looks like a valid PostScript object (any type can be a key!)
                type_byte = qword & 0xFF
                if type_byte in self.ps_type_names or (type_byte & 0x3F) in self.ps_type_names:
                    # This could be a key - parse the full 16-byte object
                    key_obj = self.parse_stack_object(dict_ptr + offset)
                    
                    # Format the key based on its type
                    if key_obj['type'] == 'NAME':
                        key_str = self.read_name_value(key_obj['value'])
                    elif key_obj['type'] == 'STRING':
                        key_str = f'({self.read_string_value(key_obj["value"], key_obj["length"])})'
                    elif key_obj['type'] == 'INTEGER':
                        key_str = str(key_obj['value'])
                    elif key_obj['type'] == 'ARRAY':
                        key_str = f'[array:{key_obj["length"]}@{key_obj["value"]:#x}]'
                    elif key_obj['type'] == 'DICTIONARY':
                        key_str = f'<<dict:{key_obj["length"]}@{key_obj["value"]:#x}>>'
                    else:
                        key_str = f'{key_obj["type"]}@{key_obj["value"]:#x}'
                    
                    # Next 16 bytes should be the value
                    offset += 16
                    if offset + 16 <= len(dict_data):
                        value_obj = self.parse_stack_object(dict_ptr + offset)
                        
                        entries[key_str] = {
                            'key_obj': key_obj,
                            'obj': value_obj,
                            'formatted': self.format_object(value_obj)
                        }
                        
                        if self.debug:
                            print(f"    Found {entries_found+1}/{entry_count}: {key_str} => {entries[key_str]['formatted']}")
                        
                        entries_found += 1
                        offset += 16
                    else:
                        break
                else:
                    # Not a valid PS object, skip 8 bytes
                    offset += 8
            
            if entries_found != entry_count:
                print(f"  WARNING: Found {entries_found} entries but expected {entry_count}!")
            
            return entries
            
        except Exception as e:
            print(f"  ERROR in parse_dictionary_raw: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
            return None
    
    def format_object(self, obj, show_addr=True):
        """Format an object for display with type annotation
        
        Args:
            obj: The object to format
            show_addr: Whether to show the object's own address (default True)
        """
        if 'error' in obj:
            return f"<error: {obj['error']}>"
        
        type_str = f"{obj['type']}({obj['type_byte']:#x})"
        
        # Include object address if requested
        addr_str = f" @obj:{obj['address']:#x}" if show_addr and 'address' in obj else ""
        
        if obj['type'] == 'STRING':
            string_val = self.read_string_value(obj['value'], obj['length'])
            return f"{type_str}: \"{string_val}\" @backing:{obj['value']:#x}{addr_str}"
        elif obj['type'] == 'NAME':
            name_val = self.read_name_value(obj['value'])
            return f"{type_str}: /{name_val} @backing:{obj['value']:#x}{addr_str}"
        elif obj['type'] == 'INTEGER':
            return f"{type_str}: {obj['value']}{addr_str}"
        elif obj['type'] == 'DICTIONARY':
            return f"{type_str}: <<{obj['length']} entries @backing:{obj['value']:#x}>>{addr_str}"
        elif obj['type'] == 'ARRAY':
            return f"{type_str}: [{obj['length']} items @backing:{obj['value']:#x}]{addr_str}"
        else:
            return f"{type_str}: @backing:{obj['value']:#x}{addr_str}"
    
    def parse_array_raw(self, array_ptr, length):
        """Parse an array structure - array of stack objects"""
        try:
            inferior = gdb.selected_inferior()
            
            elements = []
            
            for i in range(min(length, 10)):
                elem_addr = array_ptr + (i * 16)
                elem = self.parse_stack_object(elem_addr)
                elem_str = self.format_object(elem)
                elements.append(elem_str)
            
            if length > 10:
                elements.append(f"... ({length - 10} more elements)")
            
            return elements
            
        except Exception as e:
            return [f"<error: {str(e)}>"]
    
    def dump_object(self, addr, indent=0, visited=None, max_depth=4):
        """Recursively dump a PostScript object"""
        if visited is None:
            visited = set()
        
        if addr in visited or indent > max_depth:
            return
        
        visited.add(addr)
        prefix = "  " * indent
        
        try:
            # Parse as a stack object
            obj = self.parse_stack_object(addr)
            
            if 'error' not in obj:
                print(f"{prefix}{self.format_object(obj)}")
                print(f"{prefix}  Raw: {obj['raw_first']:#018x} {obj['value']:#018x}")
                print(f"{prefix}  Perms: {obj['perms']} ({obj['perms_raw']:#x}), Length: {obj['length']}")
                
                if obj['type'] == 'DICTIONARY':
                    dict_entries = self.parse_dictionary_raw(obj['value'])
                    
                    if dict_entries:
                        # Show hex dump if requested
                        if self.hexdump and indent == 0:  # Only for top-level
                            self.hexdump_dictionary(obj['value'], dict_entries)
                        
                        # IMPORTANT: Show count mismatch if it exists
                        if len(dict_entries) != obj['length']:
                            print(f"{prefix}  WARNING: Expected {obj['length']} entries but found {len(dict_entries)}!")
                        
                        print(f"{prefix}  Dictionary entries ({len(dict_entries)} found, {obj['length']} expected):")
                        
                        # DUMP ALL ENTRIES
                        for key, entry in dict_entries.items():
                            # Format key display based on type
                            if 'key_obj' in entry:
                                key_type = entry['key_obj']['type']
                                if key_type == 'NAME':
                                    key_display = f"/{key}"
                                elif key_type == 'STRING':
                                    key_display = key  # Already formatted as (string)
                                elif key_type == 'ARRAY':
                                    key_display = key  # Already formatted as [array:N@addr]
                                else:
                                    key_display = key
                            else:
                                # Legacy format (NAME only)
                                key_display = f"/{key}"
                            
                            print(f"{prefix}    {key_display} => {entry['formatted']}")
                        
                        # Now show nested structures for ALL dictionary entries
                        for key, entry in dict_entries.items():
                            # Format key display
                            if 'key_obj' in entry:
                                key_type = entry['key_obj']['type']
                                if key_type == 'NAME':
                                    key_display = f"/{key}"
                                elif key_type == 'STRING':
                                    key_display = key  # Already formatted
                                elif key_type == 'ARRAY':
                                    key_display = f"array-key"  # Simplify for nested display
                                else:
                                    key_display = key
                            else:
                                key_display = f"/{key}"
                                
                            if entry['obj']['type'] == 'DICTIONARY':
                                print(f"{prefix}    Expanding nested dictionary {key_display}:")
                                nested = self.parse_dictionary_raw(entry['obj']['value'])
                                if nested:
                                    if len(nested) != entry['obj']['length']:
                                        print(f"{prefix}      WARNING: Expected {entry['obj']['length']} entries but found {len(nested)}!")
                                    
                                    for nkey, nvalue in nested.items():
                                        # Format nested key
                                        if 'key_obj' in nvalue:
                                            nkey_type = nvalue['key_obj']['type']
                                            if nkey_type == 'NAME':
                                                nkey_display = f"/{nkey}"
                                            else:
                                                nkey_display = nkey
                                        else:
                                            nkey_display = f"/{nkey}"
                                        print(f"{prefix}      {nkey_display} => {nvalue['formatted']}")
                                    
                                    # Go even deeper for nested dictionaries
                                    for nkey, nvalue in nested.items():
                                        if 'key_obj' in nvalue:
                                            nkey_type = nvalue['key_obj']['type']
                                            if nkey_type == 'NAME':
                                                nkey_display = f"/{nkey}"
                                            else:
                                                nkey_display = nkey
                                        else:
                                            nkey_display = f"/{nkey}"
                                            
                                        if nvalue['obj']['type'] == 'DICTIONARY':
                                            print(f"{prefix}      Expanding nested dictionary {nkey_display}:")
                                            nested2 = self.parse_dictionary_raw(nvalue['obj']['value'])
                                            if nested2:
                                                for n2key, n2value in nested2.items():
                                                    if 'key_obj' in n2value:
                                                        n2key_type = n2value['key_obj']['type']
                                                        if n2key_type == 'NAME':
                                                            n2key_display = f"/{n2key}"
                                                        else:
                                                            n2key_display = n2key
                                                    else:
                                                        n2key_display = f"/{n2key}"
                                                    print(f"{prefix}        {n2key_display} => {n2value['formatted']}")
                                        elif nvalue['obj']['type'] == 'ARRAY':
                                            print(f"{prefix}      Array {nkey_display}:")
                                            array_elements = self.parse_array_raw(nvalue['obj']['value'], nvalue['obj']['length'])
                                            for i, elem in enumerate(array_elements):
                                                print(f"{prefix}        [{i}]: {elem}")
                                                
                            elif entry['obj']['type'] == 'ARRAY':
                                print(f"{prefix}    Array {key_display}:")
                                array_elements = self.parse_array_raw(entry['obj']['value'], entry['obj']['length'])
                                for i, elem in enumerate(array_elements):
                                    print(f"{prefix}      [{i}]: {elem}")
                    else:
                        print(f"{prefix}  ERROR: Could not parse dictionary!")
                        
                elif obj['type'] == 'ARRAY':
                    array_elements = self.parse_array_raw(obj['value'], obj['length'])
                    print(f"{prefix}  Array elements:")
                    for i, elem in enumerate(array_elements):
                        print(f"{prefix}    [{i}]: {elem}")
                        
                elif obj['type'] == 'STRING':
                    string_val = self.read_string_value(obj['value'], obj['length'])
                    print(f'{prefix}  Value: "{string_val}"')
                    
                elif obj['type'] == 'NAME':
                    name_val = self.read_name_value(obj['value'])
                    print(f'{prefix}  Value: /{name_val}')
                    
                elif obj['type'] == 'INTEGER':
                    print(f'{prefix}  Value: {obj["value"]}')
            else:
                print(f"{prefix}Error: {obj['error']}")
                    
        except Exception as e:
            print(f"{prefix}Error dumping object at {addr:#x}: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
    
    def invoke(self, arg, from_tty):
        args = arg.strip().split()
        if not args:
            print("Usage: ps-object <address> [debug|nodebug] [hex|nohex]")
            print("Example: ps-object 0xfffff33d60d0")
            print("         ps-object 0xfffff33d60d0 hex")
            print("         ps-object 0xfffff33d60d0 debug hex")
            return
        
        # Reset flags to defaults for each invocation
        self.debug = False
        self.hexdump = False
        
        # Parse flags
        for arg in args[1:]:
            if arg == "debug":
                self.debug = True
            elif arg == "nodebug":
                self.debug = False
            elif arg == "hex":
                self.hexdump = True
            elif arg == "nohex":
                self.hexdump = False
        
        try:
            # Parse address
            addr = int(args[0], 0)
            
            print(f"Dumping PostScript object at {addr:#x}")
            print("=" * 60)
            
            self.dump_object(addr)
            
        except ValueError:
            print(f"Invalid address: {args[0]}")
        except Exception as e:
            print(f"Error: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()

# Register command
PSObjectCommand()
print("PostScript object dumper loaded!")
print("Usage: ps-object <address> [debug|nodebug] [hex|nohex]")
print("Example: ps-object 0xfffff33d60d0 hex")