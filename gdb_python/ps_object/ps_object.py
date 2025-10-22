#!/usr/bin/env python3
"""
PostScript Object Dumper for GDB
Main module that provides the GDB command interface
"""

import sys
import os
import struct

# Add the directory containing this script to the Python path
# so we can import the other modules
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

import gdb
from ps_types import PS_TYPE_NAMES, get_ps_type_name, get_permissions
from ps_parser_base import parse_stack_object
from ps_parser_dict import parse_dictionary_raw
from ps_parser_array import parse_array_raw
from ps_parser_string import read_string_value
from ps_parser_name import read_name_value
from ps_hexdump import hexdump_dictionary

class PSObjectCommand(gdb.Command):
    """Recursively dump PostScript objects (dictionaries, arrays, etc.)"""
    
    def __init__(self):
        super(PSObjectCommand, self).__init__("ps-object", gdb.COMMAND_USER)
        self.debug = False
        self.hexdump = False
    
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
            string_val = read_string_value(obj['value'], obj['length'])
            return f"{type_str}: \"{string_val}\" @backing:{obj['value']:#x}{addr_str}"
        elif obj['type'] == 'NAME':
            name_val = read_name_value(obj['value'])
            return f"{type_str}: /{name_val} @backing:{obj['value']:#x}{addr_str}"
        elif obj['type'] == 'INTEGER':
            return f"{type_str}: {obj['value']}{addr_str}"
        elif obj['type'] == 'DICTIONARY':
            return f"{type_str}: <<{obj['length']} entries @backing:{obj['value']:#x}>>{addr_str}"
        elif obj['type'] == 'ARRAY':
            return f"{type_str}: [{obj['length']} items @backing:{obj['value']:#x}]{addr_str}"
        else:
            return f"{type_str}: @backing:{obj['value']:#x}{addr_str}"
    
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
            obj = parse_stack_object(addr, self.debug)
            
            if 'error' not in obj:
                # For dictionaries, get actual counts from the header
                if obj['type'] == 'DICTIONARY':
                    try:
                        inferior = gdb.selected_inferior()
                        dict_header = inferior.read_memory(obj['value'], 0x28)
                        count_field = struct.unpack('<Q', dict_header[0x10:0x18])[0]
                        total_slots = (count_field & 0xFF)
                        print(f"{prefix}DICTIONARY({obj['type_byte']:#x}): <<{total_slots} total slots @backing:{obj['value']:#x}>> @obj:{obj['address']:#x}")
                    except:
                        print(f"{prefix}{self.format_object(obj)}")
                else:
                    print(f"{prefix}{self.format_object(obj)}")
                
                print(f"{prefix}  Raw: {obj['raw_first']:#018x} {obj['value']:#018x}")
                print(f"{prefix}  Perms: {obj['perms']} ({obj['perms_raw']:#x}), Length: {obj['length']}")
                
                if obj['type'] == 'DICTIONARY':
                    dict_entries = parse_dictionary_raw(obj['value'], self.debug)
                    
                    if dict_entries:
                        # Show hex dump if requested
                        if self.hexdump and indent == 0:  # Only for top-level
                            hexdump_dictionary(obj['value'], dict_entries, self.debug)
                        
                        # Get the actual dictionary metadata for accurate reporting
                        inferior = gdb.selected_inferior()
                        dict_header = inferior.read_memory(obj['value'], 0x28)
                        
                        # Get counts from header
                        count_field = struct.unpack('<Q', dict_header[0x10:0x18])[0]
                        live_count = (count_field & 0xFF)
                        
                        meta_field = struct.unpack('<Q', dict_header[0x18:0x20])[0]
                        deleted_count = (meta_field & 0xFFFF) if meta_field else 0
                        
                        # Show accurate counts
                        print(f"{prefix}  Dictionary statistics:")
                        print(f"{prefix}    Total slots: {live_count} (includes active and tombstoned)")
                        print(f"{prefix}    Active entries: {len(dict_entries)}")
                        print(f"{prefix}    Deleted/tombstoned: {live_count - len(dict_entries)}")
                        
                        print(f"{prefix}  Dictionary entries ({len(dict_entries)} active):")
                        
                        # Dump all entries
                        for key, entry in dict_entries.items():
                            # Format the value using our format_object method
                            if entry['formatted'] is None:
                                entry['formatted'] = self.format_object(entry['obj'])
                            
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
                                key_display = f"/{key}"
                            
                            print(f"{prefix}    {key_display} => {entry['formatted']}")
                        
                        # Now show nested structures for all dictionary entries
                        for key, entry in dict_entries.items():
                            # Format key display
                            if 'key_obj' in entry:
                                key_type = entry['key_obj']['type']
                                if key_type == 'NAME':
                                    key_display = f"/{key}"
                                elif key_type == 'STRING':
                                    key_display = key
                                elif key_type == 'ARRAY':
                                    key_display = f"array-key"
                                else:
                                    key_display = key
                            else:
                                key_display = f"/{key}"
                                
                            if entry['obj']['type'] == 'DICTIONARY':
                                print(f"{prefix}    Expanding nested dictionary {key_display}:")
                                nested = parse_dictionary_raw(entry['obj']['value'], self.debug)
                                if nested:
                                    if len(nested) != entry['obj']['length']:
                                        print(f"{prefix}      WARNING: Expected {entry['obj']['length']} entries but found {len(nested)}!")
                                    
                                    for nkey, nvalue in nested.items():
                                        # Format nested value
                                        if nvalue['formatted'] is None:
                                            nvalue['formatted'] = self.format_object(nvalue['obj'])
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
                                            nested2 = parse_dictionary_raw(nvalue['obj']['value'], self.debug)
                                            if nested2:
                                                for n2key, n2value in nested2.items():
                                                    if n2value['formatted'] is None:
                                                        n2value['formatted'] = self.format_object(n2value['obj'])
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
                                            array_elements = parse_array_raw(nvalue['obj']['value'], nvalue['obj']['length'], self.format_object)
                                            for i, elem in enumerate(array_elements):
                                                print(f"{prefix}        [{i}]: {elem}")
                                                
                            elif entry['obj']['type'] == 'ARRAY':
                                print(f"{prefix}    Array {key_display}:")
                                array_elements = parse_array_raw(entry['obj']['value'], entry['obj']['length'], self.format_object)
                                for i, elem in enumerate(array_elements):
                                    print(f"{prefix}      [{i}]: {elem}")
                    else:
                        print(f"{prefix}  ERROR: Could not parse dictionary!")
                        
                elif obj['type'] == 'ARRAY':
                    array_elements = parse_array_raw(obj['value'], obj['length'], self.format_object)
                    print(f"{prefix}  Array elements:")
                    for i, elem in enumerate(array_elements):
                        print(f"{prefix}    [{i}]: {elem}")
                        
                elif obj['type'] == 'STRING':
                    string_val = read_string_value(obj['value'], obj['length'])
                    print(f'{prefix}  Value: "{string_val}"')
                    
                elif obj['type'] == 'NAME':
                    name_val = read_name_value(obj['value'])
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