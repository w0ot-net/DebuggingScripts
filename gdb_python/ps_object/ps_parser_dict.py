#!/usr/bin/env python3
"""
Parser for PostScript dictionary objects
"""

import gdb
import struct
from ps_types import PS_TYPE_NAMES
from ps_parser_base import parse_stack_object
from ps_parser_string import read_string_value
from ps_parser_name import read_name_value

def parse_dictionary_raw(dict_ptr, debug=False):
    """Parse a raw dictionary structure
    
    Dictionary layout:
    0x00: marker (0x...4d00 in low bytes)
    0x08: zeros
    0x10: count info (live count in byte 0 of low dword)
    0x18: additional metadata (deleted count in low 16 bits, table params in high 16 bits)
    0x20-0x27: zeros
    0x28: first slot starts
    
    Each slot is 40 bytes (5 qwords):
    - Key metadata (8 bytes)
    - Key pointer (8 bytes)  
    - Value metadata (8 bytes)
    - Value pointer (8 bytes)
    - Slot state (8 bytes)
    
    Slot states:
    - 0x0000000000000002: occupied/active slot
    - 0x????????000?ff02: tombstone (deleted entry)
    - 0x0000000000000000: empty slot (if observed)
    """
    try:
        inferior = gdb.selected_inferior()
        
        # Read dictionary header
        dict_header = inferior.read_memory(dict_ptr, 0x28)
        
        # Check dictionary marker (low 4 bytes)
        marker = struct.unpack('<Q', dict_header[0:8])[0]
        if ((marker & 0xFFFFFFFF) & 0xFFFF) != 0x4d00:
            if debug:
                print(f"  DEBUG: Not a dict marker: {marker:#x}")
            return None
        
        # Get total slot count from offset 0x10
        count_field = struct.unpack('<Q', dict_header[0x10:0x18])[0]
        count_low = count_field & 0xFFFFFFFF
        total_slots = count_low & 0xFF
        capacity_or_growth = (count_low >> 16) & 0xFFFF
        
        # Get deleted count from offset 0x18 (low 16 bits)
        meta_field = struct.unpack('<Q', dict_header[0x18:0x20])[0]
        deleted_count = (meta_field & 0xFFFF) if meta_field else 0
        hash_param = (meta_field >> 16) & 0xFFFF if meta_field else 0
        
        # Calculate expected active entries
        expected_active = total_slots - deleted_count
        
        if total_slots == 0 or total_slots > 200:
            if debug:
                print(f"  DEBUG: Invalid total slots: {total_slots}")
            return None
        
        if debug:
            print(f"  DEBUG: Dictionary @ {dict_ptr:#x} has {total_slots} total slots, {deleted_count} deleted, expecting {expected_active} active")
        
        # Read enough data for all slots (40 bytes per slot)
        dict_size = min(16384, 0x28 + (total_slots * 40))
        dict_data = inferior.read_memory(dict_ptr, dict_size)
        
        entries = {}
        offset = 0x28
        entries_found = 0
        slots_scanned = 0
        
        # Define slot state constants
        SLOT_OCCUPIED = 0x0000000000000002
        SLOT_EMPTY = 0x0000000000000000
        
        # Scan slots until we find all expected active entries or run out of data
        while entries_found < expected_active and offset + 40 <= len(dict_data):
            # Each slot is 40 bytes (5 qwords)
            # Read the slot state first (it's at offset+32)
            slot_state = struct.unpack('<Q', dict_data[offset+32:offset+40])[0]
            
            if debug and slots_scanned < 20:  # Limit debug output
                print(f"    Slot {slots_scanned} @ {dict_ptr+offset:#x}: state={slot_state:#018x}")
            
            # Only process occupied slots
            if slot_state == SLOT_OCCUPIED:
                # Parse key object (first 16 bytes of slot)
                key_obj = parse_stack_object(dict_ptr + offset, debug)
                
                if 'error' in key_obj:
                    if debug:
                        print(f"    Error parsing key at slot {slots_scanned}")
                    offset += 40
                    slots_scanned += 1
                    continue
                
                # Parse value object (next 16 bytes of slot)
                value_obj = parse_stack_object(dict_ptr + offset + 16, debug)
                
                if 'error' in value_obj:
                    if debug:
                        print(f"    Error parsing value at slot {slots_scanned}")
                    offset += 40
                    slots_scanned += 1
                    continue
                
                # Format the key
                if key_obj['type'] == 'NAME':
                    key_str = read_name_value(key_obj['value'])
                elif key_obj['type'] == 'STRING':
                    key_str = f'({read_string_value(key_obj["value"], key_obj["length"])})'
                elif key_obj['type'] == 'INTEGER':
                    key_str = str(key_obj['value'])
                elif key_obj['type'] == 'ARRAY':
                    key_str = f'[array:{key_obj["length"]}@{key_obj["value"]:#x}]'
                elif key_obj['type'] == 'DICTIONARY':
                    key_str = f'<<dict:{key_obj["length"]}@{key_obj["value"]:#x}>>'
                else:
                    key_str = f'{key_obj["type"]}@{key_obj["value"]:#x}'
                
                # Store the entry with raw objects - formatting will be done by caller
                entries[key_str] = {
                    'key_obj': key_obj,
                    'obj': value_obj,
                    'formatted': None  # Will be formatted by the main module
                }
                
                if debug:
                    print(f"    Found entry {entries_found+1}: {key_str}")
                
                entries_found += 1
                
            elif slot_state == SLOT_EMPTY:
                if debug:
                    print(f"    Slot {slots_scanned}: empty")
            elif (slot_state & 0xFF00) == 0xFF00 or (slot_state & 0xFF02) == 0xFF02:
                # Tombstone pattern
                if debug:
                    print(f"    Slot {slots_scanned}: tombstone (deleted)")
            else:
                if debug:
                    print(f"    Slot {slots_scanned}: unknown state {slot_state:#018x}")
            
            offset += 40  # Move to next slot
            slots_scanned += 1
        
        if debug:
            print(f"  DEBUG: Scanned {slots_scanned} slots, found {entries_found} live entries")
        
        # Don't warn if we found the expected number based on total - deleted
        if entries_found != expected_active:
            print(f"  WARNING: Found {entries_found} entries but expected {expected_active} (total={total_slots}, deleted={deleted_count})")
        
        return entries
        
    except Exception as e:
        print(f"  ERROR in parse_dictionary_raw: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        return None