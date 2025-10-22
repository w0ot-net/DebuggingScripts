#!/usr/bin/env python3
"""
Hex dump functionality for PostScript objects
"""

import gdb
import struct
from ps_parser_base import parse_stack_object
from ps_parser_string import read_string_value
from ps_parser_name import read_name_value

# ANSI color codes
COLORS = {
    'reset': '\033[0m',
    'header': '\033[95m',     # Magenta for dict header
    'padding': '\033[90m',    # Gray for padding
    'address': '\033[93m',    # Yellow for addresses
    'normal': '\033[0m'       # Reset
}

# Color pairs for key-value pairs (light/dark versions)
COLOR_PAIRS = [
    ('\033[38;5;209m', '\033[38;5;202m'),  # Light orange / Dark orange
    ('\033[38;5;117m', '\033[38;5;33m'),   # Light blue / Dark blue  
    ('\033[38;5;120m', '\033[38;5;28m'),   # Light green / Dark green
    ('\033[38;5;225m', '\033[38;5;165m'),  # Light pink / Dark pink
    ('\033[38;5;228m', '\033[38;5;136m'),  # Light yellow / Dark yellow
    ('\033[38;5;183m', '\033[38;5;97m'),   # Light purple / Dark purple
    ('\033[38;5;159m', '\033[38;5;30m'),   # Light cyan / Dark cyan
    ('\033[38;5;210m', '\033[38;5;124m'),  # Light red / Dark red
]

def format_object_simple(obj, show_addr=False):
    """Simple object formatter for hex dump annotations"""
    if 'error' in obj:
        return f"<error: {obj['error']}>"
    
    type_str = f"{obj['type']}({obj['type_byte']:#x})"
    
    if obj['type'] == 'STRING':
        string_val = read_string_value(obj['value'], obj['length'])
        return f"{type_str}: \"{string_val}\" @backing:0x..."
    elif obj['type'] == 'NAME':
        name_val = read_name_value(obj['value'])
        return f"{type_str}: /{name_val} @backing:0xfffff2d..."
    elif obj['type'] == 'INTEGER':
        return f"{type_str}: {obj['value']}"
    else:
        return f"{type_str}: @backing:0x..."

def hexdump_dictionary(dict_ptr, entries, debug=False):
    """Display a colorized hex dump of the dictionary with annotations
    
    Each slot is 40 bytes (5 qwords):
    - Key metadata (8 bytes)
    - Key pointer (8 bytes)
    - Value metadata (8 bytes)
    - Value pointer (8 bytes)
    - Slot state (8 bytes)
    """
    try:
        inferior = gdb.selected_inferior()
        
        print(f"\n{COLORS['address']}Hex dump of dictionary @ {dict_ptr:#x}:{COLORS['reset']}")
        print("-" * 80)
        
        # Mark regions in the hex dump
        regions = []
        pair_index = 0  # Track which color pair to use
        
        # Parse the dictionary header for detailed annotations
        dict_header = inferior.read_memory(dict_ptr, 0x28)
        
        # Parse header fields
        marker = struct.unpack('<Q', dict_header[0x00:0x08])[0]
        marker_low = marker & 0xFFFFFFFF
        
        count_field = struct.unpack('<Q', dict_header[0x10:0x18])[0]
        count_low = count_field & 0xFFFFFFFF
        total_slots = count_low & 0xFF
        capacity = (count_low >> 16) & 0xFFFF
        
        meta_field = struct.unpack('<Q', dict_header[0x18:0x20])[0]
        deleted_count = (meta_field & 0xFFFF) if meta_field else 0
        hash_param = (meta_field >> 16) & 0xFFFF if meta_field else 0
        
        # Calculate active entries
        expected_active = total_slots - deleted_count
        
        # Detailed header annotations
        regions.append((0x00, 0x08, 'header', f'Marker: {marker_low:#x} (dict signature)', None))
        regions.append((0x08, 0x10, 'header', f'Reserved/zeros', None))
        regions.append((0x10, 0x18, 'header', f'Slots: total={total_slots}, capacity/growth={capacity}', None))
        regions.append((0x18, 0x20, 'header', f'Meta: deleted={deleted_count}, hash_param={hash_param:#x}', None))
        regions.append((0x20, 0x28, 'header', f'Reserved/zeros', None))
        
        if total_slots == 0 or total_slots > 200:
            print(f"Invalid total slots: {total_slots}")
            return
        
        # Calculate size needed for all slots (40 bytes per slot)
        dict_size = min(16384, 0x28 + (total_slots * 40))
        dict_data = inferior.read_memory(dict_ptr, dict_size)
        
        # Define slot state constants  
        SLOT_OCCUPIED = 0x0000000000000002
        SLOT_EMPTY = 0x0000000000000000
        
        # Process slots and mark regions
        offset = 0x28
        slot_num = 0
        
        while offset + 40 <= len(dict_data) and slot_num < total_slots:
            # Read slot state (last qword of the 40-byte slot)
            slot_state = struct.unpack('<Q', dict_data[offset+32:offset+40])[0]
            
            if slot_state == SLOT_OCCUPIED:
                # Parse key and value for annotation
                key_obj = parse_stack_object(dict_ptr + offset)
                
                # Format key based on type
                if key_obj['type'] == 'NAME':
                    key_desc = f"/{read_name_value(key_obj['value'])}"
                elif key_obj['type'] == 'STRING':
                    key_desc = f"({read_string_value(key_obj['value'], key_obj['length'])})"
                elif key_obj['type'] == 'INTEGER':
                    key_desc = f"{key_obj['value']}"
                else:
                    key_desc = f"{key_obj['type']}"
                
                value_obj = parse_stack_object(dict_ptr + offset + 16)
                value_desc = format_object_simple(value_obj, show_addr=False)
                if len(value_desc) > 35:
                    value_desc = value_desc[:32] + "..."
                
                # Assign color pair for this slot
                color_pair = COLOR_PAIRS[pair_index % len(COLOR_PAIRS)]
                
                # Mark the regions - aligned properly
                regions.append((offset, offset+16, 'key', f'Slot {slot_num} Key: {key_desc}', color_pair[0]))
                regions.append((offset+16, offset+32, 'value', f'Slot {slot_num} Val: {value_desc}', color_pair[1]))
                regions.append((offset+32, offset+40, 'slot_state', f'Slot {slot_num} State: ACTIVE', None))
                
                pair_index += 1
                
            elif (slot_state & 0xFF00) == 0xFF00 or (slot_state & 0xFF02) == 0xFF02:
                # Tombstone slot - mark entire slot as tombstone
                regions.append((offset, offset+40, 'tombstone', f'Slot {slot_num}: TOMBSTONE (deleted, state={slot_state:#x})', None))
            elif slot_state == SLOT_EMPTY:
                # Empty slot
                regions.append((offset, offset+40, 'empty', f'Slot {slot_num}: EMPTY', None))
            else:
                # Unknown state
                regions.append((offset, offset+40, 'unknown', f'Slot {slot_num}: Unknown state {slot_state:#018x}', None))
            
            offset += 40
            slot_num += 1
        
        # Truncate dict_data to actual size used
        max_offset = offset
        dict_data = dict_data[:max_offset]
        
        # Print hex dump with colors - show as qwords in little-endian format
        for i in range(0, len(dict_data), 16):
            # Address
            print(f"{COLORS['address']}{dict_ptr+i:016x}:{COLORS['reset']} ", end="")
            
            # Two qwords per line
            for qword_idx in range(2):
                start_idx = i + (qword_idx * 8)
                if start_idx + 8 <= len(dict_data):
                    # Read 8 bytes and format as little-endian qword
                    qword_bytes = dict_data[start_idx:start_idx+8]
                    qword_val = struct.unpack('<Q', qword_bytes)[0]
                    
                    # Find color for this qword based on its start position
                    color = COLORS['normal']
                    annotation = ""
                    for start, end, region_type, desc, custom_color in regions:
                        if start <= start_idx < end:
                            if custom_color:
                                color = custom_color
                            elif region_type == 'tombstone':
                                color = '\033[91m'  # Red for tombstones
                            elif region_type == 'slot_state':
                                color = '\033[94m'  # Blue for slot state
                            elif region_type in COLORS:
                                color = COLORS[region_type]
                            annotation = desc
                            break
                    
                    print(f"{color}0x{qword_val:016x}{COLORS['reset']}", end="")
                else:
                    print(" " * 18, end="")
                
                # Add space between qwords
                if qword_idx == 0:
                    print(" ", end="")
            
            # Add annotation for this line - find the most relevant one
            best_annotation = None
            for start, end, region_type, desc, custom_color in regions:
                if start <= i < end:
                    best_annotation = (region_type, desc, custom_color)
                    break
            
            if best_annotation:
                region_type, desc, custom_color = best_annotation
                if custom_color:
                    print(f"  {custom_color}<-- {desc}{COLORS['reset']}", end="")
                elif region_type == 'tombstone':
                    print(f"  \033[91m<-- {desc}{COLORS['reset']}", end="")
                elif region_type == 'slot_state':
                    print(f"  \033[94m<-- {desc}{COLORS['reset']}", end="")
                else:
                    print(f"  {COLORS.get(region_type, COLORS['normal'])}<-- {desc}{COLORS['reset']}", end="")
            
            print()  # Newline
        
        print("-" * 80)
        
        # Print legend with color pairs
        print(f"\nLegend: {COLORS['header']}■ Header{COLORS['reset']} "
              f"\033[94m■ Slot State (ACTIVE){COLORS['reset']} "
              f"\033[91m■ Tombstone (DELETED){COLORS['reset']}")
        print("Key-Value pairs use rotating colors:")
        for i, (light, dark) in enumerate(COLOR_PAIRS[:4]):
            print(f"  Pair {i+1}: {light}■ Key{COLORS['reset']} {dark}■ Value{COLORS['reset']}", end="")
            if i == 1:
                print()
        if len(COLOR_PAIRS) > 4:
            print(f"\n  ... and {len(COLOR_PAIRS)-4} more color pairs")
        
        # Calculate actual statistics
        active_count = len(entries) if entries else 0
        tombstoned = total_slots - active_count
        
        print(f"\nDictionary Statistics:")
        print(f"  Total slots: {total_slots}")
        print(f"  Active entries: {expected_active}")
        print(f"  Tombstoned/deleted: {deleted_count}")
        print(f"  Hash parameter: {hash_param:#x} (likely free slot index or hash mask)")
        
    except Exception as e:
        print(f"Error creating hex dump: {e}")
        if debug:
            import traceback
            traceback.print_exc()