"""
IDA Pro Variable Renamer
Renames variables in a specified function based on a mapping dictionary.
"""

import ida_funcs
import ida_name
import ida_hexrays
import idaapi
from typing import Dict

def rename_function_variables(func_name: str, rename_map: Dict[str, str]) -> bool:
    """
    Rename variables in a function based on the provided mapping.
    
    Args:
        func_name: Name of the function to process
        rename_map: Dictionary mapping old variable names to new names
        
    Returns:
        True if successful, False otherwise
        
    Example:
        rename_function_variables("main", {"v4": "counter", "v8": "buffer"})
    """
    renamed_count = 0
    errors = []
    
    print(f"[DEBUG] Starting rename for function: {func_name}")
    print(f"[DEBUG] Rename map: {rename_map}")
    
    # Get function address by name
    func_ea = ida_name.get_name_ea(idaapi.BADADDR, func_name)
    if func_ea == idaapi.BADADDR:
        print(f"[ERROR] Function '{func_name}' not found in database")
        return False
    
    print(f"[DEBUG] Function found at address: 0x{func_ea:X}")
    
    # Get function object
    func = ida_funcs.get_func(func_ea)
    if not func:
        print(f"[ERROR] Could not get function object for '{func_name}'")
        return False
    
    print(f"[DEBUG] Function object retrieved: 0x{func.start_ea:X} - 0x{func.end_ea:X}")
    
    # Check if Hex-Rays is available
    if not idaapi.init_hexrays_plugin():
        print("[ERROR] Hex-Rays decompiler not available")
        return False
    
    print("[DEBUG] Hex-Rays decompiler initialized")
    
    # Get decompiled function
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            print("[ERROR] Failed to decompile function")
            return False
    except Exception as e:
        print(f"[ERROR] Decompilation error: {str(e)}")
        return False
    
    print("[DEBUG] Function successfully decompiled")
    
    # Get local variable information
    lvars = cfunc.get_lvars()
    print(f"[DEBUG] Found {len(lvars)} local variables")
    
    # Print all variables for debugging
    for i, lvar in enumerate(lvars):
        print(f"[DEBUG] Variable {i}: name='{lvar.name}', type='{lvar.type()}', is_arg={lvar.is_arg_var}")
    
    # Process each variable
    for i in range(len(lvars)):
        lvar = lvars[i]
        old_name = lvar.name
        
        if old_name in rename_map:
            new_name = rename_map[old_name]
            print(f"[DEBUG] Attempting to rename '{old_name}' -> '{new_name}'")
            
            # Create lvar_saved_info_t for the modification
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = ida_hexrays.lvar_locator_t()
            lsi.ll.location = lvar.location
            lsi.ll.defea = lvar.defea
            lsi.name = new_name
            
            print(f"[DEBUG] lvar_locator: location={lvar.location}, defea=0x{lvar.defea:X}")
            
            # Try to modify the variable name
            if ida_hexrays.modify_user_lvar_info(func.start_ea, ida_hexrays.MLI_NAME, lsi):
                renamed_count += 1
                print(f"[SUCCESS] Renamed: {old_name} -> {new_name}")
            else:
                errors.append(f"Failed to rename {old_name} to {new_name}")
                print(f"[ERROR] Failed to rename {old_name} to {new_name}")
    
    # Refresh decompiler view if any variables were renamed
    if renamed_count > 0:
        print(f"[DEBUG] Refreshing decompiler view")
        # Get current vdui (view decompiler UI) and refresh it
        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if vdui:
            vdui.refresh_view(True)
        else:
            print("[DEBUG] No decompiler view open to refresh")
    
    print(f"[DEBUG] Rename operation complete. {renamed_count} variables renamed")
    
    # Print summary
    print(f"\n[SUMMARY] Renamed {renamed_count} variable(s)")
    if errors:
        print("[SUMMARY] Errors:")
        for error in errors:
            print(f"  - {error}")
    
    return renamed_count > 0