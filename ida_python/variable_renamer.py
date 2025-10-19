"""
IDA Pro Variable & Function Renamer Plugin

INSTALLATION:
1. Save this file as 'var_renamer.py' in IDA's plugins directory:
   - Windows: C:\Program Files\IDA Pro X.X\plugins\
   - Linux: /opt/idapro-X.X/plugins/
   - Mac: /Applications/IDA Pro X.X/ida64.app/Contents/MacOS/plugins/

2. Restart IDA or use Plugins → Reload plugins

3. The functions will be automatically available in the Python console!
"""

import ida_funcs
import ida_name
import ida_hexrays
import ida_kernwin
import idaapi
import idautils
import idc
from typing import Dict

def renamer_usage():
    """
    Display usage instructions for the variable and function renamer.
    Call this function anytime in the IDA Python console to see how to use the renamer.
    """
    print("=" * 70)
    print("IDA Pro Variable & Function Renamer - Usage Instructions")
    print("=" * 70)
    print()
    print("AVAILABLE FUNCTIONS:")
    print("-" * 70)
    print()
    print("1. rename_function(old_name, new_name)")
    print("   Rename a function in the database")
    print()
    print("2. rename_function_variables(func_name, rename_map)")
    print("   Rename multiple variables within a function")
    print()
    print("3. rename_function_and_vars(old_func_name, new_func_name, rename_map)")
    print("   Rename both the function and its variables in one call")
    print()
    print("4. rename_global(old_name, new_name)")
    print("   Rename a global variable or data label in the database")
    print()
    print("PARAMETERS:")
    print("-" * 70)
    print("  old_name/func_name : String - Current function/global name")
    print("  new_name          : String - New function/global name")
    print("  rename_map        : Dict   - Dictionary mapping old variable names to new names")
    print()
    print("NAMING CONVENTION (STRONGLY RECOMMENDED):")
    print("-" * 70)
    print("★ For functions: ALWAYS keep the original address as a suffix!")
    print("  do not rename functions that already have a meaningful name. only rename functions with a name similar to `sub_1234`")
    print("  Format: <descriptive_name>_<original_name>")
    print("  Examples:")
    print("    sub_401000 -> parse_config_file_sub_401000")
    print("    sub_C060   -> serve_language_js_sub_C060")
    print("    sub_1C3D0  -> handle_sysinfo_request_sub_1C3D0")
    print("  WHY: Preserves the original address for reference and debugging")
    print()
    print("★ For local variables: Keep the original name as a suffix")
    print("  Format: <descriptive_name>_<original_name>")
    print("  Examples: counter_v4, buffer_v8, user_input_v1, input_param_a1")
    print()
    print("★ For global variables: Keep the original address/name as a suffix")
    print("  Format: <descriptive_name>_<original_name>")
    print("  Examples:")
    print("    dword_404020 -> config_flags_dword_404020")
    print("    unk_405120   -> encryption_key_unk_405120")
    print("    byte_406000  -> initialized_flag_byte_406000")
    print("    aHelloWorld  -> greeting_string_aHelloWorld")
    print()
    print("EXAMPLES:")
    print("-" * 70)
    print()
    print("1. Rename a function (with original name preserved):")
    print('   rename_function("sub_401000", "parse_config_file_sub_401000")')
    print()
    print("2. Rename variables in a function:")
    print('   rename_function_variables("parse_config_file_sub_401000", {')
    print('       "v1": "config_buffer_v1",')
    print('       "v2": "file_size_v2",')
    print('       "a1": "filename_a1"')
    print('   })')
    print()
    print("3. Rename both function and variables at once:")
    print('   rename_function_and_vars("sub_401000", "parse_config_file_sub_401000", {')
    print('       "v1": "config_buffer_v1",')
    print('       "v2": "file_size_v2",')
    print('       "a1": "filename_a1"')
    print('   })')
    print()
    print("4. Rename a global variable:")
    print('   rename_global("dword_404020", "config_flags_dword_404020")')
    print('   rename_global("unk_405120", "encryption_key_unk_405120")')
    print('   rename_global("aHelloWorld", "greeting_string_aHelloWorld")')
    print()
    print("5. Complete workflow example:")
    print('   # First rename the function (keeping original suffix)')
    print('   rename_function("sub_C060", "serve_language_javascript_file_sub_C060")')
    print('   ')
    print('   # Then rename its variables')
    print('   rename_function_variables("serve_language_javascript_file_sub_C060", {')
    print('       "a1": "cgi_params_a1",')
    print('       "v1": "accept_lang_result_v1",')
    print('       "v2": "f_param_v2",')
    print('       "v3": "f_value_v3"')
    print('   })')
    print('   ')
    print('   # Also rename any related globals')
    print('   rename_global("dword_404020", "server_config_flags_dword_404020")')
    print()
    print("TIPS:")
    print("-" * 70)
    print("• Names are case-sensitive")
    print("• Use the decompiler view (F5) to see current variable names")
    print("• The plugin refreshes the decompiler view automatically after renaming")
    print("• Check the console output for detailed debug information")
    print("• Both local variables and function arguments can be renamed")
    print("• Function and global names must be unique in the database")
    print("• Keeping original names helps track addresses and variable origins")
    print("• Global variables can be data labels, strings, or any named location")
    print()
    print("TROUBLESHOOTING:")
    print("-" * 70)
    print("• 'Function not found' - Check the exact function name")
    print("• 'Global not found' - Check the exact global variable name")
    print("• 'Name already exists' - Choose a different name")
    print("• 'Hex-Rays not available' - Ensure you have the decompiler plugin")
    print("• 'Failed to rename' - Variable name might not exist or be invalid")
    print()
    print("To see this help again, just run: renamer_usage()")
    print("=" * 70)

def rename_function(old_name: str, new_name: str) -> bool:
    """
    Rename a function in the IDA database.
    
    Args:
        old_name: Current name of the function
        new_name: New name for the function (should include original as suffix)
        
    Returns:
        True if successful, False otherwise
        
    Example:
        rename_function("sub_401000", "parse_config_file_sub_401000")
    """
    print(f"[DEBUG] Attempting to rename function: {old_name} -> {new_name}")
    
    # Get function address by old name
    func_ea = ida_name.get_name_ea(idaapi.BADADDR, old_name)
    if func_ea == idaapi.BADADDR:
        print(f"[ERROR] Function '{old_name}' not found in database")
        return False
    
    print(f"[DEBUG] Function found at address: 0x{func_ea:X}")
    
    # Check if new name already exists
    if ida_name.get_name_ea(idaapi.BADADDR, new_name) != idaapi.BADADDR:
        print(f"[ERROR] Name '{new_name}' already exists in database")
        return False
    
    # Rename the function
    if idc.set_name(func_ea, new_name, idc.SN_CHECK):
        print(f"[SUCCESS] Renamed function: {old_name} -> {new_name}")
        
        # Refresh the UI
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
        ida_kernwin.request_refresh(ida_kernwin.IWID_FUNCS)
        
        return True
    else:
        print(f"[ERROR] Failed to rename function {old_name} to {new_name}")
        return False

def rename_global(old_name: str, new_name: str) -> bool:
    """
    Rename a global variable or data label in the IDA database.
    
    Args:
        old_name: Current name of the global variable
        new_name: New name for the global variable (should include original as suffix)
        
    Returns:
        True if successful, False otherwise
        
    Example:
        rename_global("dword_404020", "config_flags_dword_404020")
        rename_global("unk_405120", "encryption_key_unk_405120")
        rename_global("aHelloWorld", "greeting_string_aHelloWorld")
    """
    print(f"[DEBUG] Attempting to rename global: {old_name} -> {new_name}")
    
    # Get address by old name
    ea = ida_name.get_name_ea(idaapi.BADADDR, old_name)
    if ea == idaapi.BADADDR:
        print(f"[ERROR] Global '{old_name}' not found in database")
        return False
    
    print(f"[DEBUG] Global found at address: 0x{ea:X}")
    
    # Check what type of location this is
    flags = idc.get_full_flags(ea)
    if idc.is_code(flags) and ida_funcs.get_func(ea):
        print(f"[WARNING] '{old_name}' appears to be a function, not a global variable")
        print(f"[WARNING] Use rename_function() instead for functions")
        return False
    
    # Check if new name already exists
    if ida_name.get_name_ea(idaapi.BADADDR, new_name) != idaapi.BADADDR:
        print(f"[ERROR] Name '{new_name}' already exists in database")
        return False
    
    # Determine the type of global for better logging
    global_type = "unknown"
    if idc.is_strlit(flags):
        global_type = "string"
    elif idc.is_data(flags):
        item_size = idc.get_item_size(ea)
        if item_size == 1:
            global_type = "byte"
        elif item_size == 2:
            global_type = "word"  
        elif item_size == 4:
            global_type = "dword"
        elif item_size == 8:
            global_type = "qword"
        else:
            global_type = f"data ({item_size} bytes)"
    elif idc.is_unknown(flags):
        global_type = "unknown/uninitialized"
    elif idc.is_code(flags):
        global_type = "code"
    
    print(f"[DEBUG] Global type: {global_type}")
    
    # Rename the global
    if idc.set_name(ea, new_name, idc.SN_CHECK):
        print(f"[SUCCESS] Renamed global {global_type}: {old_name} -> {new_name}")
        
        # Refresh the UI
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
        ida_kernwin.request_refresh(ida_kernwin.IWID_NAMES)
        
        # If a decompiler view is open, refresh it too
        vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if vdui:
            vdui.refresh_view(True)
            print("[DEBUG] Refreshed decompiler view")
        
        return True
    else:
        print(f"[ERROR] Failed to rename global {old_name} to {new_name}")
        return False

def rename_function_variables(func_name: str, rename_map: Dict[str, str]) -> bool:
    """
    Rename variables in a function based on the provided mapping.
    
    Args:
        func_name: Name of the function to process
        rename_map: Dictionary mapping old variable names to new names
        
    Returns:
        True if successful, False otherwise
        
    Example:
        rename_function_variables("main", {"v4": "counter_v4", "v8": "buffer_v8"})
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

def rename_function_and_vars(old_func_name: str, new_func_name: str, rename_map: Dict[str, str]) -> bool:
    """
    Rename both a function and its variables in one operation.
    
    Args:
        old_func_name: Current name of the function
        new_func_name: New name for the function (should include original as suffix)
        rename_map: Dictionary mapping old variable names to new names
        
    Returns:
        True if both operations succeeded, False otherwise
        
    Example:
        rename_function_and_vars("sub_401000", "parse_config_sub_401000", 
                                {"v1": "buffer_v1", "v2": "size_v2"})
    """
    print(f"[INFO] Starting combined rename operation")
    print(f"[INFO] Function: {old_func_name} -> {new_func_name}")
    print(f"[INFO] Variables: {rename_map}")
    
    # First rename the function
    func_renamed = rename_function(old_func_name, new_func_name)
    
    if not func_renamed:
        print("[ERROR] Function rename failed, aborting variable rename")
        return False
    
    # Then rename variables using the new function name
    vars_renamed = rename_function_variables(new_func_name, rename_map)
    
    if func_renamed and vars_renamed:
        print("[SUCCESS] Both function and variables renamed successfully")
        return True
    elif func_renamed:
        print("[PARTIAL] Function renamed but variable rename had issues")
        return False
    else:
        return False

# Plugin class required for IDA to recognize this as a plugin
class VarRenamerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE
    comment = "Variable & Function Renamer Plugin - Provides renamer functions in console"
    help = "Run renamer_usage() in the Python console for help"
    wanted_name = "Variable & Function Renamer"
    wanted_hotkey = ""

    def init(self):
        """Initialize plugin - inject functions into global namespace"""
        # Make functions available globally in the Python console
        import sys
        if sys.version_info[0] >= 3:
            import builtins
        else:
            import __builtin__ as builtins
        
        builtins.rename_function = rename_function
        builtins.rename_global = rename_global
        builtins.rename_function_variables = rename_function_variables
        builtins.rename_function_and_vars = rename_function_and_vars
        builtins.renamer_usage = renamer_usage
        
        # Print success message
        print("=" * 70)
        print("IDA Pro Variable & Function Renamer Plugin Loaded!")
        print("Available functions in Python console:")
        print("  • renamer_usage()  - Show usage instructions")
        print("  • rename_function(old_name, new_name) - Rename a function")
        print("  • rename_global(old_name, new_name) - Rename a global variable")
        print("  • rename_function_variables(func_name, rename_map) - Rename variables")
        print("  • rename_function_and_vars(old, new, map) - Rename both")
        print()
        print("REMEMBER: Keep original names as suffixes!")
        print("  Functions: sub_401000 -> parse_config_sub_401000")
        print("  Globals: dword_404020 -> config_flags_dword_404020")
        print("  Variables: v1 -> config_buffer_v1")
        print("=" * 70)
        
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Run plugin - not used since we want console functions"""
        renamer_usage()

    def term(self):
        """Terminate plugin"""
        pass

# REQUIRED: This function is called by IDA to register the plugin
def PLUGIN_ENTRY():
    return VarRenamerPlugin()