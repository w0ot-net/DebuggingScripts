#!/usr/bin/env python3
"""
IDA Pro GDB Sync Server Plugin
Receives cursor position updates from GDB via UDP
Place this file in your IDA plugins directory
"""

import ida_kernwin
import ida_idaapi
import idaapi
import ida_name
import json
import socket
import threading

# Global variables
server_thread = None
server_socket = None
server_running = False
config = {
    "ip": "0.0.0.0",
    "port": 4444,
    "module_name": ""
}

def udp_server():
    """UDP server thread function"""
    global server_socket, server_running
    
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.settimeout(1.0)  # Allow checking server_running periodically
        server_socket.bind((config["ip"], config["port"]))
        
        print(f"[GDB Sync] Server listening on {config['ip']}:{config['port']} for module '{config['module_name']}'")
        
        while server_running:
            try:
                data, addr = server_socket.recvfrom(1024)
                handle_message(data.decode('utf-8'), addr)
            except socket.timeout:
                continue
            except Exception as e:
                if server_running:
                    print(f"[GDB Sync] Error receiving data: {e}")
                
    except Exception as e:
        print(f"[GDB Sync] Failed to start server: {e}")
    finally:
        if server_socket:
            server_socket.close()
            server_socket = None
        print("[GDB Sync] Server stopped")

def handle_message(data, addr):
    """Handle incoming UDP message"""
    try:
        msg = json.loads(data)
        module_name = msg.get("module_name", "")
        offset_str = msg.get("offset", "")
        
        if module_name != config["module_name"]:
            print(f"[GDB Sync] Received request for non-matching module: '{module_name}' (expected: '{config['module_name']}')")
            # Send error response
            response = json.dumps({"status": "ERROR", "message": f"Module mismatch: expected {config['module_name']}"})
            server_socket.sendto(response.encode('utf-8'), addr)
            return
            
        # Parse offset (handle both "0x1234" and "1234" formats)
        offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str, 16)
        
        # Jump to address in IDA (thread-safe) - must be done in main thread
        def jump():
            try:
                # Get image base
                image_base = idaapi.get_imagebase()
                target_ea = image_base + offset
                
                # Jump to the address
                ida_kernwin.jumpto(target_ea)
                
                # Log where we moved the cursor
                func = idaapi.get_func(target_ea)
                if func:
                    func_name = ida_name.get_name(func.start_ea) or f"sub_{func.start_ea:X}"
                else:
                    func_name = ida_name.get_name(target_ea) or f"loc_{target_ea:X}"
                
                print(f"[GDB Sync] Moved cursor to {hex(target_ea)} (base: {hex(image_base)} + offset: {hex(offset)}) in {func_name}")
                
                # Send OK response after successful jump
                response = json.dumps({"status": "OK"})
                server_socket.sendto(response.encode('utf-8'), addr)
            except Exception as e:
                print(f"[GDB Sync] Error jumping to address: {e}")
                response = json.dumps({"status": "ERROR", "message": str(e)})
                server_socket.sendto(response.encode('utf-8'), addr)
        
        # Execute in main thread - use MFF_FAST for immediate execution
        ida_kernwin.execute_sync(jump, ida_kernwin.MFF_FAST)
        
    except json.JSONDecodeError:
        print(f"[GDB Sync] Invalid JSON received from {addr}: {data}")
        try:
            response = json.dumps({"status": "ERROR", "message": "Invalid JSON"})
            server_socket.sendto(response.encode('utf-8'), addr)
        except:
            pass
    except Exception as e:
        print(f"[GDB Sync] Error handling message: {e}")
        try:
            response = json.dumps({"status": "ERROR", "message": str(e)})
            server_socket.sendto(response.encode('utf-8'), addr)
        except:
            pass

def start_server():
    """Start the UDP server"""
    global server_thread, server_running
    
    if not config["module_name"]:
        ida_kernwin.warning("Module name is required to start the server")
        return False
    
    if server_running:
        print("[GDB Sync] Server is already running")
        return False
    
    server_running = True
    server_thread = threading.Thread(target=udp_server)
    server_thread.daemon = True
    server_thread.start()
    return True

def stop_server():
    """Stop the UDP server"""
    global server_running, server_thread
    
    if not server_running:
        print("[GDB Sync] Server is not running")
        return False
    
    server_running = False
    if server_thread:
        server_thread.join(timeout=2)
        server_thread = None
    return True

def show_config_dialog():
    """Show configuration dialog with all options"""
    global config
    
    # Build the input form string
    form_str = """STARTITEM 0
GDB Sync Server Configuration

<IP Address:{txtIP}>
<Port      :{txtPort}>
<Module Name:{txtModule}>

Server Status: %s

<Start Server:{btnStart}> <Stop Server:{btnStop}>
""" % ("RUNNING" if server_running else "STOPPED")
    
    # Setup the form
    class ConfigForm(ida_kernwin.Form):
        def __init__(self):
            # Initialize form with template and controls dict
            ida_kernwin.Form.__init__(self, form_str, {
                'txtIP': ida_kernwin.Form.StringInput(swidth=20, value=config["ip"]),
                'txtPort': ida_kernwin.Form.StringInput(swidth=10, value=str(config["port"])),
                'txtModule': ida_kernwin.Form.StringInput(swidth=30, value=config["module_name"]),
                'btnStart': ida_kernwin.Form.ButtonInput(self.OnStart),
                'btnStop': ida_kernwin.Form.ButtonInput(self.OnStop)
            })
        
        def OnStart(self, code=0):
            # Update config from form values
            config["ip"] = self.GetControlValue(self.txtIP) or "127.0.0.1"
            try:
                config["port"] = int(self.GetControlValue(self.txtPort))
            except ValueError:
                ida_kernwin.warning("Invalid port number")
                return 1
            config["module_name"] = self.GetControlValue(self.txtModule)
            
            # Start the server
            if start_server():
                ida_kernwin.info(f"Server started on {config['ip']}:{config['port']} for module '{config['module_name']}'")
                self.Close(1)
            return 1
        
        def OnStop(self, code=0):
            if stop_server():
                ida_kernwin.info("Server stopped")
                self.Close(1)
            return 1
    
    # Show the form
    form = ConfigForm()
    form.Compile()
    form.Execute()
    form.Free()

# Plugin class for IDA
class GdbSyncPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Sync cursor position with GDB"
    help = "Receives cursor position updates from GDB debugger"
    wanted_name = "GDB Sync Server"
    wanted_hotkey = "Ctrl+Shift+G"
    
    def init(self):
        """Initialize plugin"""
        print(f"[GDB Sync] Plugin loaded. Use {self.wanted_hotkey} or Edit->Plugins->GDB Sync Server")
        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        """Run plugin"""
        show_config_dialog()
    
    def term(self):
        """Cleanup on plugin unload"""
        global server_running
        if server_running:
            print("[GDB Sync] Stopping server...")
            stop_server()
    
    class ActionHandler(ida_kernwin.action_handler_t):
        def activate(self, ctx):
            show_config_dialog()
            return 1
        
        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

# Plugin entry point
def PLUGIN_ENTRY():
    return GdbSyncPlugin()