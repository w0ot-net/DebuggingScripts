#!/usr/bin/env python3
"""
GDB Sync Client
Sends current execution position to IDA Pro via UDP whenever execution pauses
"""

import gdb
import json
import socket

# Global configuration
sync_config = {
    "enabled": False,
    "ip": "",
    "port": 0,
    "module_name": ""
}

class SyncStopHandler:
    """Handler that sends position when GDB stops"""
    
    def __init__(self):
        gdb.events.stop.connect(self.on_stop)
    
    def on_stop(self, event):
        """Called whenever GDB stops (breakpoint, step, etc.)"""
        if not sync_config["enabled"]:
            return
        
        try:
            # Get current PC
            frame = gdb.selected_frame()
            pc = frame.pc()
            
            # Find the module base address
            module_base = self.get_module_base(sync_config["module_name"])
            if module_base is None:
                # Don't spam the console - module not found message already printed by get_module_base
                return
            
            # Calculate offset
            offset = pc - module_base
            
            # Send to IDA
            self.send_position(offset)
            
        except Exception as e:
            print(f"[GDB Sync] Error: {e}")
    
    def get_module_base(self, module_name):
        """Get base address of a loaded module using info proc mapping"""
        try:
            # Use info proc mapping to get memory mappings
            mappings = gdb.execute("info proc mapping", to_string=True)
            
            # Find the first executable mapping for our module
            for line in mappings.split('\n'):
                if module_name in line:
                    # Parse lines that look like:
                    # 0x555555554000     0x555555573000    0x1f000        0x0 /path/to/scsi_plugin_server
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0].startswith("0x"):
                        base = int(parts[0], 16)
                        print(f"[GDB Sync] Found module '{module_name}' at base {hex(base)}")
                        return base
            
            # If not found by name, try to get the main executable base
            # Look for the first executable mapping (usually the main binary)
            for line in mappings.split('\n'):
                # Look for the first mapped region with executable permissions
                if "0x" in line and len(line.strip().split()) >= 5:
                    parts = line.strip().split()
                    if parts[0].startswith("0x") and not "ld-" in line and not ".so" in line:
                        # This might be our main executable
                        path = " ".join(parts[4:]) if len(parts) > 4 else ""
                        if "/" in path and not "[" in path:  # Actual file path, not [vdso] etc
                            base = int(parts[0], 16)
                            print(f"[GDB Sync] Using main executable base {hex(base)} (found: {path})")
                            return base
                            
        except Exception as e:
            print(f"[GDB Sync] Error getting module base: {e}")
        
        print(f"[GDB Sync] Could not find module '{module_name}' base address")
        return None
    
    def send_position(self, offset):
        """Send position to IDA via UDP and receive response"""
        try:
            # Create message
            msg = {
                "module_name": sync_config["module_name"],
                "offset": hex(offset)
            }
            
            # Create socket with timeout for response
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)  # 500ms timeout for response
            
            # Send UDP packet
            sock.sendto(json.dumps(msg).encode('utf-8'), 
                       (sync_config["ip"], sync_config["port"]))
            
            # Try to receive response
            try:
                response_data, _ = sock.recvfrom(1024)
                response = json.loads(response_data.decode('utf-8'))
                
                if response.get("status") == "OK":
                    print(f"[GDB Sync] IDA acknowledged - moved to offset {hex(offset)}")
                else:
                    print(f"[GDB Sync] IDA response: {response}")
            except socket.timeout:
                print(f"[GDB Sync] Sent offset {hex(offset)} (no response from IDA)")
            except json.JSONDecodeError:
                print(f"[GDB Sync] Invalid response from IDA")
            
            sock.close()
            
        except Exception as e:
            print(f"[GDB Sync] Failed to send position: {e}")

class GdbSyncCommand(gdb.Command):
    """GDB command to configure sync client"""
    
    def __init__(self):
        super().__init__("gdb_sync", gdb.COMMAND_USER)
        self.stop_handler = SyncStopHandler()
    
    def invoke(self, args, from_tty):
        """Handle gdb_sync command"""
        parts = args.split()
        
        if len(parts) == 0:
            # Show status
            if sync_config["enabled"]:
                print(f"[GDB Sync] Active: {sync_config['ip']}:{sync_config['port']} (module: {sync_config['module_name']})")
            else:
                print("[GDB Sync] Inactive. Usage: gdb_sync <ip> <port> <module_name>")
                print("                     Or: gdb_sync off")
                print("                     Or: gdb_sync test")
            return
        
        if len(parts) == 1 and parts[0].lower() == "off":
            # Disable sync
            sync_config["enabled"] = False
            print("[GDB Sync] Disabled")
            return
        
        if len(parts) == 1 and parts[0].lower() == "test":
            # Test current configuration
            if not sync_config["module_name"]:
                print("[GDB Sync] No module configured. Use: gdb_sync <ip> <port> <module_name>")
                return
            
            print(f"[GDB Sync] Testing module '{sync_config['module_name']}'...")
            base = self.stop_handler.get_module_base(sync_config["module_name"])
            if base:
                print(f"[GDB Sync] Found module base: {hex(base)}")
                # Get current PC and calculate offset
                try:
                    pc = gdb.selected_frame().pc()
                    offset = pc - base
                    print(f"[GDB Sync] Current PC: {hex(pc)}, Offset: {hex(offset)}")
                    if sync_config["enabled"]:
                        self.stop_handler.send_position(offset)
                except:
                    print("[GDB Sync] Could not get current PC")
            else:
                print(f"[GDB Sync] Module '{sync_config['module_name']}' not found!")
                print("[GDB Sync] Try using just the binary name without path")
            return
        
        if len(parts) != 3:
            print("[GDB Sync] Usage: gdb_sync <ip> <port> <module_name>")
            print("              Or: gdb_sync off")
            print("              Or: gdb_sync test")
            return
        
        # Configure and enable
        try:
            sync_config["ip"] = parts[0]
            sync_config["port"] = int(parts[1])
            sync_config["module_name"] = parts[2]
            sync_config["enabled"] = True
            
            print(f"[GDB Sync] Enabled: {sync_config['ip']}:{sync_config['port']} (module: {sync_config['module_name']})")
            
            # Test if we can find the module
            base = self.stop_handler.get_module_base(sync_config["module_name"])
            if base:
                print(f"[GDB Sync] Module found at base: {hex(base)}")
            else:
                print(f"[GDB Sync] WARNING: Module '{sync_config['module_name']}' not found!")
                print("[GDB Sync] The sync will try to find it on each stop event")
            
            print("[GDB Sync] Position will be sent to IDA on every stop event")
            
        except ValueError:
            print("[GDB Sync] Error: Port must be a number")

# Register the command when script loads
print("[GDB Sync Client] Loading...")
GdbSyncCommand()
print("[GDB Sync Client] Ready. Use 'gdb_sync <ip> <port> <module_name>' to start")
print("                   Use 'gdb_sync off' to stop")
print("                   Use 'gdb_sync test' to test module detection")
print("                   Use 'gdb_sync' to show status")