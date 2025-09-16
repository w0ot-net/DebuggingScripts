#!/usr/bin/env python
# -*- coding: ascii -*-
#
# Restart a remote systemd service, attach gdbserver, and connect with local gdb.
# OR attach directly to a specified PID without restarting any service.
# Python 2.7 / 3.x compatible.
# Enhanced with special PID selection strategy for syncd

from __future__ import print_function
import argparse
import atexit
import logging
import os
import signal
import subprocess
import sys
import time
import tempfile

def setup_logging(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%%Y-%%m-%%d %%H:%%M:%%S".replace("%%", "%"))

def to_text(s):
    if s is None:
        return ""
    if isinstance(s, bytes):
        try:
            return s.decode("utf-8", "replace")
        except Exception:
            return s.decode("latin-1", "replace")
    return s

def run(cmd, capture=False, check=True):
    logging.debug("RUN: %s", " ".join(cmd))
    if capture:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        rc = p.returncode
        out_s = to_text(out)
        err_s = to_text(err)
        if err_s.strip():
            logging.debug("stderr: %s", err_s.strip())
        if rc != 0 and check:
            logging.error("Command failed (rc=%d): %s", rc, " ".join(cmd))
            raise subprocess.CalledProcessError(rc, cmd, out_s)
        return out_s
    else:
        rc = subprocess.call(cmd)
        if rc != 0 and check:
            logging.error("Command failed (rc=%d): %s", rc, " ".join(cmd))
            raise subprocess.CalledProcessError(rc, cmd)
        return ""

def ssh_base_cmd(key_path):
    return [
        "ssh",
        "-i", key_path,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
    ]

def ssh_run(host, user, key_path, remote_cmd, capture=False, check=True):
    cmd = ssh_base_cmd(key_path) + [user + "@" + host, remote_cmd]
    logging.debug("SSH RUN on %s: %s", host, remote_cmd)
    return run(cmd, capture=capture, check=check)

def restart_unit(host, user, key_path, unit):
    logging.info("Restarting unit: %s", unit)
    ssh_run(host, user, key_path, "systemctl restart {0}".format(unit), capture=False, check=True)

def get_main_pid(host, user, key_path, unit):
    """
    Robustly obtain MainPID for a unit on systems where:
      - 'systemctl show -p MainPID --value' is unsupported, or
      - only 'systemctl show -p MainPID' exists, or
      - only 'systemctl status' output is available.
    """
    # Try 1: systemctl show -p MainPID --value
    cmd1 = "systemctl show -p MainPID --value {0}".format(unit)
    logging.debug("Get MainPID: trying: %s", cmd1)
    out = ssh_run(host, user, key_path, cmd1 + " 2>/dev/null || true", capture=True, check=False).strip()
    logging.debug("Result1: %r", out)
    if out.isdigit() and out not in ("", "0"):
        return out

    # Try 2: systemctl show -p MainPID (parse MainPID=NNN)
    cmd2 = "systemctl show -p MainPID {0}".format(unit)
    logging.debug("Get MainPID: trying: %s", cmd2)
    out = ssh_run(host, user, key_path, cmd2 + " 2>/dev/null || true", capture=True, check=False)
    logging.debug("Result2 raw: %r", out)
    for line in to_text(out).splitlines():
        if line.startswith("MainPID="):
            val = line.split("=", 1)[1].strip()
            logging.debug("Parsed MainPID= %r", val)
            if val.isdigit() and val not in ("", "0"):
                return val
            break

    # Try 3: systemctl status (parse 'Main PID: NNN')
    cmd3 = "systemctl --no-pager status {0}".format(unit)
    logging.debug("Get MainPID: trying: %s", cmd3)
    out = ssh_run(host, user, key_path, cmd3 + " 2>/dev/null || true", capture=True, check=False)
    logging.debug("Result3 raw: %r", out)
    for line in to_text(out).splitlines():
        # Accept both 'Main PID:' and 'MainPID:' variants, extract first integer
        if "Main PID:" in line or "MainPID:" in line:
            tokens = line.replace("MainPID:", "Main PID:").split()
            # Example: 'Main PID: 14598 (procname)'
            for tok in tokens:
                if tok.isdigit():
                    logging.debug("Parsed Main PID token: %r", tok)
                    return tok
            # Fallback: strip non-digits
            import re
            m = re.search(r"Main\s*PID:\s*([0-9]+)", line)
            if m:
                return m.group(1)
            break

    raise RuntimeError("Could not determine MainPID for unit {0}".format(unit))

def get_syncd_worker_pid(host, user, key_path, process_name="syncd"):
    """
    Special strategy for syncd: find worker process that handles most TCP accepts.
    Returns the PID of the best worker process.
    """
    logging.info("Using special syncd strategy to find best worker PID")
    
    # Create the shell script content
    script_content = '''#!/bin/sh
# pick-accept-pid-min.sh
set -eu
PROC="${1:-syncd}"

# collect PIDs by /proc/.../comm
pids=""
for d in /proc/[0-9]*; do
  [ "$(cat "$d/comm" 2>/dev/null || true)" = "$PROC" ] && pids="$pids ${d##*/}"
done
pids=$(printf '%s\\n' $pids | tr -s ' \\n' ' ' | sed 's/^ //;s/ $//')
[ -n "$pids" ] || exit 1

# choose "main" (whose PPid isn't in the set); workers = others (fallback to main if none)
main=""
for p in $pids; do
  ppid=$(awk '/^PPid:/{print $2}' "/proc/$p/status" 2>/dev/null || echo 0)
  echo "$pids" | tr ' ' '\\n' | grep -qx "$ppid" || { main="$p"; break; }
done
[ -n "$main" ] || main=$(echo "$pids" | awk '{print $1}')
workers=$(for p in $pids; do [ "$p" != "$main" ] && echo "$p"; done | tr '\\n' ' ')
[ -n "$workers" ] || workers="$main"

# pick -yy if available for TCP tagging
YFLAG="-y"
strace -h 2>/dev/null | grep -q ' -yy' && YFLAG="-yy"

# short strace capture focused on accept/accept4
ts=$(date +%Y%m%d-%H%M%S 2>/dev/null || date)
prefix="/tmp/${PROC}-accpick.$ts"
set +e
strace -ff -tt -T $YFLAG -s 128 \\
  -e trace=accept,accept4 \\
  -o "$prefix" \\
  $(for p in $workers; do printf ' -p %s' "$p"; done) 2>/dev/null &
spid=$!
sleep 5
kill -INT "$spid" >/dev/null 2>&1
wait "$spid" >/dev/null 2>&1
set -e

# no outputs? fail silently
ls -1 "$prefix".* >/dev/null 2>&1 || exit 1

best_tid=""; best_cnt=-1
for f in "$prefix".*; do
  # count TCP accepts (fallback to AF_INET/6 if -yy not present)
  if [ "$YFLAG" = "-yy" ]; then
    cnt=$(grep -E 'accept4?\\(' "$f" 2>/dev/null | grep -c '<TCP:' || true)
  else
    cnt=$(grep -E 'accept4?\\(' "$f" 2>/dev/null | grep -cE 'AF_INET|AF_INET6' || true)
  fi
  [ "${cnt:-0}" -gt "$best_cnt" ] && { best_cnt="$cnt"; best_tid="${f##*.}"; }
done
[ -n "$best_tid" ] || best_tid=$(basename "$prefix".* | sed "s|^.*\\.||" | head -n1)

# map thread -> process (Tgid)
tgid=$(awk '/^Tgid:/{print $2}' "/proc/$best_tid/status" 2>/dev/null || echo "$best_tid")

# clean up trace files
rm -f "$prefix".* 2>/dev/null || true

# print only the PID
printf '%s\\n' "$tgid"
'''
    
    # Execute the script on the remote host
    remote_script = "/tmp/pick-syncd-pid.sh"
    
    # Write the script to remote host
    escaped_content = script_content.replace("'", "'\\''")
    write_cmd = "cat > {0} << 'EOF'\n{1}\nEOF\nchmod +x {0}".format(remote_script, script_content)
    ssh_run(host, user, key_path, write_cmd, capture=False, check=True)
    
    # Execute the script
    logging.info("Running syncd worker selection (this will take ~5 seconds for strace)")
    result = ssh_run(host, user, key_path, "{0} {1}".format(remote_script, process_name), 
                    capture=True, check=False).strip()
    
    # Clean up the script
    ssh_run(host, user, key_path, "rm -f {0}".format(remote_script), capture=False, check=False)
    
    if result and result.isdigit():
        logging.info("Selected syncd worker PID: %s", result)
        return result
    else:
        logging.warning("Failed to get syncd worker PID, will fall back to MainPID")
        return None

def verify_pid_exists(host, user, key_path, pid):
    """Verify that a PID exists on the remote host."""
    cmd = "kill -0 {0} 2>/dev/null && echo 'EXISTS' || echo 'NOT_EXISTS'".format(pid)
    result = ssh_run(host, user, key_path, cmd, capture=True, check=False).strip()
    return result == "EXISTS"

def kill_previous_gdbserver(host, user, key_path, port):
    cmd = (
        "old=$(cat /tmp/gdbserver.{p}.pid 2>/dev/null || true); "
        "if [ -n \"$old\" ] && kill -0 \"$old\" 2>/dev/null; then "
        "  kill \"$old\" || true; "
        "fi; "
        "rm -f /tmp/gdbserver.{p}.pid"
    ).format(p=port)
    ssh_run(host, user, key_path, cmd, capture=False, check=False)

def start_gdbserver(host, user, key_path, gdbserver_path, pid, port):
    cmd = (
        "nohup {g} --attach :{p} {pid} >/tmp/gdbserver.{p}.log 2>&1 & "
        "echo $! >/tmp/gdbserver.{p}.pid"
    ).format(g=gdbserver_path, p=port, pid=pid)
    ssh_run(host, user, key_path, cmd, capture=False, check=True)

def is_listening_snippet(port):
    hex_port = "%04X" % int(port)
    # Note: BusyBox 'ss' may be absent; fall back to /proc/net parsing
    return (
        "if command -v ss >/dev/null 2>&1; then "
        "  ss -ltn | grep -q ':{p} '; "
        "else "
        "  grep -q ':{hp}' /proc/net/tcp /proc/net/tcp6 2>/dev/null; "
        "fi"
    ).format(p=port, hp=hex_port)

def wait_for_listen(host, user, key_path, port, timeout_sec):
    logging.debug("Waiting for gdbserver to listen on %s:%s (timeout %ss)", host, port, timeout_sec)
    deadline = time.time() + timeout_sec
    snippet = is_listening_snippet(port)
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        cmd = ssh_base_cmd(key_path) + [user + "@" + host, snippet]
        # Handle both Python 2 and 3
        if sys.version_info[0] >= 3:
            rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            with open(os.devnull, 'w') as devnull:
                rc = subprocess.call(cmd, stdout=devnull, stderr=devnull)
        logging.debug("Listen check attempt %d rc=%d", attempt, rc)
        if rc == 0:
            return True
        time.sleep(0.2)
    return False

def start_local_gdb(gdb_path):
    # Simply start gdb without any arguments - let gdbinit handle everything
    args = [gdb_path]
    logging.info("Launching gdb: %s", " ".join(args))
    
    # Ignore SIGINT in the parent process while GDB is running
    old_sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
    
    try:
        # Reset signal handling to default for GDB subprocess
        def preexec_fn():
            # Reset SIGINT to default handler for GDB
            signal.signal(signal.SIGINT, signal.SIG_DFL)
        
        # Use preexec_fn on Unix/Linux systems
        if os.name != 'nt':  # Unix/Linux
            rc = subprocess.call(args, preexec_fn=preexec_fn)
        else:  # Windows
            rc = subprocess.call(args)
    finally:
        # Restore original signal handler
        signal.signal(signal.SIGINT, old_sigint)
    
    logging.info("gdb exited with status %s", str(rc))
    return rc

def cleanup_remote_gdbserver(host, user, key_path, port):
    logging.info("Cleaning up remote gdbserver on port %s", str(port))
    try:
        ssh_run(
            host, user, key_path,
            "pid=$(cat /tmp/gdbserver.{p}.pid 2>/dev/null || true); "
            "if [ -n \"$pid\" ] && kill -0 \"$pid\" 2>/dev/null; then kill \"$pid\"; fi; "
            "rm -f /tmp/gdbserver.{p}.pid".format(p=port),
            capture=False, check=False)
    except Exception as e:
        logging.debug("Cleanup exception ignored: %s", str(e))

def main():
    parser = argparse.ArgumentParser(
        description="Attach gdbserver to a remote process. Either restart a service and attach to it, "
                    "or attach directly to a specified PID.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Restart a service and attach to its main process
  %(prog)s --unit pkg-scsi-plugin-server.service

  # Attach directly to a specific PID without restarting anything
  %(prog)s --pid 12345

  # Restart syncd service and use special worker selection
  %(prog)s --unit pkg-synologydrive-syncd.service
""")
    
    parser.add_argument("--host", default="192.168.1.26", help="Remote host")
    parser.add_argument("--user", default="root", help="Remote user")
    parser.add_argument("--ssh-key", default="/root/.ssh/id_ed25519", help="SSH private key path")
    
    # Make unit and pid mutually exclusive
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--unit", help="Systemd unit to restart and attach to")
    group.add_argument("--pid", type=int, help="PID to attach to directly (skips service restart)")
    
    parser.add_argument("--gdbserver", default="/bin/gdbserver", help="Remote gdbserver path")
    parser.add_argument("--gdb", default="gdb", help="Local gdb path")
    parser.add_argument("--port", default=4444, type=int, help="TCP port for gdbserver")
    parser.add_argument("--timeout", default=10.0, type=float, help="Seconds to wait for gdbserver to listen")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()

    # Require either --unit or --pid
    if not args.unit and args.pid is None:
        parser.error("Either --unit or --pid must be specified")

    setup_logging(args.verbose)

    logging.info("Target: %s@%s", args.user, args.host)
    logging.info("Port: %d", args.port)

    atexit.register(cleanup_remote_gdbserver, args.host, args.user, args.ssh_key, args.port)

    # Don't install a SIGINT handler - let it pass through to GDB
    # If you need to exit the script before GDB starts, use Ctrl+\ (SIGQUIT) instead

    pid = None

    if args.pid:
        # Direct PID attachment mode
        logging.info("Direct PID attachment mode: PID %d", args.pid)
        
        # Verify the PID exists
        if not verify_pid_exists(args.host, args.user, args.ssh_key, str(args.pid)):
            logging.error("PID %d does not exist on remote host", args.pid)
            sys.exit(1)
        
        pid = str(args.pid)
        logging.info("Attaching to existing PID: %s", pid)
        
    else:
        # Service restart mode
        logging.info("Service restart mode: %s", args.unit)
        
        # 1) Restart the unit
        restart_unit(args.host, args.user, args.ssh_key, args.unit)

        # 2) Wait a moment for the service to fully start
        time.sleep(1)

        # 3) Determine which PID to attach to
        # Check if this is the syncd unit - use special strategy
        if "syncd" in args.unit.lower():
            logging.info("Detected syncd unit - using special worker selection strategy")
            pid = get_syncd_worker_pid(args.host, args.user, args.ssh_key, "syncd")
        
        # If syncd strategy failed or not syncd unit, use standard MainPID
        if not pid:
            pid = get_main_pid(args.host, args.user, args.ssh_key, args.unit)
        
        logging.info("Target PID: %s", pid)

    # 4) Kill any previous gdbserver instance on this port
    kill_previous_gdbserver(args.host, args.user, args.ssh_key, args.port)

    # 5) Start gdbserver attached to the PID
    logging.info("Starting gdbserver %s --attach :%d %s", args.gdbserver, args.port, pid)
    start_gdbserver(args.host, args.user, args.ssh_key, args.gdbserver, pid, args.port)

    # 6) Wait for listening state
    ok = wait_for_listen(args.host, args.user, args.ssh_key, args.port, args.timeout)
    if not ok:
        logging.error("gdbserver did not open port %d within %.1f seconds", args.port, args.timeout)
        sys.exit(1)
    logging.info("gdbserver is listening on %s:%d", args.host, args.port)

    # 7) Launch local gdb and connect
    # The modified start_local_gdb will reset SIGINT handling for GDB
    rc = start_local_gdb(args.gdb)
    sys.exit(0 if rc == 0 else rc)

if __name__ == "__main__":
    main()