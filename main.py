# import asyncio
# import logging
# import platform
# import time
# from collections import deque
# from datetime import datetime
# from prometheus_client import Gauge, start_http_server

# # --- Prometheus Metrics ---
# icmp_up = Gauge('icmp_up', 'ICMP up (1 = reachable, 0 = unreachable)', ['node', 'ip'])
# icmp_rtt_ms = Gauge('icmp_rtt_ms', 'ICMP round-trip time in milliseconds (last probe)', ['node', 'ip'])
# icmp_packet_loss_percent = Gauge('icmp_packet_loss_percent', 'Packet loss percentage over sliding window', ['node', 'ip'])
# icmp_last_seen_ts = Gauge('icmp_last_seen_timestamp_seconds', 'Unix timestamp of last successful ICMP reply', ['node', 'ip'])

# # --- Logging ---
# logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
# logger = logging.getLogger(__name__)

# # Probe configuration
# PROBE_INTERVAL = 10        # seconds between probes per node
# PROBE_TIMEOUT = 3          # seconds timeout for each ping
# LOSS_WINDOW = 10           # sliding window size to compute packet loss

# async def ping_system(ip: str, timeout: int = PROBE_TIMEOUT):
#     """
#     Cross-platform 'ping one probe' via system ping command using asyncio subprocess.
#     Returns (success: bool, rtt_ms: float|None, raw_output: str).
#     """
#     system = platform.system().lower()
#     if 'windows' in system:
#         # -n 1 (one echo), -w timeout in ms
#         cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
#     elif 'darwin' in system:
#         # macOS: -c 1 (count), -W timeout in ms (note: macOS '-W' expects milliseconds in some versions)
#         # Use -c 1 and rely on overall timeout via asyncio.wait_for as a safety net.
#         cmd = ["ping", "-c", "1", ip]
#     else:
#         # Assume Linux/Unix: -c 1 (count), -W timeout (seconds)
#         cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

#     try:
#         proc = await asyncio.create_subprocess_exec(
#             *cmd,
#             stdout=asyncio.subprocess.PIPE,
#             stderr=asyncio.subprocess.STDOUT
#         )

#         try:
#             stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
#         except asyncio.TimeoutError:
#             proc.kill()
#             await proc.communicate()
#             return False, None, ""

#         out = stdout.decode(errors='ignore')
#         # parse RTT from common patterns: "time=12.3 ms" or "rtt min/avg/max/mdev = ... / 12.3 / ..."
#         rtt = None
#         for line in out.splitlines():
#             if "time=" in line.lower():
#                 # attempt to extract e.g. "time=12.3 ms"
#                 try:
#                     part = [p for p in line.split() if "time=" in p.lower()][0]
#                     # part may be 'time=12.3' or 'time=12.3ms' depending on platform
#                     value = part.split("=", 1)[1]
#                     # strip non-numeric suffixes
#                     value = value.replace("ms", "").replace("MS", "")
#                     rtt = float(value)
#                     break
#                 except Exception:
#                     continue
#             if "rtt min" in line.lower() or "round-trip" in line.lower():
#                 # fallback: parse avg from " = min/avg/max/..." or "round-trip min/avg/max/stddev = ..."
#                 try:
#                     avg = line.split("=")[1].split("/")[1]
#                     rtt = float(avg)
#                     break
#                 except Exception:
#                     continue

#         success = proc.returncode == 0 or ("ttl=" in out.lower()) or (rtt is not None)
#         return success, rtt, out

#     except Exception as e:
#         logger.debug(f"ping_system exception for {ip}: {e}")
#         return False, None, ""

# async def poll_node(node: dict, interval: int = PROBE_INTERVAL, loss_window: int = LOSS_WINDOW):
#     """
#     Poll a single node using ICMP. Maintains an in-memory sliding window for packet loss.
#     """
#     name = node.get("name", node.get("ip"))
#     ip = node["ip"]
#     history = deque(maxlen=loss_window)  # True for success, False for failure

#     logger.info(f"Started ICMP polling for {name} ({ip}), interval={interval}s, timeout={PROBE_TIMEOUT}s")

#     while True:
#         ts = time.time()
#         try:
#             success, rtt, raw = await ping_system(ip, timeout=PROBE_TIMEOUT)
#         except Exception as e:
#             logger.warning(f"Exception pinging {name} ({ip}): {e}")
#             success, rtt, raw = False, None, ""

#         # Update history and compute metrics
#         history.append(success)
#         loss_pct = 0.0
#         if len(history) > 0:
#             loss_pct = (1.0 - (sum(1 if x else 0 for x in history) / len(history))) * 100.0

#         # Prometheus metrics:
#         icmp_up.labels(node=name, ip=ip).set(1 if success else 0)

#         if success and rtt is not None:
#             # set last seen and rtt
#             icmp_rtt_ms.labels(node=name, ip=ip).set(float(rtt))
#             icmp_last_seen_ts.labels(node=name, ip=ip).set(ts)
#         else:
#             # failed probe -> set rtt to 0 to indicate no measurable RTT; up flag shows it's down
#             icmp_rtt_ms.labels(node=name, ip=ip).set(0.0)

#         icmp_packet_loss_percent.labels(node=name, ip=ip).set(loss_pct)

#         # Logging for debugging/visibility
#         logger.info(f"{name} ({ip}) success={success} rtt={rtt}ms loss={loss_pct:.1f}%")

#         await asyncio.sleep(interval)

# async def main():
#     # Start Prometheus metrics server
#     start_http_server(8000)
#     logger.info("Prometheus metrics server started on port 8000")

#     nodes = [
#         {"name": "PCdharmil", "ip": "192.168.0.164"},{"name": "PC-avrut", "ip": "192.168.0.160"},
#         # add more nodes here...
#     ]

#     # spawn one task per node
#     tasks = [asyncio.create_task(poll_node(n)) for n in nodes]
#     await asyncio.gather(*tasks)

# if __name__ == "__main__":
#     try:
#         asyncio.run(main())
#     except KeyboardInterrupt:
#         logger.info("Shutting down ICMP monitor.")

#!/usr/bin/env python3
"""
snmp_icmp_monitor.py

Merged SNMP + ICMP monitor that:
 - Scans a CIDR for SNMP-enabled devices (v2c with a community string)
 - For each discovered device, starts:
    * an SNMP polling task that exports system + interface metrics
    * an ICMP polling task that exports reachability, RTT and packet-loss
 - Serves Prometheus metrics on port 8000

Notes:
 - Requires: prometheus_client, pysnmp (and its asyncio backend)
 - Designed for Unix/Linux/macOS/Windows (uses system `ping` command)
 - Run as a user that can execute ping (Windows: may need Administrator)

Example:
    python3 snmp_icmp_monitor.py --network 192.168.0.0/24 --community public

"""

import argparse
import asyncio
import ipaddress
import logging
import platform
import time
from collections import deque
from datetime import datetime

from prometheus_client import Gauge, start_http_server

# pysnmp asyncio API
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, get_cmd
)

# ---------------- Prometheus metrics ----------------
# ICMP metrics
icmp_up = Gauge('icmp_up', 'ICMP up (1 = reachable, 0 = unreachable)', ['node', 'ip'])
icmp_rtt_ms = Gauge('icmp_rtt_ms', 'ICMP round-trip time in milliseconds (last probe)', ['node', 'ip'])
icmp_packet_loss_percent = Gauge('icmp_packet_loss_percent', 'Packet loss percentage over sliding window', ['node', 'ip'])
icmp_last_seen_ts = Gauge('icmp_last_seen_timestamp_seconds', 'Unix timestamp of last successful ICMP reply', ['node', 'ip'])

# SNMP metrics
sys_uptime = Gauge('snmp_system_uptime_seconds', 'System uptime in seconds', ['node', 'sys_name'])
sys_info = Gauge('snmp_system_info', 'System information', ['node', 'sys_name', 'sys_descr', 'sys_location'])
if_octets_in = Gauge('snmp_interface_octets_in', 'Interface input octets', ['node', 'interface', 'if_index'])
if_octets_out = Gauge('snmp_interface_octets_out', 'Interface output octets', ['node', 'interface', 'if_index'])
if_errors_in = Gauge('snmp_interface_errors_in', 'Interface input errors', ['node', 'interface', 'if_index'])
if_errors_out = Gauge('snmp_interface_errors_out', 'Interface output errors', ['node', 'interface', 'if_index'])
if_oper_status = Gauge('snmp_interface_oper_status', 'Interface operational status (1=up, 2=down)', ['node', 'interface', 'if_index'])

# ---------------- Logging ----------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------- SNMP OIDs ----------------
SYS_OIDS = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
    "sys_location": "1.3.6.1.2.1.1.6.0",
    "sys_uptime": "1.3.6.1.2.1.1.3.0"
}

IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"
IF_OPERSTATUS_OID = "1.3.6.1.2.1.2.2.1.8"
IF_INOCTETS_OID = "1.3.6.1.2.1.2.2.1.10"
IF_OUTOCTETS_OID = "1.3.6.1.2.1.2.2.1.16"
IF_INERRORS_OID = "1.3.6.1.2.1.2.2.1.14"
IF_OUTERRORS_OID = "1.3.6.1.2.1.2.2.1.20"

# ---------------- Configuration defaults ----------------
PROBE_INTERVAL = 10        # seconds between ICMP probes per node
PROBE_TIMEOUT = 3          # seconds timeout for each ping
LOSS_WINDOW = 10           # sliding window size to compute packet loss
SNMP_POLL_INTERVAL = 20    # seconds between SNMP polls per node
METRICS_PORT = 8000

# ---------------- Helper: cross-platform ping via subprocess ----------------
async def ping_system(ip: str, timeout: int = PROBE_TIMEOUT):
    """
    Cross-platform 'ping one probe' via system ping command using asyncio subprocess.
    Returns (success: bool, rtt_ms: float|None, raw_output: str).
    """
    system = platform.system().lower()
    if 'windows' in system:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif 'darwin' in system:
        cmd = ["ping", "-c", "1", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )

        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return False, None, ""

        out = stdout.decode(errors='ignore')
        # parse RTT from common patterns: "time=12.3 ms" or "rtt min/avg/max/mdev = ... / 12.3 / ..."
        rtt = None
        for line in out.splitlines():
            if "time=" in line.lower():
                try:
                    part = [p for p in line.split() if "time=" in p.lower()][0]
                    value = part.split("=", 1)[1]
                    value = value.replace("ms", "").replace("MS", "")
                    rtt = float(value)
                    break
                except Exception:
                    continue
            if "rtt min" in line.lower() or "round-trip" in line.lower():
                try:
                    avg = line.split("=")[1].split("/")[1]
                    rtt = float(avg)
                    break
                except Exception:
                    continue

        success = proc.returncode == 0 or ("ttl=" in out.lower()) or (rtt is not None)
        return success, rtt, out

    except Exception as e:
        logger.debug(f"ping_system exception for {ip}: {e}")
        return False, None, ""

# ---------------- SNMP helpers ----------------
async def snmp_get(snmp_engine, community_data, transport, oid):
    try:
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmp_engine, community_data, transport, ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        if errorIndication or errorStatus:
            return None
        for _, val in varBinds:
            return val
    except Exception:
        return None

async def snmp_walk(snmp_engine, community_data, transport, base_oid):
    """
    Simple walk that tries index suffixes starting from 1 until no more values.
    This is a naive walker but works for typical IF table indexes.
    """
    result = {}
    try:
        index = 1
        while True:
            oid = f"{base_oid}.{index}"
            val = await snmp_get(snmp_engine, community_data, transport, oid)
            if val is None:
                break
            result[index] = val
            index += 1
    except Exception:
        pass
    return result

# ---------------- Polling tasks ----------------
import random
import traceback

async def poll_icmp_for_node(node: dict, interval: int = PROBE_INTERVAL, loss_window: int = LOSS_WINDOW):
    """
    ICMP polling task per node — robust, logs each probe, never dies silently.
    Use this version to debug/update-frequency issues.
    """
    name = node.get("name", node.get("ip"))
    ip = node["ip"]
    history = deque(maxlen=loss_window)

    logger.info(f"Started ICMP polling for {name} ({ip}), interval={interval}s, timeout={PROBE_TIMEOUT}s")

    while True:
        ts = time.time()
        try:
            success, rtt, raw = await ping_system(ip, timeout=PROBE_TIMEOUT)
        except Exception as e:
            # log the full traceback and mark as failure
            logger.error(f"Exception during ping_system for {name} ({ip}): {e}\n{traceback.format_exc()}")
            success, rtt, raw = False, None, ""

        # update history and compute loss %
        try:
            history.append(bool(success))
            loss_pct = 0.0
            if len(history) > 0:
                loss_pct = (1.0 - (sum(1 if x else 0 for x in history) / len(history))) * 100.0
        except Exception as e:
            logger.error(f"Error updating history for {name} ({ip}): {e}")
            loss_pct = 100.0

        # write Prometheus metrics every iteration
        try:
            icmp_up.labels(node=name, ip=ip).set(1 if success else 0)
            if success and rtt is not None:
                icmp_rtt_ms.labels(node=name, ip=ip).set(float(rtt))
                icmp_last_seen_ts.labels(node=name, ip=ip).set(ts)
            else:
                # keep last seen timestamp unchanged when probe fails, but set rtt to 0
                icmp_rtt_ms.labels(node=name, ip=ip).set(0.0)

            icmp_packet_loss_percent.labels(node=name, ip=ip).set(loss_pct)
        except Exception as e:
            logger.error(f"Error setting Prometheus metrics for {name} ({ip}): {e}")

        # detailed per-probe log (DEBUG level can be shown by setting logging to DEBUG)
        logger.info(f"ICMP probe: {name} ({ip}) success={success} rtt={rtt}ms loss={loss_pct:.1f}%")

        # small jitter to avoid synchronized probes
        sleep_for = interval + random.uniform(-0.2 * interval, 0.2 * interval)
        if sleep_for < 0.5:
            sleep_for = 0.5
        await asyncio.sleep(sleep_for)

# Store last known good system info to avoid exporting "unknown"
LAST_GOOD_SYSINFO = {}

async def poll_snmp_for_node(node: dict, interval: int = SNMP_POLL_INTERVAL):
    ip = node["ip"]
    community = node.get("community", "public")
    name = node.get("name", ip)

    snmp_engine = SnmpEngine()
    transport = await UdpTransportTarget.create((ip, 161))
    community_data = CommunityData(community)

    global LAST_GOOD_SYSINFO
    if name not in LAST_GOOD_SYSINFO:
        LAST_GOOD_SYSINFO[name] = {
            "sys_name": "",
            "sys_descr": "",
            "sys_location": ""
        }

    logger.info(f"Started SNMP polling for {name} ({ip}), interval={interval}s")

    while True:
        sys_data = {}

        # fetch system OIDs
        for label, oid in SYS_OIDS.items():
            val = await snmp_get(snmp_engine, community_data, transport, oid)
            if val is not None:
                if label == "sys_uptime":
                    sys_data[label] = int(val)
                else:
                    sys_data[label] = val.prettyPrint()

        # Update uptime metric
        if "sys_uptime" in sys_data:
            try:
                uptime_seconds = int(sys_data["sys_uptime"]) // 100
            except Exception:
                uptime_seconds = int(sys_data["sys_uptime"])
            sys_uptime.labels(node=name,
                              sys_name=LAST_GOOD_SYSINFO[name]["sys_name"]).set(uptime_seconds)

        # Update last known good values
        for field in ["sys_name", "sys_descr", "sys_location"]:
            if field in sys_data and sys_data[field] not in ("", "unknown", None):
                LAST_GOOD_SYSINFO[name][field] = sys_data[field]

        # Export clean system info (NEVER export "unknown")
        sys_info.labels(
            node=name,
            sys_name=LAST_GOOD_SYSINFO[name]["sys_name"],
            sys_descr=LAST_GOOD_SYSINFO[name]["sys_descr"],
            sys_location=LAST_GOOD_SYSINFO[name]["sys_location"]
        ).set(1)

        # interfaces (unchanged)
        if_descr = await snmp_walk(snmp_engine, community_data, transport, IF_DESCR_OID)
        if_operstatus = await snmp_walk(snmp_engine, community_data, transport, IF_OPERSTATUS_OID)

        for if_index, if_name_obj in if_descr.items():
            if_name = str(if_name_obj)
            oper_status = int(if_operstatus.get(if_index, 2))

            if_oper_status.labels(node=name, interface=if_name, if_index=if_index).set(oper_status)
            if oper_status != 1:
                continue

            in_octets = await snmp_get(snmp_engine, community_data, transport, f"{IF_INOCTETS_OID}.{if_index}")
            out_octets = await snmp_get(snmp_engine, community_data, transport, f"{IF_OUTOCTETS_OID}.{if_index}")
            in_errors = await snmp_get(snmp_engine, community_data, transport, f"{IF_INERRORS_OID}.{if_index}")
            out_errors = await snmp_get(snmp_engine, community_data, transport, f"{IF_OUTERRORS_OID}.{if_index}")

            if in_octets is not None:
                try:
                    if_octets_in.labels(node=name, interface=if_name, if_index=if_index).set(int(in_octets))
                except:
                    pass
            if out_octets is not None:
                try:
                    if_octets_out.labels(node=name, interface=if_name, if_index=if_index).set(int(out_octets))
                except:
                    pass
            if in_errors is not None:
                try:
                    if_errors_in.labels(node=name, interface=if_name, if_index=if_index).set(int(in_errors))
                except:
                    pass
            if out_errors is not None:
                try:
                    if_errors_out.labels(node=name, interface=if_name, if_index=if_index).set(int(out_errors))
                except:
                    pass

        await asyncio.sleep(interval)

# ---------------- Discovery ----------------
async def check_snmp_device(snmp_engine, ip, community):
    try:
        transport = await UdpTransportTarget.create((ip, 161), timeout=1, retries=0)
        community_data = CommunityData(community)
        val = await snmp_get(snmp_engine, community_data, transport, SYS_OIDS["sys_name"])
        if val:
            return {"name": str(val), "ip": ip, "community": community}
    except Exception:
        pass
    return None

async def discover_nodes(network_cidr="10.147.62.0/24", community="public", concurrency=200):
    snmp_engine = SnmpEngine()
    discovered = []

    ips = [str(ip) for ip in ipaddress.IPv4Network(network_cidr) if ip.packed[-1] not in (0, 255)]

    logger.info(f"Scanning {network_cidr} for SNMP devices ({len(ips)} addresses)")

    sem = asyncio.Semaphore(concurrency)

    async def _check(ip_addr):
        async with sem:
            return await check_snmp_device(snmp_engine, ip_addr, community)

    tasks = [asyncio.create_task(_check(ip)) for ip in ips]
    results = await asyncio.gather(*tasks)

    for node in results:
        if node:
            discovered.append(node)

    logger.info(f"Discovered {len(discovered)} SNMP devices")
    for d in discovered:
        logger.info(f"→ {d['name']} ({d['ip']})")

    return discovered

# ---------------- Main ----------------
async def main(args):
    start_http_server(METRICS_PORT)
    logger.info(f"Prometheus metrics server started on port {METRICS_PORT}")

    nodes = []

    if args.discover:
        nodes = await discover_nodes(args.network, community=args.community)
    else:
        # use static list
        for ip in args.targets:
            nodes.append({"name": ip, "ip": ip, "community": args.community})

    if not nodes:
        logger.warning("No nodes to poll. Exiting.")
        return

    # create tasks for both SNMP and ICMP for each discovered node
    tasks = []
    for n in nodes:
        tasks.append(asyncio.create_task(poll_snmp_for_node(n)))
        tasks.append(asyncio.create_task(poll_icmp_for_node(n)))

    # wait until tasks complete (they won't unless cancelled)
    await asyncio.gather(*tasks)

if __name__ == '__main__':
    # --- Args removed: always auto-discover ---
    class Args:
        network = '10.147.62.0/24'
        community = 'public'
        discover = True
        targets = []
    args = Args()

    # # Argument parser removed; using default Args class instead.()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        logger.info('Shutting down monitor')
