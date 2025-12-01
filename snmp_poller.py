import argparse
import asyncio
import ipaddress
import logging
import platform
import time
from collections import deque
import random
import traceback

from prometheus_client import Gauge, start_http_server

# pysnmp asyncio API
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, get_cmd
)

# ---------------- Prometheus metrics ----------------
icmp_up = Gauge('icmp_up', 'ICMP up (1 = reachable, 0 = unreachable)', ['node', 'ip'])
icmp_rtt_ms = Gauge('icmp_rtt_ms', 'ICMP round-trip time in ms', ['node', 'ip'])
icmp_packet_loss_percent = Gauge('icmp_packet_loss_percent', 'Packet loss %', ['node', 'ip'])
icmp_last_seen_ts = Gauge('icmp_last_seen_timestamp_seconds', 'Last ICMP success (unix ts)', ['node', 'ip'])

# SNMP system
sys_uptime = Gauge('snmp_system_uptime_seconds', 'System uptime (sec)', ['node', 'sys_name'])
sys_info = Gauge('snmp_system_info', 'System info', ['node', 'sys_name', 'sys_descr', 'sys_location'])

# SNMP interfaces
if_octets_in = Gauge('snmp_interface_octets_in', 'Interface input octets', ['node', 'interface', 'if_index'])
if_octets_out = Gauge('snmp_interface_octets_out', 'Interface output octets', ['node', 'interface', 'if_index'])
if_errors_in = Gauge('snmp_interface_errors_in', 'Interface input errors', ['node', 'interface', 'if_index'])
if_errors_out = Gauge('snmp_interface_errors_out', 'Interface output errors', ['node', 'interface', 'if_index'])
if_oper_status = Gauge('snmp_interface_oper_status', 'Interface operational status', ['node', 'interface', 'if_index'])

# CPU & Memory
cpu_load_percent = Gauge('snmp_cpu_load_percent', 'CPU core utilization %', ['node', 'cpu_index'])
memory_total_bytes = Gauge('snmp_memory_total_bytes', 'Total RAM bytes', ['node'])
memory_used_bytes = Gauge('snmp_memory_used_bytes', 'Used RAM bytes', ['node'])
memory_used_percent = Gauge('snmp_memory_used_percent', 'RAM used %', ['node'])

# ---------------- Logging ----------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------- OIDs ----------------
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

CPU_OID = "1.3.6.1.2.1.25.3.3.1.2"

HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
HR_STORAGE_ALLOC = "1.3.6.1.2.1.25.2.3.1.4"
HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"

# ---------------- CONFIG ----------------
PROBE_INTERVAL = 10
PROBE_TIMEOUT = 3
LOSS_WINDOW = 10
SNMP_POLL_INTERVAL = 20
METRICS_PORT = 8000

# ---------------- PING ----------------
async def ping_system(ip: str, timeout: int = PROBE_TIMEOUT):
    system = platform.system().lower()
    if 'windows' in system:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
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
        rtt = None

        for line in out.splitlines():
            if "time=" in line.lower():
                try:
                    part = [p for p in line.split() if "time=" in p.lower()][0]
                    rtt = float(part.split("=")[1].replace("ms", ""))
                except:
                    pass

        success = proc.returncode == 0 or rtt is not None
        return success, rtt, out

    except Exception as e:
        logger.error(f"Ping error for {ip}: {e}")
        return False, None, ""

# ---------------- SNMP HELPERS ----------------
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
    except:
        return None

# WINDOWS COMPATIBLE WALK
async def snmp_walk(snmp_engine, community_data, transport, base_oid):
    results = {}
    index = 1

    while True:
        oid = f"{base_oid}.{index}"
        val = await snmp_get(snmp_engine, community_data, transport, oid)

        if val is None:
            break

        results[index] = val
        index += 1

    return results

# ---------------- ICMP TASK ----------------
async def poll_icmp_for_node(node: dict, interval: int = PROBE_INTERVAL, loss_window: int = LOSS_WINDOW):
    name = node.get("name", node.get("ip"))
    ip = node["ip"]
    history = deque(maxlen=loss_window)

    logger.info(f"Started ICMP polling for {name} ({ip})")

    while True:
        ts = time.time()
        success, rtt, out = await ping_system(ip)
        history.append(success)

        loss_pct = (1 - (sum(history) / len(history))) * 100

        icmp_up.labels(node=name, ip=ip).set(1 if success else 0)
        icmp_rtt_ms.labels(node=name, ip=ip).set(rtt if rtt else 0)
        icmp_packet_loss_percent.labels(node=name, ip=ip).set(loss_pct)
        if success:
            icmp_last_seen_ts.labels(node=name, ip=ip).set(ts)

        logger.info(f"[ICMP] {name} {ip} success={success} rtt={rtt}ms loss={loss_pct:.1f}%")

        await asyncio.sleep(interval)

# ---------------- SNMP TASK ----------------
LAST_GOOD_SYSINFO = {}

async def poll_snmp_for_node(node: dict, interval: int = SNMP_POLL_INTERVAL):
    ip = node["ip"]
    community = node.get("community", "public")
    name = node.get("name", ip)

    snmp_engine = SnmpEngine()
    transport = await UdpTransportTarget.create((ip, 161))
    community_data = CommunityData(community)

    LAST_GOOD_SYSINFO.setdefault(name, {"sys_name": "", "sys_descr": "", "sys_location": ""})

    logger.info(f"Started SNMP polling for {name} ({ip})")

    while True:

        # SYSTEM INFO
        sys_data = {}
        for label, oid in SYS_OIDS.items():
            val = await snmp_get(snmp_engine, community_data, transport, oid)
            if val is not None:
                sys_data[label] = val.prettyPrint() if label != "sys_uptime" else int(val)

        if "sys_uptime" in sys_data:
            uptime_seconds = int(sys_data["sys_uptime"]) // 100
            sys_uptime.labels(node=name,
                              sys_name=LAST_GOOD_SYSINFO[name]["sys_name"]).set(uptime_seconds)

        # Update cached values
        for f in ["sys_name", "sys_descr", "sys_location"]:
            if sys_data.get(f) is not None:
                LAST_GOOD_SYSINFO[name][f] = sys_data[f]

        sys_info.labels(
            node=name,
            sys_name=LAST_GOOD_SYSINFO[name]["sys_name"],
            sys_descr=LAST_GOOD_SYSINFO[name]["sys_descr"],
            sys_location=LAST_GOOD_SYSINFO[name]["sys_location"]
        ).set(1)

        # INTERFACES
        if_descr = await snmp_walk(snmp_engine, community_data, transport, IF_DESCR_OID)
        if_oper = await snmp_walk(snmp_engine, community_data, transport, IF_OPERSTATUS_OID)

        for idx, iface in if_descr.items():
            iface_name = str(iface)
            oper = int(if_oper.get(idx, 2))

            if_oper_status.labels(node=name, interface=iface_name, if_index=idx).set(oper)

            if oper != 1:
                continue

            # FIX: check "is not None" here
            in_oct = await snmp_get(snmp_engine, community_data, transport, f"{IF_INOCTETS_OID}.{idx}")
            out_oct = await snmp_get(snmp_engine, community_data, transport, f"{IF_OUTOCTETS_OID}.{idx}")
            in_err = await snmp_get(snmp_engine, community_data, transport, f"{IF_INERRORS_OID}.{idx}")
            out_err = await snmp_get(snmp_engine, community_data, transport, f"{IF_OUTERRORS_OID}.{idx}")

            if in_oct is not None:
                if_octets_in.labels(node=name, interface=iface_name, if_index=idx).set(int(in_oct))

            if out_oct is not None:
                if_octets_out.labels(node=name, interface=iface_name, if_index=idx).set(int(out_oct))

            if in_err is not None:
                if_errors_in.labels(node=name, interface=iface_name, if_index=idx).set(int(in_err))

            if out_err is not None:
                if_errors_out.labels(node=name, interface=iface_name, if_index=idx).set(int(out_err))

        # -------- CPU BLOCK (WINDOWS-SAFE, SPARSE INDEXES) --------
        cpu_table = {}
        for idx in range(1, 40):  # check Windows sparse indexes like 4–11
            oid = f"{CPU_OID}.{idx}"
            val = await snmp_get(snmp_engine, community_data, transport, oid)
            if val is not None:
                cpu_table[idx] = val

        logger.info(f"[DEBUG] CPU results for {name}: {cpu_table}")

        for cpu_idx, value in cpu_table.items():
            cpu_load_percent.labels(
                node=name,
                cpu_index=str(cpu_idx)
            ).set(int(value))


        # MEMORY BLOCK
        descr = await snmp_walk(snmp_engine, community_data, transport, HR_STORAGE_DESCR)
        alloc = await snmp_walk(snmp_engine, community_data, transport, HR_STORAGE_ALLOC)
        size = await snmp_walk(snmp_engine, community_data, transport, HR_STORAGE_SIZE)
        used = await snmp_walk(snmp_engine, community_data, transport, HR_STORAGE_USED)

        logger.info(f"[DEBUG] MEMORY DESCR for {name}: {descr}")

        ram_index = None
        for idx, d in descr.items():
            if "Physical Memory" in d.prettyPrint():
                ram_index = idx
                break

        if ram_index:
            unit = int(alloc[ram_index])
            total = int(size[ram_index]) * unit
            used_val = int(used[ram_index]) * unit

            memory_total_bytes.labels(node=name).set(total)
            memory_used_bytes.labels(node=name).set(used_val)

            if total > 0:
                memory_used_percent.labels(node=name).set((used_val / total) * 100)

        await asyncio.sleep(interval)

# ---------------- DISCOVERY ----------------
async def check_snmp_device(snmp_engine, ip, community):
    try:
        transport = await UdpTransportTarget.create((ip, 161), timeout=1, retries=0)
        community_data = CommunityData(community)
        val = await snmp_get(snmp_engine, community_data, transport, SYS_OIDS["sys_name"])
        if val is not None:
            return {"name": str(val), "ip": ip, "community": community}
    except:
        pass
    return None

async def discover_nodes(network_cidr="10.147.62.0/24", community="public", concurrency=200):
    snmp_engine = SnmpEngine()
    discovered = []

    ips = [str(ip) for ip in ipaddress.IPv4Network(network_cidr)
           if ip.packed[-1] not in (0, 255)]

    logger.info(f"Scanning {network_cidr} ({len(ips)} hosts)")

    sem = asyncio.Semaphore(concurrency)

    async def _check(ip_addr):
        async with sem:
            return await check_snmp_device(snmp_engine, ip_addr, community)

    results = await asyncio.gather(*[asyncio.create_task(_check(ip)) for ip in ips])

    for node in results:
        if node:
            discovered.append(node)

    logger.info(f"Discovered {len(discovered)} SNMP devices")

    return discovered

# ---------------- MAIN ----------------
async def main(args):
    start_http_server(METRICS_PORT)
    logger.info(f"Prometheus metrics available on :{METRICS_PORT}/metrics")

    if args.discover:
        nodes = await discover_nodes(args.network, args.community)
    else:
        nodes = [{"name": ip, "ip": ip, "community": args.community} for ip in args.targets]

    if not nodes:
        logger.warning("No nodes found!")
        return

    tasks = []
    for n in nodes:
        tasks.append(asyncio.create_task(poll_icmp_for_node(n)))
        tasks.append(asyncio.create_task(poll_snmp_for_node(n)))

    await asyncio.gather(*tasks)

if __name__ == '__main__':
    class Args:
        network = '10.147.62.0/24'
        community = 'public'
        discover = True
        targets = []

    args = Args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
