import asyncio
import logging
import ipaddress
from prometheus_client import Gauge, start_http_server
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, get_cmd
)

# --- Prometheus Metrics ---
sys_uptime = Gauge('snmp_system_uptime_seconds', 'System uptime in seconds', ['node', 'sys_name'])
sys_info = Gauge('snmp_system_info', 'System information', ['node', 'sys_name', 'sys_descr', 'sys_location'])
if_octets_in = Gauge('snmp_interface_octets_in', 'Interface input octets', ['node', 'interface', 'if_index'])
if_octets_out = Gauge('snmp_interface_octets_out', 'Interface output octets', ['node', 'interface', 'if_index'])
if_errors_in = Gauge('snmp_interface_errors_in', 'Interface input errors', ['node', 'interface', 'if_index'])
if_errors_out = Gauge('snmp_interface_errors_out', 'Interface output errors', ['node', 'interface', 'if_index'])
if_oper_status = Gauge('snmp_interface_oper_status', 'Interface operational status (1=up, 2=down)',
                      ['node', 'interface', 'if_index'])

# --- Logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

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


# --- SNMP GET helper ---
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


# --- SNMP WALK helper ---
async def snmp_walk(snmp_engine, community_data, transport, base_oid):
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


# --- Poll single node ---
async def poll_node(node, interval=20):
    ip = node["ip"]
    community = node.get("community", "public")
    name = node.get("name", ip)

    snmp_engine = SnmpEngine()
    transport = await UdpTransportTarget.create((ip, 161))
    community_data = CommunityData(community)

    while True:
        logger.info(f"Polling {name} ({ip})")

        # --- System info ---
        sys_data = {}
        for label, oid in SYS_OIDS.items():
            val = await snmp_get(snmp_engine, community_data, transport, oid)
            if val is not None:
                sys_data[label] = val.prettyPrint() if label != "sys_uptime" else int(val)

        if 'sys_uptime' in sys_data:
            uptime_seconds = sys_data['sys_uptime'] // 100
            sys_uptime.labels(node=name, sys_name=sys_data.get('sys_name', 'unknown')).set(uptime_seconds)

        sys_info.labels(
            node=name,
            sys_name=sys_data.get('sys_name', 'unknown'),
            sys_descr=sys_data.get('sys_descr', 'unknown'),
            sys_location=sys_data.get('sys_location', 'unknown')
        ).set(1)

        # --- Interface info ---
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
                if_octets_in.labels(node=name, interface=if_name, if_index=if_index).set(int(in_octets))
            if out_octets is not None:
                if_octets_out.labels(node=name, interface=if_name, if_index=if_index).set(int(out_octets))
            if in_errors is not None:
                if_errors_in.labels(node=name, interface=if_name, if_index=if_index).set(int(in_errors))
            if out_errors is not None:
                if_errors_out.labels(node=name, interface=if_name, if_index=if_index).set(int(out_errors))

        await asyncio.sleep(interval)


# --- Discover SNMP devices in subnet ---
async def discover_nodes(network_cidr="192.168.0.129/32", community="public"):
    snmp_engine = SnmpEngine()
    discovered = []

    tasks = []
    for ip in ipaddress.IPv4Network(network_cidr):
        if ip.packed[-1] in (0, 255):  # skip network and broadcast
            continue
        tasks.append(check_snmp_device(snmp_engine, str(ip), community))

    logger.info(f"Scanning {network_cidr} for SNMP devices...")
    results = await asyncio.gather(*tasks)
    for node in results:
        if node:
            discovered.append(node)

    logger.info(f"Discovered {len(discovered)} SNMP devices")
    for d in discovered:
        logger.info(f"→ {d['name']} ({d['ip']})")

    return discovered


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


# --- Main entrypoint ---
async def main():
    start_http_server(8000)
    logger.info("Prometheus metrics server started on port 8000")

    # 🔍 Automatically discover SNMP devices
    nodes = await discover_nodes("192.168.0.129/32", community="public")

    if not nodes:
        logger.warning("No SNMP devices discovered!")
        return

    await asyncio.gather(*(poll_node(node) for node in nodes))


if __name__ == "__main__":
    asyncio.run(main())