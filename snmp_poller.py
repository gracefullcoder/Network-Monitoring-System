import asyncio
import logging
import datetime
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,      # async version
    next_cmd
)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# --- OIDs for system info ---
SYS_OIDS = {
    "System Description": "1.3.6.1.2.1.1.1.0",
    "System Name": "1.3.6.1.2.1.1.5.0",
    "System Location": "1.3.6.1.2.1.1.6.0",
    "System Uptime": "1.3.6.1.2.1.1.3.0"
}

# --- Interface OIDs ---
IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"
IF_OPERSTATUS_OID = "1.3.6.1.2.1.2.2.1.8"
IF_INOCTETS_OID = "1.3.6.1.2.1.2.2.1.10"
IF_OUTOCTETS_OID = "1.3.6.1.2.1.2.2.1.16"
IF_INERRORS_OID = "1.3.6.1.2.1.2.2.1.14"
IF_OUTERRORS_OID = "1.3.6.1.2.1.2.2.1.20"


async def snmp_get(snmp_engine, community_data, transport, oid):
    try:
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmp_engine,
            community_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        if errorIndication:
            logger.error(f"SNMP error for {oid}: {errorIndication}")
            return None
        if errorStatus:
            logger.error(f"SNMP error for {oid}: {errorStatus.prettyPrint()} at {errorIndex}")
            return None
        for _, val in varBinds:
            return val
    except Exception as e:
        logger.exception(f"Exception for {oid}: {e}")
        return None


async def snmp_walk(snmp_engine, community_data, transport, base_oid):
    """Return dict {index: value} for a table OID"""
    result = {}
    try:
        index = 1
        while True:
            oid = f"{base_oid}.{index}"
            val = await snmp_get(snmp_engine, community_data, transport, oid)
            if val is None:
                break  # no more entries
            result[index] = val
            index += 1
    except Exception as e:
        logger.exception(f"Exception during SNMP walk for {base_oid}: {e}")
    return result


async def poll_node(node, interval=10):
    ip = node["ip"]
    community = node.get("community", "public")
    name = node.get("name", ip)

    transport = await UdpTransportTarget.create((ip, 161))
    snmp_engine = SnmpEngine()
    community_data = CommunityData(community)

    while True:
        logger.info(f"--- Poll Result for {name} ({ip}) ---")

        # --- System info ---
        for label, oid in SYS_OIDS.items():
            val = await snmp_get(snmp_engine, community_data, transport, oid)
            if val is None:
                continue
            if label == "System Uptime":
                # convert centiseconds to human-readable
                seconds = int(val) // 100
                human = str(datetime.timedelta(seconds=seconds))
                logger.info(f"{label}: {human} ({val} centiseconds)")
            else:
                logger.info(f"{label}: {val.prettyPrint()}")

        # --- Interface info ---
        if_descr = await snmp_walk(snmp_engine, community_data, transport, IF_DESCR_OID)
        if_operstatus = await snmp_walk(snmp_engine, community_data, transport, IF_OPERSTATUS_OID)

        for if_index, if_name in if_descr.items():
            if int(if_operstatus.get(if_index, 2)) != 1:
                continue  # skip down interfaces
            # Poll counters
            in_octets = await snmp_get(snmp_engine, community_data, transport, f"{IF_INOCTETS_OID}.{if_index}")
            out_octets = await snmp_get(snmp_engine, community_data, transport, f"{IF_OUTOCTETS_OID}.{if_index}")
            in_errors = await snmp_get(snmp_engine, community_data, transport, f"{IF_INERRORS_OID}.{if_index}")
            out_errors = await snmp_get(snmp_engine, community_data, transport, f"{IF_OUTERRORS_OID}.{if_index}")

            logger.info(f"Interface: {if_name}")
            if in_octets is not None:
                logger.info(f"  InOctets: {int(in_octets)} bytes")
            if out_octets is not None:
                logger.info(f"  OutOctets: {int(out_octets)} bytes")
            if in_errors is not None:
                logger.info(f"  InErrors: {int(in_errors)}")
            if out_errors is not None:
                logger.info(f"  OutErrors: {int(out_errors)}")

        await asyncio.sleep(interval)


async def main():
    nodes = [
        {"name": "PC-Friend1", "ip": "192.168.1.154"},
    ]
    await asyncio.gather(*(poll_node(node) for node in nodes))


if __name__ == "__main__":
    asyncio.run(main())
