"""ics-ctf-toolkit - OT/ICS artefact analysis helpers.

Modules
-------
pcapio    pcap / pcapng reader, L2-L4 decode, TCP stream assembly
bacnet    BACnet/IP (BVLC/NPDU/APDU) incident decoder
s7comm    S7comm + S7comm-plus (ISO-on-TCP) decoder
modbus    Modbus/TCP decoder, register map, scan heuristics
iec104    IEC 60870-5-104 decoder, command timeline, select-before-operate audit
dnp3      DNP3 link/transport/application decoder
creds     cleartext credential harvesting (FTP/HTTP/SNMP/LDAP/TDS/...)
carve     blob and archive carving out of binary artefacts
gbcart    Game Boy cartridge image (.gb/.gbc) inspector
dosbin    MS-DOS .COM / MZ .EXE static inspector
"""
__version__ = "0.1.0"
__all__ = ["pcapio", "bacnet", "s7comm", "modbus", "iec104", "dnp3",
           "creds", "carve", "gbcart", "dosbin", "util"]
