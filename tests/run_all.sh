#!/usr/bin/env bash
# Smoke-test every tool against the synthetic fixtures.
#   python3 tests/make_fixtures.py fixtures/ && bash tests/run_all.sh fixtures/
set -u
FX="${1:-fixtures}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$ROOT/tools"
fail=0

run() {
  echo "--- $*"
  if ! python3 "$@" > /dev/null; then
    echo "FAILED: $*"
    fail=$((fail + 1))
  fi
}

run "$T/pcap-overview.py"     "$FX/bacnet_bms.pcap" "$FX/modbus_plc.pcap"
run "$T/bacnet-triage.py"     "$FX/bacnet_bms.pcap"
run "$T/bacnet-triage.py"     "$FX/bacnet_bms.pcap" --dcc
run "$T/bacnet-triage.py"     "$FX/bacnet_bms.pcap" --writes
run "$T/bacnet-triage.py"     "$FX/bacnet_bms.pcap" --timeline
run "$T/s7-triage.py"         "$FX/s7comm_wtp.pcap"
run "$T/s7-triage.py"         "$FX/s7comm_wtp.pcap" --szl
run "$T/s7-triage.py"         "$FX/s7comm_wtp.pcap" --blocks
run "$T/s7-triage.py"         "$FX/s7comm_wtp.pcap" --control
run "$T/modbus-triage.py"     "$FX/modbus_plc.pcap"
run "$T/modbus-triage.py"     "$FX/modbus_plc.pcap" --map
run "$T/modbus-triage.py"     "$FX/modbus_plc.pcap" --floats
run "$T/modbus-triage.py"     "$FX/modbus_plc.pcap" --strings
run "$T/modbus-triage.py"     "$FX/modbus_plc.pcap" --timeline
run "$T/iec104-triage.py"     "$FX/iec104_rtu.pcap"
run "$T/iec104-triage.py"     "$FX/iec104_rtu.pcap" --sbo
run "$T/iec104-triage.py"     "$FX/iec104_rtu.pcap" --ioa
run "$T/dnp3-triage.py"       "$FX/dnp3_outstation.pcap"
run "$T/dnp3-triage.py"       "$FX/dnp3_outstation.pcap" --timeline
run "$T/cleartext-creds.py"   "$FX/cleartext_dmz.pcap"
run "$T/pcap-merge.py"        "$FX/_merged.pcap" "$FX/modbus_plc.pcap" "$FX/iec104_rtu.pcap"
run "$T/stream-carve.py"      "$FX/cleartext_dmz.pcap"
run "$T/stream-carve.py"      "$FX/cleartext_dmz.pcap" --stream 0 --ascii
run "$T/gb-cart-inspect.py"   "$FX/rig.gb"
run "$T/gb-cart-inspect.py"   "$FX/rig.gb" --blobs
run "$T/gb-cart-inspect.py"   "$FX/rig.gb" --vectors
run "$T/dos-bin-inspect.py"   "$FX/SETPT16.COM"
run "$T/dos-bin-inspect.py"   "$FX/SETPT16.COM" --ints
run "$T/blob-carve.py"        "$FX/rig.gb" --entropy
run "$T/blob-carve.py"        "$FX/rig.gb" --xor

echo
if [ "$fail" -eq 0 ]; then
  echo "all tools ran successfully"
else
  echo "$fail tool invocation(s) failed"
  exit 1
fi
