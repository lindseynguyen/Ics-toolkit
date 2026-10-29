# MITRE ATT&CK for ICS mapping

Mapping the technology in each challenge group to the ATT&CK for ICS
techniques it exercises. Useful both for writing up a CTF and for turning the
same observations into detections at work.

| Tactic | Technique | How it appears on the wire |
|---|---|---|
| Discovery | Remote System Discovery (T0846) | BACnet `who-Is` broadcast; Modbus unit-id sweep; ARP/ICMP fan-out |
| Discovery | Remote System Information Discovery (T0888) | S7comm SZL reads 0x0011 / 0x001C; Modbus FC 43 device identification; BACnet `readProperty` on `object-name`, `vendor-identifier` |
| Collection | Automated Collection (T0802) | bulk `readPropertyMultiple`; staircase Modbus block reads; historian SQL queries |
| Collection | Point & Tag Identification (T0861) | reading tag names and units out of registers, DBs or BACnet object names |
| Collection | Monitor Process State (T0801) | sustained polling of level, flow and status points before acting |
| Lateral Movement | Default Credentials (T0812) | FTP/HTTP/SNMP/TDS logins in cleartext; `private`/`public` SNMP communities |
| Lateral Movement | Exploitation of Remote Services (T0866) | an IT-side exploit, then a jump host inside the OT DMZ |
| Execution | Change Operating Mode (T0858) | S7comm `plc-stop` / PI-service; DNP3 cold restart; BACnet `reinitializeDevice` |
| Execution | Modify Controller Tasking (T0821) | S7comm `request-download` of OB/FB/DB blocks |
| Inhibit Response Function | Denial of Service (T0814) | BACnet `deviceCommunicationControl` disable |
| Inhibit Response Function | Block Reporting Message (T0804) | IEC-104 `STOPDT act`; DNP3 `disable-unsolicited` |
| Inhibit Response Function | Alarm Suppression (T0878) | forcing alarm coils off; writing BACnet `out-of-service`; disabling notification classes |
| Inhibit Response Function | Data Destruction (T0809) | clearing diagnostic buffers and logs after the fact |
| Impair Process Control | Unauthorized Command Message (T0855) | Modbus FC 5/6/15/16 writes; IEC-104 `C_SC_NA_1` / `C_SE_NC_1`; DNP3 CROB |
| Impair Process Control | Modify Parameter (T0836) | writing a trip limit, a dose setpoint or a PID gain |
| Impair Process Control | Spoof Reporting Message (T0856) | BACnet `out-of-service` + a written `present-value`, so the HMI shows a value the field does not have |
| Impact | Manipulation of Control (T0831) | the sequence of commands that drives plant out of its envelope |
| Impact | Loss of Safety (T0880) / Loss of Control (T0827) | the consequence the narrative describes |
| Impact | Damage to Property (T0879) | overdose, overpressure, dry-run of a pump |

## Observations that generalise

- **Inhibit before impair.** In almost every scenario the adversary silences
  reporting *first*. Detections on "the quiet" - a reporting channel that
  stops without a TCP close, an alarm point forced out of service - fire
  earlier than detections on the damaging command itself.
- **Reconnaissance is protocol-native.** SZL reads, device identification and
  object enumeration are legitimate functions. The signal is the *source* and
  the *rate*, not the function code.
- **Refusals are evidence.** Error PDUs, exception codes and negative
  activation confirmations tell you what the adversary tried and failed to do,
  which is often more informative than what succeeded.
- **One packet is enough.** A DCC disable, a TRIP CROB, a CPU STOP: there is
  no multi-stage payload to catch. Prevention is segmentation and
  allow-listing; detection has to work on single events.
