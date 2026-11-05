# 08 - Lessons Learned & Next Steps

## What worked well
- **Isolation first:** moving from NAT to a LAN segment *before* detonation, with clipboard/drag-and-drop/shared folders off.
- **Clean snapshot** made repeated, safe executions trivial.
- **Procmon backing file** prevented memory exhaustion when events exceeded 20 million.
- **Static -> dynamic correlation:** strings and capa predicted the ransom note, wallpaper and file renaming that were later observed.

## Pitfalls / observations
- The sample encrypted the **analyst toolkit itself** (`C:\Tools`) - always revert to the snapshot; never keep tools you need only on the analysis VM.
- Without admin rights, `HKCR` writes failed (ACCESS DENIED). Run a second pass **as administrator** to compare behavior.
- Regshot deltas include normal OS noise; rely on Procmon to attribute changes.
- Procmon filters limited to `BlackBasta.exe` may hide child-process activity (`cmd.exe`) - widen filters for a complete tree.

## Limitations of this study
- No debugger/decompiler-level analysis of the encryption scheme.
- No internet, so no real TOR/C2 behavior.
- Single run, single OS build.

## Next steps
1. Reverse the encryption routine in **Ghidra / x64dbg** (key generation, chunking, header/footer format).
2. Capture the **`vssadmin`/child-process command lines** with Sysmon + a process tree export.
3. Run elevated and non-elevated comparisons.
4. Write and test a **YARA rule** from unique strings and the code pattern.
5. Analyze the **FakeNet-NG PCAP** and Wireshark capture for DNS/HTTP attempts.
6. Repeat with newer Black Basta builds (e.g. ESXi/Linux variants) for a comparison table.

## References
- Mandiant FLARE-VM: https://github.com/mandiant/flare-vm
- FLOSS: https://github.com/mandiant/flare-floss
- capa: https://github.com/mandiant/capa
- FakeNet-NG: https://github.com/mandiant/flare-fakenet-ng
- Sysinternals Suite: https://learn.microsoft.com/sysinternals/
- MITRE ATT&CK: https://attack.mitre.org/
- Elastic protections-artifacts (YARA): https://github.com/elastic/protections-artifacts
