# ICS Console PLC Security Assessment

ICS Console is a local defensive PLC and OT asset discovery dashboard. It combines a browser-based HTML interface with a Python standard-library backend for authorized network checks, protocol visibility, packet inspection, and report-ready findings.

## Project Identity

| Item | Details |
| --- | --- |
| Project name | ICS Console |
| Developer | Bhushan Hiralal Bhole |
| Domain | Industrial automation, PLC networks, OT cybersecurity |
| Platform | Local web dashboard with Python backend |
| Dependencies | Python 3 standard library only |
| Release version | 1.0.0 |

## What It Does

- Serves a local dashboard at `http://127.0.0.1:8800`.
- Accepts authorized IP, CIDR, or comma-separated target input.
- Checks common industrial protocol ports such as Modbus/TCP, S7 ISO-TSAP, EtherNet/IP, OPC UA, IEC-104, DNP3, FINS, CODESYS, Niagara Fox, and related services.
- Performs limited read-only identity-style probes for selected protocols.
- Displays protocol exposure, packet details, diagnostics, severity notes, and mitigation guidance.
- Exports results as JSON for documentation or review.

## Safety Boundary

This repository is for defensive learning, lab use, and authorized assessment only. The tool is not an exploit framework, does not fuzz controllers, and does not send state-changing write commands. Only scan equipment and networks that you own or have explicit permission to test.

## Quick Start

```bash
python3 ics_console.py
```

Then open:

```text
http://127.0.0.1:8800
```

Keep `ics_console.py` and `ics_console.html` in the same folder.

## Repository Contents

| Path | Description |
| --- | --- |
| `ics_console.py` | Python backend and read-only scan engine |
| `ics_console.html` | Local dashboard UI and packet inspector |
| `docs/README.md` | Report and documentation notes |
| `release/README.md` | Release asset notes |

## Release Assets

The latest release includes:

- `ICS_Console_Source_Package-v1.0.0.zip`
- `ICS_Console_PLC_Security_Assessment_Report-v1.0.0.pdf`
- `ICS_Console_PLC_Security_Assessment_Report-v1.0.0.docx`

## Important Note

The original uploaded package filename used the word `hack`, but the source and report describe a defensive assessment console. This repository presents it as an authorized PLC and OT security awareness project.

## License

Copyright (c) Bhushan Hiralal Bhole. All rights reserved unless a separate license is added.
