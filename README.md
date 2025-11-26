🛡️ Warzone-1 (THM – Medium) – PCAP C2 Investigation
📌 Summary

This investigation analyzes a network alert indicating Potentially Bad Traffic and Malware Command-and-Control (C2) Activity. As a SOC Tier 1 Analyst, I examined the PCAP, identified malicious communications, extracted indicators of compromise, and confirmed the alert as a true positive.
Using Brim, Wireshark, CyberChef, and VirusTotal, I mapped the full network activity, identified the malware family MirrorBlast, and correlated external infrastructure to a known threat group.


🧠 Investigation Overview

Objective:
Analyze PCAP traffic, detect malicious outbound connections, identify payload downloads, perform threat attribution, and reconstruct the full attack chain.

Tools Used:

Brim

Wireshark

PCAP Analysis

CyberChef

VirusTotal

MITRE ATT&CK Mapping

🔍 What I Did

Inspected PCAP for C2 alerts and confirmed the Brim detection.

Identified source & destination IPs (defanged).

Attributed the malicious IP to a known threat group via VirusTotal.

Identified malware family: MirrorBlast (seen on page 3). 

Warzone1-THM

Analyzed HTTP traffic to extract user-agent information.

Discovered additional malicious IPs tied to the same attack flow.

Extracted downloaded payload names from Brim (pages 4–5). 

Warzone1-THM

Followed TCP streams in Wireshark to uncover full file paths and dropped payloads (.exe + .bin).

Mapped end-to-end infection chain.

🚨 Key Findings

Malware Command & Control Activity confirmed (Brim alert).

Threat group attribution linked via VirusTotal Community tab.

Malware family: MirrorBlast.

Multiple malicious IPs involved in multi-stage delivery.

Downloaded payloads: two for each malicious host.

User-Agent artifacts revealed script/tool origin.

Local file paths extracted from TCP streams (page 6–7). 

Warzone1-THM

Full attack chain reconstructed:
C2 Alert → Suspicious IPs → Downloads → Payload Paths → Attribution.

🧩 MITRE ATT&CK Mapping
| Tactic            | Technique                         | ID        |
| ----------------- | --------------------------------- | --------- |
| Command & Control | Web-Based C2                      | **T1102** |
| Command & Control | Encrypted/Tunneled Traffic        | **T1573** |
| Delivery          | Malicious File Download           | **T1105** |
| Reconnaissance    | Network Scanning via HTTP Headers | **T1592** |
| Execution         | User Execution of Payloads        | **T1204** |

🧪 IOCs (Indicators of Compromise)
| Type             | Value                                |
| ---------------- | ------------------------------------ |
| Malware Family   | MirrorBlast                          |
| C2 IP (defanged) | e.g., 198[.]229[.]130[.]81           |
| Additional IPs   | (from page 5 of PDF)                 |
| Downloaded Files | 100prd_load.msi, <other>             |
| File Paths       | Extracted from TCP streams (page 6)  |

🎯 What I Learned

Efficient PCAP filtering using Brim.

Identifying and validating malware C2 behavior.

Using VirusTotal for threat group attribution.

Tracing multi-stage attack chains in Wireshark.

Extracting payload file paths via TCP streams.

Understanding distributed malware infrastructure.

🏁 Conclusion

The network activity was confirmed to be part of a coordinated malware campaign linked to MirrorBlast.
By correlating PCAP data, threat intelligence, and payload analysis, I reconstructed the full kill chain and validated the alert as a legitimate security incident.
This project demonstrates proficiency in PCAP forensics, C2 analysis, threat attribution, and end-to-end SOC investigation.
