# Honeypots

Honeypots in cybersecurity are decoy systems, services, or resources deliberately designed to appear vulnerable and attractive to attackers. They act as digital bait by mimicking real production assets like servers, databases, web apps, IoT devices, or network endpoints to lure malicious actors away from genuine targets while capturing detailed information about their behavior, tools, tactics, techniques, and procedures (TTPs).

The core idea is deception-based defense: instead of only blocking known threats, honeypots invite interaction so defenders can observe, log, analyze, and sometimes contain or study attacks in a controlled environment without risking actual data or systems.

## Primary Purposes
- Early detection of unauthorized access or scanning
- Threat intelligence gathering (IPs, payloads, malware samples, credentials, exploit attempts)
- Diversion and distraction to waste attacker time
- Research into emerging threats and attacker tradecraft
- Deception layer as part of broader deception technology programs

## Main Classifications

### By Purpose or Deployment Strategy
- Production honeypots
  Deployed inside or alongside real organizational networks. Usually low or medium interaction to minimize risk. Integrate with SIEM or IDS for alerts.
- Research honeypots
  Isolated systems run by researchers or threat-intel providers. Often high interaction for deeper observation and malware collection.

### By Level of Interaction
- Low interaction
  Emulate basic protocol responses. Safe and easy to deploy but limited data and easily fingerprinted.
- Medium interaction
  Simulate realistic services with partial shells or file systems. Richer logs but higher risk.
- High interaction
  Real operating systems or services with intentional vulnerabilities. Most realistic but highest risk; must be heavily isolated.

## Specialized Types
- Honeynets for studying lateral movement
- Spam traps or email honeypots for phishing and spam
- Malware honeypots to capture payloads
- Web or application honeypots (including ICS/SCADA)

## Popular Open-Source Tools
- Cowrie (SSH/Telnet, full session logging)
- Dionaea (multi-protocol malware capture)
- T-Pot (bundled platform with dashboards)
- OpenCanary, Conpot, Honeytrap

## How Honeypots Work in Practice
1. Deploy (usually containerized or VM based).
2. Expose to the internet or internal network.
3. Log every interaction (probes, logins, commands, files).
4. Analyze and enrich (SIEM, dashboards, IOC extraction).
5. Feed into maps or other visualizations.

## Benefits
- Low false positives
- Captures attacker ground truth
- Improves threat intel and visualization feeds
- Relatively low cost for low-interaction setups

## Limitations and Risks
- Detection by sophisticated attackers
- Risk of compromise for high-interaction systems
- High noise from automated scans
- Legal and ethical constraints
- Maintenance required to stay realistic

## Relation to This Repo
Honeypots are an excellent upstream feed for threat maps because they provide real attacker IPs, geolocations, attack types, and timestamps that can be processed, enriched, and visualized using the scripts and tooling in this repo.
