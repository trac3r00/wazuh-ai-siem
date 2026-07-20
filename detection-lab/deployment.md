# Detection lab deployment notes

These notes describe how to stage the artifacts under `detection-lab/`. They intentionally avoid prescribing a Wazuh, Windows, hypervisor, or Sysmon installation version because those components are not managed by this repository.

Use current vendor documentation to create an isolated Wazuh environment and enroll the test endpoints. Do not run adversary simulations on production systems or networks.

## Lab components

A minimal environment needs:

- A Wazuh manager that accepts custom rule files.
- A Windows endpoint with the Wazuh agent.
- Sysmon process-creation telemetry for the rules that inspect Event ID 1.
- Windows Security auditing for Kerberos events 4768 and 4769 when testing the identity rules.
- A disposable Linux endpoint only when evaluating the `iptables` active-response script.

Keep management access separate from the network used for simulations, take recoverable snapshots, and use test accounts and addresses.

## 1. Collect Sysmon events

On the Windows agent, add the following block inside the existing `<ossec_config>` element in `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the Wazuh agent:

```powershell
Restart-Service WazuhSvc
```

Before adding custom rules, confirm that process-creation events arrive with the fields referenced by the XML, especially `win.system.providerName`, `win.system.eventID`, `win.eventdata.image`, and `win.eventdata.commandLine`.

## 2. Select a Windows rule set

The directory includes two alternatives:

- `rules/windows/mimikatz-detection.xml` contains rules `100001` through `100011` for process, Kerberos, and simulated file events.
- `rules/windows/custom_sysmon_rules.xml` contains self-contained Sysmon rules `100004`, `100007`, and `100008`.

The three IDs in `custom_sysmon_rules.xml` overlap with IDs in `mimikatz-detection.xml`. Do not install both files unchanged. Choose one set or assign unique local rule IDs, then update and retest any parent references.

Copy the selected XML into the custom rules directory used by the lab's Wazuh manager. Validate it with the rule and configuration validation facilities supplied by that Wazuh installation before restarting the manager.

## 3. Validate event fields before detection behavior

The rule files assume specific decoded fields:

| Detection | Required event data |
| --- | --- |
| Process and command-line rules | Sysmon Event ID 1 and populated image or command-line fields |
| Kerberoasting heuristic | Security Event ID 4769 and ticket encryption type `0x17` |
| AS-REP roasting heuristic | Security Event ID 4768, encryption type `0x17`, and pre-authentication type `0` |
| Simulated file-drop rule | A parent event matching Wazuh rule `554` and the literal test filename in rule `100011` |

Treat these rules as hypotheses to validate against known benign and synthetic malicious events. Several patterns are broad and can produce false positives; the comments in `mimikatz-detection.xml` identify known mapping and scope concerns.

## 4. Stage the active-response experiment

The two active-response artifacts are not a complete installable pair:

- `active-response/wazuh_manager_config.xml` defines `firewall-drop-suricata` but sets its executable to `firewall-drop`.
- `active-response/linux/custom-firewall-drop.sh` is a different executable that reads `src_ip` from standard input and inserts an `iptables` drop rule.

Do not merge the manager snippet and assume it invokes the custom script. If evaluating the script, first design a matching Wazuh command entry for the installed version and test the full add/delete protocol expected by Wazuh.

The checked-in shell script has significant lab-only limitations:

- It accepts an extracted address without validating that it is a safe IPv4 source.
- It adds a permanent `INPUT` drop rule and has no removal path.
- It does not deduplicate rules.
- It writes the complete event payload to `/tmp/ar-input.txt`.
- It requires GNU `grep` PCRE support and `iptables` at `/usr/sbin/iptables`.

Use a console-accessible disposable endpoint. Supply only synthetic payloads and remove test firewall rules after the experiment using the host's normal firewall administration process.

## Verification checklist

- [ ] The test endpoints are isolated from production networks.
- [ ] Windows Event ID 1 arrives with the fields used by the selected rules.
- [ ] Events 4768 and 4769 are present before testing Kerberos rules.
- [ ] No duplicate Wazuh rule IDs are loaded.
- [ ] Each rule is tested against at least one expected match and one benign non-match.
- [ ] Active-response testing uses console access and a disposable Linux endpoint.
- [ ] Test logs and `/tmp/ar-input.txt` are handled as potentially sensitive data.

Return to the [Detection lab overview](README.md).
