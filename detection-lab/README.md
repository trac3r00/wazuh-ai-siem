# Detection lab

This directory contains reference detection content for Windows event collection and a Linux active-response experiment. It is separate from the rules installed by `scripts/setup.sh`.

Use these files only in an isolated test environment. Review rule IDs, parent rules, field names, and response behavior against the Wazuh version and event schema in that environment before deployment.

## Contents

```text
detection-lab/
├── active-response/
│   ├── linux/custom-firewall-drop.sh
│   └── wazuh_manager_config.xml
├── rules/windows/
│   ├── custom_sysmon_rules.xml
│   └── mimikatz-detection.xml
└── deployment.md
```

## Windows detection rules

`rules/windows/mimikatz-detection.xml` defines the following rules:

| Rule | Detection logic | ATT&CK mapping |
| --- | --- | --- |
| `100001` | Image path containing `mimikatz` | T1003 |
| `100002` | Mimikatz-related command-line terms | T1003 |
| `100003` | Encoded PowerShell command | T1059.001 |
| `100004` | PowerShell download cradle | T1059.001 |
| `100005` | `net user` or `net localgroup` with `/add` | T1136.001 |
| `100006` | Scheduled task creation | T1053.005 |
| `100007` | Windows Defender disable command | T1562.001 |
| `100008` | Security-service stop command | T1562.001 |
| `100009` | Event 4769 with RC4 ticket encryption | T1558.003 |
| `100010` | Event 4768 with RC4 and no pre-authentication | T1558.004 |
| `100011` | A specifically named simulated dropper observed by parent rule `554` | T1105 |

The file contains review comments for rules whose scope or ATT&CK mapping needs refinement. In particular, rule `100005` combines account creation and group membership changes, and rule `100011` is intentionally tied to a synthetic filename.

`rules/windows/custom_sysmon_rules.xml` contains self-contained Sysmon Event ID 1 rules for:

- PowerShell download commands (`100004`).
- Disabling Defender real-time monitoring (`100007`).
- Stopping or disabling selected Windows security services (`100008`).

These three IDs overlap with `mimikatz-detection.xml`. Do not load both files unchanged in the same Wazuh manager; select one implementation or assign unique IDs and retest the parent relationships.

## Required Windows telemetry

The process-creation rules expect Wazuh fields under `win.system` and `win.eventdata`, including:

- `win.system.providerName`
- `win.system.eventID`
- `win.eventdata.image`
- `win.eventdata.commandLine`

The Kerberos rules expect Windows Security events 4768 and 4769 with ticket encryption and pre-authentication fields. Configure endpoint auditing and Wazuh event-channel collection so those fields are present before testing the rules.

## Active-response experiment

`active-response/linux/custom-firewall-drop.sh`:

1. Reads the complete Wazuh active-response payload from standard input.
2. Extracts a JSON field named `src_ip`.
3. Inserts an `iptables` `INPUT` drop rule for that source.
4. Writes debug data to `/tmp/ar-debug.log` and `/tmp/ar-input.txt`.

The script does not implement deletion, timeout rollback, address validation, or duplicate-rule handling. It also records the complete input payload in `/tmp`, which may contain sensitive event data. Treat it as a lab artifact, not a production response control.

`active-response/wazuh_manager_config.xml` is a separate Wazuh configuration example for a command named `firewall-drop-suricata`. Its `<executable>` value is `firewall-drop`, not the checked-in `custom-firewall-drop.sh`. The two files are not wired together automatically.

See [Deployment notes](deployment.md) for a safe staging sequence.
