# Windows Network Log Analyzer

Windows desktop utility for investigating enterprise Wi-Fi onboarding and connectivity problems.

The project currently combines Windows Event Log analysis with live network diagnostics. This README is the working source of documentation for the project: new features, fixes, and design decisions should update it as part of the same change.

## Current status

This is an early prototype implemented primarily in [`network_log_analyzer.py`](network_log_analyzer.py). The built-in synthetic self-check passes and the module compiles with Python 3.12, but real Windows validation is still required.

The application is Windows-specific and uses:

- Python 3.11 or newer
- Tkinter for the desktop UI
- `pywin32` for Windows Event Log access
- `netsh`, `ipconfig`, `ping`, `nslookup`, and PowerShell for diagnostics

The analysis concepts are portable, but the current collectors are not. The next major architectural goal is support for macOS and Linux without pretending that their logs expose exactly the same information as Windows.

## Assessment of `requirements.txt`

The current [`requirements.txt`](requirements.txt) is not a product-requirements document. It is a dependency file containing one package:

```text
pywin32==306
```

That dependency is Windows-specific and is only needed by the current Windows Event Log reader. It should not block Linux or macOS development, but it does mean the current file is not a complete cross-platform dependency definition.

The likely future arrangement is:

- Put shared runtime dependencies in `pyproject.toml`.
- Add a platform marker for `pywin32`, for example `pywin32==306; sys_platform == 'win32'`.
- Keep development tools such as pytest, Ruff, and mypy in a separate development dependency group.
- Document operating-system tools separately because `nmcli`, `networksetup`, `journalctl`, PowerShell, and similar utilities are not Python packages.
- Treat Tkinter as a system/runtime capability: it is part of many Python installations, but Linux distributions may require a separate package such as `python3-tk`.

Until the packaging is refactored, Linux/macOS developers can install the source without `pywin32` for the platform-neutral work, provided they do not invoke the Windows Event Log path.

## Publication and ownership assessment

The current files appear to contain generic diagnostic code, standard Windows event IDs, standard operating-system commands, and no obvious credentials, tokens, captured logs, customer data, or organization-specific names. A preliminary repository scan found no obvious secrets.

That is not a legal determination that the project is non-proprietary. Before publishing it, confirm that:

- The code was written by you or you have permission to publish it.
- It was not created under an employer or client agreement that assigns ownership or restricts disclosure.
- No future exports, screenshots, sample logs, certificate details, SSIDs, MAC addresses, usernames, hostnames, or IP addresses are committed.
- The full Git history has been checked, not only the current working tree.
- A `.gitignore` excludes virtual environments, caches, exported diagnostic reports, and local IDE files where appropriate.
- The tracked `.idea/` directory is removed or reduced to intentionally shared project settings before publication.
- A license is added. Without one, others can view the code but generally do not receive clear permission to use, modify, or redistribute it.

Based on the current contents alone, the technical risk of making the source public looks low; the ownership and employment-context questions still need your confirmation.

## Quickest wins without a Windows machine

Most of the highest-value work can be completed on Linux or macOS:

1. Extract the platform-neutral timeline and issue logic from the Tkinter application.
2. Define normalized event and diagnostic models with provider/source fields.
3. Fix source-aware event severity and issue classification.
4. Add fixture-based tests for Windows-shaped event records and command output.
5. Make command execution return structured stdout, stderr, return code, and timeout state.
6. Add worker error handling and remove Tkinter access from background threads.
7. Build a Linux collector first using detected `nmcli`, `ip`, `journalctl`, and DNS tools.
8. Build a macOS collector using detected `networksetup`, `system_profiler`, `scutil`, and `log show` capabilities.
9. Add Linux CI and macOS CI for unit tests, syntax checks, and mocked collectors.

The main work that cannot be honestly validated without Windows is the actual `pywin32` Event Log integration, Windows provider/event mappings, PowerShell output, permissions, and the WLAN report. Those should be marked as Windows-unverified until a Windows runner or test machine is available.

### Completed quick wins

- Declared `pywin32` as a Windows-only dependency in both packaging files and refreshed `uv.lock`.
- Made the command runner tolerate platforms where Windows’ `CREATE_NO_WINDOW` flag does not exist.
- Verified the self-check and a real non-Windows command-runner invocation on Linux.
- Made event severity channel-aware and added regression coverage for reused IDs such as `1002` and `1003`.
- Made failed commands report their exit code and stderr instead of appearing as empty output.

## Cross-platform expansion

Yes, the project can be expanded to macOS and Linux. The Tkinter interface and much of the reporting layer can be shared, but the current command and event-log code must be separated behind platform-specific collectors.

### What can be shared

- Normalized models for interfaces, access points, IP configuration, certificates, connection attempts, events, and findings
- Connection-stage concepts such as association, authentication, DHCP, DNS, gateway reachability, and disconnects
- Timeline correlation, evidence linking, severity, confidence, and recommendation logic
- Report/export formats
- Most of the UI

### What must be platform-specific

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Wi-Fi state | `netsh wlan` | `networksetup`, `system_profiler`, possibly CoreWLAN APIs | `nmcli`, `iw`, or NetworkManager/D-Bus |
| IP and routes | `ipconfig` | `ifconfig`, `scutil`, `route` | `ip`, `nmcli`, NetworkManager or systemd-networkd |
| DNS | `nslookup` | `scutil --dns`, `dscacheutil`, `dig` | `resolvectl`, `nmcli`, `dig` |
| Logs | Windows Event Log | Unified Logging via `log show` | `journalctl`, NetworkManager logs, kernel logs, or syslog |
| Certificates | Windows certificate stores / PowerShell | Keychain / `security` | NSS, OpenSSL, Java, or distribution-specific stores |
| WLAN profiles | `netsh wlan show profiles` | Network preferences / plist data | NetworkManager connection profiles or `wpa_supplicant` |
| WLAN report | Windows WLAN report | No direct equivalent; collect targeted log and interface evidence | No direct equivalent; collect targeted log and interface evidence |

There is no universal event-ID mapping across these operating systems. The current Windows event IDs must remain in a Windows provider module. macOS and Linux collectors should translate their native records into a common event vocabulary, retaining the original source, identifier, message, and raw evidence.

### Recommended architecture

Refactor the single file into four layers:

1. **Platform collectors** — Windows, macOS, and Linux implementations for commands, logs, certificates, profiles, and interface data.
2. **Normalized data model** — typed records such as `NetworkInterface`, `NetworkEvent`, `ConnectionAttempt`, `DiagnosticResult`, and `Finding`.
3. **Platform-neutral analysis** — correlation, timelines, evidence linking, confidence, and recommendations.
4. **Presentation** — Tkinter UI, text export, and eventually JSON/CLI output.

Collectors should advertise capabilities instead of assuming every platform supports every diagnostic. For example, a macOS collector can report that a Windows-style WLAN report is unavailable while still providing Wi-Fi state, routes, DNS, certificates, and unified-log evidence.

### Suggested rollout

1. Extract the current Windows command and event-log code into a `platforms/windows` backend without changing behavior.
2. Define normalized models and convert the existing Windows collector to produce them.
3. Add a read-only Linux backend using `nmcli`/`ip`/`journalctl`, with NetworkManager detection and graceful fallbacks.
4. Add a read-only macOS backend using `networksetup`/`system_profiler`/`scutil`/`log show`.
5. Move timeline and issue logic to the normalized layer.
6. Add platform fixture tests and capability-aware UI messaging.

The first cross-platform release should focus on read-only diagnostics and evidence collection. Automated network changes, profile modification, certificate installation, and privileged operations should remain out of scope until platform-specific permissions and safety behavior are well defined.

## What the application does

### Event-log analysis

The scanner reads recent events from these channels:

- WLAN AutoConfig
- DHCP Client
- Network Profile
- Dot3SVCM / wired 802.1X
- EapHost
- OneX
- CAPI2
- Certificate Services Client lifecycle
- System, filtered for likely wireless NIC providers
- Security, filtered for selected 802.1X events

Events are converted into `LogEvent` objects, assigned a severity, and displayed in an “All Events” view. The analyzer then attempts to build connection timelines and produces heuristic issue messages for authentication, EAP, certificate, DHCP, roaming, disconnect, and NIC-driver problems.

### Live diagnostics

The diagnostics workflow collects:

- Current Wi-Fi interface state
- IP configuration
- Default-gateway ping results
- DNS resolution tests
- Wireless adapter and driver information
- Nearby access points
- Saved WLAN profile details
- Client-authentication certificates
- The Windows WLAN report

The results can be exported as a text report from the GUI.

## Running it

Install the current dependencies:

```powershell
py -m pip install -r requirements.txt
```

Run the application:

```powershell
py network_log_analyzer.py
```

Run the non-GUI self-check:

```powershell
py network_log_analyzer.py --self-check
```

The event scanner may require access to protected Windows logs. The code is intended to work without elevation for most live diagnostics, but access to the Security log, machine certificate store, or report generation is not guaranteed.

## Code map

| Area | Location | Responsibility |
|---|---|---|
| Event and reason-code definitions | `network_log_analyzer.py` near the top | Hard-coded provider/event metadata |
| Command execution | `_run_cmd` | Runs Windows commands and returns text |
| Live diagnostics | `get_*`, `test_*`, and `generate_wlan_report` | Collects local network state |
| Event reading | `read_events` | Reads and filters Windows Event Log records |
| Timeline analysis | `analyze_connection_timeline` | Correlates events into connection attempts |
| Issue detection | `find_issues` | Generates heuristic findings and recommendations |
| GUI | `NetworkLogAnalyzerApp` | Displays results and exports reports |
| Verification | `_self_check` | Tests a small set of synthetic scenarios |

## Known problems and risks

These are current limitations, not completed features. They are ordered roughly by impact.

### High priority

1. **Packaging does not declare the runtime dependency.**

   [`requirements.txt`](requirements.txt) contains `pywin32`, but [`pyproject.toml`](pyproject.toml) declares `dependencies = []`. Installing the project through package tooling will not necessarily install the library required for event scanning.

2. **Event severity is keyed only by event ID.**

   Windows event IDs are provider/channel-specific. IDs such as `1002` and `1003` are used by multiple mappings in this project, but global `ERROR_EVENT_IDS` and `WARNING_EVENT_IDS` sets classify them without considering their source. This can turn warnings into errors and generate the wrong recommendations.

3. **Issue detection also ignores event source in places.**

   For example, event `1003` from the certificate lifecycle channel can be counted as a DHCP failure because the DHCP rule checks only the numeric ID.

4. **Event messages are not rendered as Windows event messages.**

   The reader joins raw `StringInserts` with pipe characters. This may omit the actual event description and makes reason-code extraction unreliable. `win32evtlogutil` is imported but not currently used to format messages.

5. **Timeline correlation is global and time-based.**

   Events are associated without an interface GUID, connection attempt ID, SSID, or BSSID. Multiple adapters, roaming, overlapping attempts, or unrelated certificate/EAP activity can therefore produce an incorrect timeline.

6. **Background errors can leave the UI stuck.**

   The scan and diagnostics worker methods do not have a reliable error/finally path. An unexpected exception can leave a button disabled and the status message unchanged.

### Medium priority

7. **Tkinter state is accessed from a worker thread.**

   `_scan_logs` reads the Tkinter `StringVar` from a background thread. GUI state should be read on the main thread and passed into the worker.

8. **Read failures can look like valid partial scans.**

   `read_events` catches broad exceptions and returns the events collected so far. The UI distinguishes an inaccessible channel from an incomplete read poorly.

9. **Parsers depend on English Windows output.**

   The `netsh`, `ipconfig`, `ping`, `nslookup`, and WLAN-profile parsers search for English labels and output formats. They will be unreliable on localized systems.

10. **Command results are still text-based.**

    Failed commands now expose their exit code and stderr, but `_run_cmd` still returns formatted strings rather than a structured result object. A future collector API should separate stdout, stderr, return code, and timeout state.

11. **The WLAN HTML report is parsed with brittle regular expressions.**

    Changes in Windows report markup, line breaks, or unrelated numbers can produce missing or incorrect summaries.

12. **“No significant issues” can mean “no usable evidence.”**

    Empty, disabled, inaccessible, or unrecognized logs are not clearly separated from a genuinely healthy time window.

13. **Some normal events are presented as problems.**

    For example, the presence of Security event `5632` is reported in the Issues tab even though the mapping describes it as an authentication request, not a failure. The 4-way handshake failure is also grouped under authentication failures.

14. **The self-check is narrow.**

    It covers synthetic timeline and issue cases but does not test real event records, provider mappings, permissions, localized output, PowerShell behavior, or GUI concurrency.

## Expansion roadmap

The roadmap is deliberately incremental. Each phase should leave the application usable and should add tests or fixtures before changing the corresponding behavior.

### Phase 1 — Make the existing prototype trustworthy

- Declare `pywin32` in `pyproject.toml` and establish one dependency-management path.
- Split event metadata into provider/channel-aware definitions.
- Store severity and issue classification with each event mapping instead of global ID sets.
- Render event messages using the Windows provider metadata where available.
- Preserve provider, channel, record ID, task, keywords, and raw inserts for troubleshooting.
- Return structured command results containing stdout, stderr, return code, and timeout state.
- Add clear “unavailable,” “partial,” “empty,” and “healthy” result states.
- Add worker exception handling and guaranteed UI re-enablement.
- Move all Tkinter reads and writes onto the main thread.

### Phase 2 — Improve analysis quality

- Correlate events by interface GUID and, where available, SSID/BSSID.
- Replace the single global state machine with explicit connection-attempt objects.
- Add configurable correlation windows and deduplication.
- Distinguish association, authentication, certificate validation, 4-way handshake, DHCP, and network-profile outcomes.
- Attach evidence events to every recommendation so users can inspect why it was produced.
- Avoid treating informational audit events as failures.
- Add confidence levels to heuristic findings.

### Phase 3 — Build a durable evidence model

- Introduce typed models for event records, command results, diagnostics, findings, and timelines.
- Add JSON export alongside the human-readable text report.
- Record collection time, machine identity, timezone, permissions, and unavailable sources.
- Make reports deterministic and suitable for support-case attachments.
- Add redaction controls for usernames, certificate subjects, MAC addresses, SSIDs, and IP addresses.

### Phase 4 — Testing and maintainability

- Split the single module into packages for collection, parsing, analysis, reporting, and UI.
- Add unit tests for each parser using captured Windows fixtures.
- Add tests for overlapping event IDs across providers.
- Add tests for localized or malformed command output.
- Add integration tests on a Windows runner where possible.
- Add linting, formatting, and type checking to the development workflow.

### Phase 5 — User-facing improvements

- Add filters by time, severity, source, SSID, interface, and finding type.
- Add searchable and sortable event tables.
- Add a progress indicator and cancellation support.
- Add a “copy evidence” action for individual findings.
- Add a clear distinction between current-state diagnostics and historical event analysis.
- Consider a CLI mode for remote or automated collection.

## Definition of done for future changes

A change is complete when:

- The README is updated if behavior, assumptions, or operational steps change.
- The relevant unit/self-check coverage is added or updated.
- Failures are visible to the user and do not leave the GUI in a stuck state.
- Findings identify the source evidence behind them.
- Windows-specific behavior is tested or explicitly marked as unverified.
- No new parser or event mapping is added without documenting its provider/channel and expected format.

## Working principles

- Treat event provider and channel as part of an event’s identity; event ID alone is insufficient.
- Prefer evidence-backed findings over broad recommendations.
- Never present missing data as proof that the network is healthy.
- Keep raw evidence available even when producing a simplified summary.
- Protect sensitive network, identity, certificate, and machine information in exported reports.
- Update this README alongside implementation changes so it remains the project’s shared design record.
