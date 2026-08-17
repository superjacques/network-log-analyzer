# Network Log Analyzer

Cross-platform desktop utility for investigating enterprise Wi-Fi onboarding and connectivity problems on Windows, macOS, and Linux.

The project combines platform-native log collection with live network diagnostics. This README is the working source of documentation for the project: new features, fixes, and design decisions should update it as part of the same change.

## Current status

This is an early cross-platform prototype implemented primarily in [`network_log_analyzer.py`](network_log_analyzer.py). The built-in synthetic self-check passes and the module compiles with Python 3.12. Linux and macOS have received local validation; Windows still requires direct validation on that operating system.

The application uses:

- Python 3.11 or newer
- Tkinter for the desktop UI
- `pywin32` and Windows-native commands on Windows
- `journalctl`, NetworkManager, `ip`, resolver tools, and `ping` on Linux
- Unified Logging and standard macOS networking commands on macOS

The interface and normalized event model are shared, while each operating system retains its native collectors and capabilities.

## Python and Tk requirements

Python and Tkinter are separate requirements. This project requires:

- Python 3.11 or newer.
- A working Tkinter installation built for the same Python interpreter used to launch the app.
- The operating-system tools listed above.

[`requirements.txt`](requirements.txt) contains only the platform-specific Python package:

```text
pywin32==306
```

That dependency is Windows-specific and is only needed by the Windows Event Log reader. Linux and macOS skip it automatically because of the platform marker. The same dependency is declared in [`pyproject.toml`](pyproject.toml).

Tkinter is not installed from `requirements.txt`:

- On Windows, use a normal Python installer that includes Tcl/Tk.
- On macOS, use a current Python distribution with a matching Tk runtime; the older system Tk supplied by macOS may produce deprecation warnings or rendering problems.
- On Debian/Ubuntu Linux, install the system package `python3-tk` if importing `tkinter` fails. Other distributions provide an equivalent Tk package.

To verify the active interpreter has Tkinter, run:

```bash
python3 -c "import tkinter; print(tkinter.TkVersion)"
```

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
- Added an initial Linux `journalctl` collector for network-related events; Linux scanning now populates the existing event view.
- Added Linux live diagnostics for NetworkManager state/profiles, nearby Wi-Fi, IP/routes, DNS, and gateway ping.
- Added initial Linux issue detection for authentication, DHCP, DNS, disconnect, and wireless-driver messages.
- Added a macOS Unified Log collector, native diagnostics, and a classic-Tk full interface; the macOS interface has now been visually validated.
- Bounded Linux journal collection to network services and kernel messages so high-volume unrelated logs do not trigger false “journal unavailable” timeouts.

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
| Network report | Windows WLAN report | Native evidence report from Wi-Fi, routes, DNS, and Unified Log | Native evidence from journal and live diagnostics |

There is no universal event-ID mapping across these operating systems. The current Windows event IDs must remain in a Windows provider module. macOS and Linux collectors should translate their native records into a common event vocabulary, retaining the original source, identifier, message, and raw evidence.

### Recommended architecture

Refactor the single file into four layers:

1. **Platform collectors** — Windows, macOS, and Linux implementations for commands, logs, certificates, profiles, and interface data.
2. **Normalized data model** — typed records such as `NetworkInterface`, `NetworkEvent`, `ConnectionAttempt`, `DiagnosticResult`, and `Finding`.
3. **Platform-neutral analysis** — correlation, timelines, evidence linking, confidence, and recommendations.
4. **Presentation** — Tkinter UI, text export, and eventually JSON/CLI output.

Collectors should advertise capabilities instead of assuming every platform supports every diagnostic. The macOS collector provides a native evidence report rather than attempting to reproduce the Windows-specific WLAN report format.

### Suggested rollout

1. Extract the current Windows command and event-log code into a `platforms/windows` backend without changing behavior.
2. Define normalized models and convert the existing Windows collector to produce them.
3. Extend the initial Linux backend using `nmcli`/`ip` and NetworkManager-specific evidence, with graceful fallbacks.
4. Extend the initial macOS backend using `networksetup`/`system_profiler`/`scutil` alongside the Unified Log collector.
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
- A platform-appropriate network evidence report

The results can be exported as a text report from the GUI.

On Linux, the implemented live diagnostics use `nmcli`, `ip`, `resolvectl`/`getent`, and `ping`. Linux certificate inventory remains explicitly unsupported for now. Linux issue detection is message-based and intentionally lower-confidence than provider-specific Windows analysis.

On macOS, the bundled system Tcl/Tk may print a deprecation warning. The application suppresses that warning and selects Tk's portable `clam` theme. A newer Python distribution with a current Tk runtime is still recommended if the GUI renders incorrectly.

macOS now uses the same complete seven-tab interface as Windows and Linux. Its diagnostics use `networksetup`, `system_profiler`, `ifconfig`, `netstat`, `scutil`, `route`, `ping`, `dscacheutil`, and `security`; macOS no longer falls through to Windows `netsh`, `ipconfig`, or PowerShell commands. The Network Report tab produces a compact macOS network-evidence report from native Wi-Fi, route, DNS, and recent Unified Log data.

## Running it

Install the current dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run the application:

```bash
python3 network_log_analyzer.py
```

Run the non-GUI self-check:

```bash
python3 network_log_analyzer.py --self-check
```

The event scanner may require access to protected Windows logs. The code is intended to work without elevation for most live diagnostics, but access to the Security log, machine certificate store, or report generation is not guaranteed.

## Code map

| Area | Location | Responsibility |
|---|---|---|
| Event and reason-code definitions | `network_log_analyzer.py` near the top | Hard-coded provider/event metadata |
| Command execution | `_run_cmd` | Runs platform-native commands and returns text |
| Live diagnostics | `get_*`, `test_*`, and `generate_wlan_report` | Collects local network state |
| Event reading | `read_events`, `read_linux_events`, `read_macos_events` | Reads and normalizes native log records |
| Timeline analysis | `analyze_connection_timeline` | Correlates events into connection attempts |
| Issue detection | `find_issues` | Generates heuristic findings and recommendations |
| GUI | `NetworkLogAnalyzerApp` | Displays results and exports reports |
| Verification | `_self_check` | Tests a small set of synthetic scenarios |

## Known problems and risks

These are current limitations, not completed features. They are ordered roughly by impact.

### High priority

1. **Event severity is keyed only by event ID.**

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
