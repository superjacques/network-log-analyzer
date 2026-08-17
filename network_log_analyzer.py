"""
Windows Network Log Analyzer — Enterprise Wireless Edition
Analyzes WLAN, DHCP, Network Profile, EAP, 802.1X, certificate,
NIC driver, and Security audit event logs to show the full path
of enterprise wireless onboarding.

Also provides live diagnostics: Wi-Fi snapshot, DNS test, gateway ping,
NIC driver info, nearby APs, WLAN profile inspection, certificate
inventory, and WLAN report generation.

Requires: pywin32 (pip install pywin32)
All diagnostics work WITHOUT admin rights.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import subprocess
import re
import os
import sys

try:
    import win32evtlog
    import win32evtlogutil
    import pywintypes
except ImportError:
    win32evtlog = None


# =============================================================================
# WLAN Disconnect/Failure Reason Codes (IEEE 802.11 + Microsoft extensions)
# =============================================================================

WLAN_REASON_CODES = {
    0: "Success / No reason",
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated — station leaving",
    4: "Disassociated due to inactivity",
    5: "Disassociated — AP unable to handle all stations",
    6: "Class 2 frame received from non-authenticated station",
    7: "Class 3 frame received from non-associated station",
    8: "Disassociated — station leaving BSS",
    9: "Association request not authenticated",
    10: "Disassociated — power capability unacceptable",
    11: "Disassociated — supported channels unacceptable",
    12: "Reserved",
    13: "Invalid information element",
    14: "MIC failure (TKIP countermeasures)",
    15: "4-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "4-Way Handshake IE mismatch",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSN IE version",
    22: "Invalid RSN IE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected by security policy",
    25: "TDLS unreachable",
    26: "TDLS unspecified",
    27: "SSP requested but not supported",
    34: "Requested service change rejected",
    45: "Peer initiated action",
    # Microsoft-specific reason codes (high values)
    32769: "Network not available (SSID not found)",
    32770: "AP rejected connection",
    32771: "Network authentication type mismatch",
    32772: "Network cipher mismatch",
    32773: "Profile settings mismatch",
    32774: "Connection attempt cancelled by user",
    32775: "Pre-association security failure",
    32776: "Profile not found on the system",
    32777: "No auto-connection attempted (manual profile)",
    32784: "MSMSEC profile invalid",
    32785: "MSMSEC key type not supported",
    32786: "MSMSEC auth/cipher pair invalid",
    36864: "Connection dropped during roaming",
    36865: "AP disassociated due to insufficient resources",
    36866: "AP deauthenticated for security reasons",
    36867: "Connection dropped — AP sent deauth",
}


# =============================================================================
# Event ID Mappings
# =============================================================================

WLAN_EVENTS = {
    # Connection lifecycle
    8000: ("Connecting", "WLAN service started connecting to network"),
    8001: ("Connected", "Successfully connected to wireless network"),
    8002: ("Disconnected", "Disconnected from wireless network"),
    8003: ("Connection Failed", "Failed to connect to wireless network"),
    # Authentication
    8004: ("Auth Started", "Started authentication with wireless network"),
    8005: ("Auth Succeeded", "Authentication with wireless network succeeded"),
    8006: ("Auth Failed", "Authentication with wireless network failed"),
    # Connection mode/reason detail
    8010: ("Connection Mode", "Connection attempt mode details"),
    8011: ("Connection Profile", "Profile used for connection attempt"),
    8012: ("Interface State", "Wireless interface state change"),
    8013: ("Security Started", "Security negotiation started"),
    8014: ("Security Completed", "Security negotiation completed"),
    8015: ("Security Failed", "Security negotiation failed"),
    # Association
    11000: ("Association Started", "Wireless association started"),
    11001: ("Association Succeeded", "Wireless association succeeded"),
    11002: ("Association Failed", "Wireless association failed"),
    11003: ("Association Cleared", "Previous association cleared"),
    11004: ("4-Way Handshake Started", "WPA/WPA2 4-way handshake started"),
    11005: ("4-Way Handshake Succeeded", "WPA/WPA2 4-way handshake succeeded"),
    11006: ("4-Way Handshake Failed", "WPA/WPA2 4-way handshake failed"),
    11010: ("Group Key Handshake OK", "Group key handshake succeeded"),
    # Roaming (with BSSID detail)
    12000: ("Roaming Needed", "Roaming decision triggered — signal below threshold"),
    12001: ("Roaming Candidate Found", "Candidate AP identified for roaming"),
    12002: ("Roaming Candidate List", "Full candidate AP list built"),
    12011: ("Roaming Started", "Wireless roaming started"),
    12012: ("Roaming Succeeded", "Wireless roaming completed"),
    12013: ("Roaming Failed", "Wireless roaming failed"),
    # Scanning
    20000: ("Scan Started", "Wireless scan started"),
    20001: ("Scan Results", "Wireless scan completed with results"),
    20002: ("Scan Failed", "Wireless scan failed"),
    20003: ("BSS Entry Added", "New BSS entry added from scan"),
}

DHCP_EVENTS = {
    50036: ("DHCP Request Sent", "DHCP Discover/Request sent"),
    50037: ("DHCP Offer Received", "DHCP Offer received"),
    50038: ("DHCP Ack Received", "DHCP Ack received - IP assigned"),
    50039: ("DHCP Nack", "DHCP Nack received - IP assignment refused"),
    50040: ("DHCP Timeout", "DHCP request timed out"),
    1000: ("DHCP Lease Obtained", "IP address lease obtained"),
    1001: ("DHCP Lease Renewed", "IP address lease renewed"),
    1002: ("DHCP Lease Released", "IP address lease released"),
    1003: ("DHCP Lease Failed", "Failed to obtain IP address lease"),
}

NETWORK_PROFILE_EVENTS = {
    10000: ("Network Connected", "Network connected and identified"),
    10001: ("Network Disconnected", "Network disconnected"),
    4001: ("Profile Changed", "Network profile/category changed"),
}

DOT3_EVENTS = {
    15500: ("802.1X Auth Started", "802.1X authentication started"),
    15501: ("802.1X Auth Succeeded", "802.1X authentication succeeded"),
    15502: ("802.1X Auth Failed", "802.1X authentication failed"),
}

EAPHOST_EVENTS = {
    2001: ("EAP Auth Started", "EAP method negotiation started"),
    2002: ("EAP Auth Succeeded", "EAP authentication succeeded"),
    2003: ("EAP Auth Failed", "EAP authentication failed"),
    2004: ("EAP Method Selected", "EAP method selected for authentication"),
    2100: ("EAP-TLS Started", "EAP-TLS certificate handshake initiated"),
    2101: ("EAP-TLS Succeeded", "EAP-TLS handshake succeeded"),
    2102: ("EAP-TLS Failed", "EAP-TLS handshake failed — cert issue"),
    2104: ("EAP Identity Sent", "EAP identity response sent"),
}

ONEX_EVENTS = {
    1: ("OneX Auth Started", "802.1X supplicant started"),
    2: ("OneX Auth Succeeded", "802.1X supplicant succeeded"),
    3: ("OneX Auth Failed", "802.1X supplicant failed"),
    4: ("OneX Auth Restarted", "802.1X restarted (timeout/NAK)"),
    5: ("OneX Credentials Prompted", "802.1X prompted for credentials"),
    6: ("OneX Auth Timeout", "802.1X timed out waiting for server"),
    10: ("OneX EAPOL Key", "EAPOL key frame received"),
}

CAPI2_EVENTS = {
    11: ("Cert Chain Built", "Certificate chain building completed"),
    30: ("Cert Verify Failed", "Certificate verification failed"),
    40: ("Cert Revocation Check", "CRL/OCSP check performed"),
    41: ("Cert Revocation Failed", "CRL/OCSP unreachable"),
    50: ("Cert Trust Error", "Certificate trust error"),
    53: ("Cert Expired", "Certificate time validity failed"),
    70: ("Cert Key Access", "Private key accessed"),
    80: ("Cert Auto-Enroll", "Auto-enrollment triggered"),
    82: ("Cert Auto-Enroll Failed", "Auto-enrollment failed"),
}

# System log NIC driver events — source names vary by vendor
NIC_DRIVER_EVENTS = {
    27: ("NIC Reset", "Network adapter was reset by the driver"),
    32: ("NIC Disconnected", "Network adapter link disconnected"),
    33: ("NIC Connected", "Network adapter link connected"),
    36: ("NIC Power Off", "Network adapter entering low power state"),
    37: ("NIC Power On", "Network adapter resuming from low power"),
    5000: ("NIC Warning", "Network adapter driver warning"),
    5001: ("NIC Error", "Network adapter driver error"),
    5002: ("NIC Firmware Error", "Network adapter firmware error"),
    5004: ("NIC Tx Hang", "Network adapter transmit queue stalled"),
    5007: ("NIC Auth Offload Fail", "Hardware authentication offload failed"),
}

# Security audit — event 5632 for wireless 802.1X
SECURITY_WIRELESS_EVENTS = {
    5632: ("802.1X Auth Request", "Wireless 802.1X authentication attempt (Security audit)"),
    5633: ("Wired 802.1X Auth", "Wired 802.1X authentication attempt"),
}

# Certificate lifecycle
CERT_LIFECYCLE_EVENTS = {
    1001: ("Cert Enrollment OK", "Certificate enrollment succeeded"),
    1002: ("Cert Enrollment Failed", "Certificate enrollment failed"),
    1003: ("Cert Expiry Warning", "Certificate approaching expiration"),
    1004: ("Cert Expired", "Certificate has expired"),
    1006: ("Cert Renewal Started", "Certificate renewal initiated"),
    1007: ("Cert Renewal OK", "Certificate renewal succeeded"),
    1008: ("Cert Renewal Failed", "Certificate renewal failed"),
}

EVENT_SEVERITY_BY_LOG = {
    "Microsoft-Windows-WLAN-AutoConfig/Operational": {
        8002: "WARNING", 8003: "ERROR", 8006: "ERROR", 8015: "ERROR",
        11002: "ERROR", 11006: "ERROR", 12000: "WARNING",
        12011: "WARNING", 12013: "ERROR", 20002: "ERROR",
    },
    "Microsoft-Windows-Dhcp-Client/Admin": {
        50039: "ERROR", 50040: "ERROR", 1003: "ERROR",
    },
    "Microsoft-Windows-NetworkProfile/Operational": {
        10001: "WARNING",
    },
    "Microsoft-Windows-Dot3SVCM/Operational": {
        15502: "ERROR",
    },
    "Microsoft-Windows-EapHost/Operational": {
        2003: "ERROR", 2102: "ERROR",
    },
    "Microsoft-Windows-OneX/Operational": {
        3: "ERROR", 4: "WARNING", 5: "WARNING", 6: "ERROR",
    },
    "Microsoft-Windows-CAPI2/Operational": {
        30: "ERROR", 41: "ERROR", 50: "ERROR", 53: "ERROR", 82: "ERROR",
    },
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational": {
        1002: "ERROR", 1003: "WARNING", 1004: "ERROR",
        1006: "WARNING", 1008: "ERROR",
    },
    "System": {
        27: "WARNING", 36: "WARNING", 5000: "WARNING",
        5001: "ERROR", 5002: "ERROR", 5004: "ERROR", 5007: "ERROR",
    },
}

LOG_SOURCES = [
    ("Microsoft-Windows-WLAN-AutoConfig/Operational", WLAN_EVENTS),
    ("Microsoft-Windows-Dhcp-Client/Admin", DHCP_EVENTS),
    ("Microsoft-Windows-NetworkProfile/Operational", NETWORK_PROFILE_EVENTS),
    ("Microsoft-Windows-Dot3SVCM/Operational", DOT3_EVENTS),
    ("Microsoft-Windows-EapHost/Operational", EAPHOST_EVENTS),
    ("Microsoft-Windows-OneX/Operational", ONEX_EVENTS),
    ("Microsoft-Windows-CAPI2/Operational", CAPI2_EVENTS),
    ("Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational", CERT_LIFECYCLE_EVENTS),
    ("System", NIC_DRIVER_EVENTS),
    ("Security", SECURITY_WIRELESS_EVENTS),
]

# NIC driver source name patterns to filter System log
NIC_SOURCE_PATTERNS = re.compile(
    r"(netwtw|netwlv|netwns|netwsw|ndis|netvsc|rtl|realtek|qca|ath|mrvl|bcm|intel)", re.IGNORECASE
)


def _event_severity(log_name, event_id):
    """Return severity using the event channel as well as the numeric ID."""
    return EVENT_SEVERITY_BY_LOG.get(log_name, {}).get(event_id, "INFO")


# =============================================================================
# Live Diagnostic Functions (all work without admin rights)
# =============================================================================

def _run_cmd(cmd, timeout=15):
    """Run a command and return stdout, or a useful bracketed error string."""
    try:
        # CREATE_NO_WINDOW exists only on Windows. Keep the runner importable
        # and testable on other platforms while preserving Windows behavior.
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=creationflags
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            if not detail:
                detail = f"exit code {result.returncode}"
            return f"[Command failed with exit code {result.returncode}: {detail}]"
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[Command timed out]"
    except Exception as e:
        return f"[Error: {e}]"


def get_wifi_snapshot():
    """Get current Wi-Fi interface status via netsh. No admin needed."""
    output = _run_cmd(["netsh", "wlan", "show", "interfaces"])
    if not output or output.startswith("["):
        return "Wi-Fi interface information unavailable.\n" + output

    lines = output.splitlines()
    summary = "=== Current Wi-Fi Connection ===\n\n"
    fields_of_interest = [
        "Name", "State", "SSID", "BSSID", "Network type", "Radio type",
        "Authentication", "Cipher", "Channel", "Band", "Receive rate",
        "Transmit rate", "Signal", "Profile",
    ]
    for line in lines:
        for field in fields_of_interest:
            if line.strip().startswith(field):
                summary += line.strip() + "\n"
                break

    signal_match = re.search(r"Signal\s*:\s*(\d+)%", output)
    if signal_match:
        sig = int(signal_match.group(1))
        if sig < 40:
            summary += f"\n⚠ WEAK SIGNAL ({sig}%) — likely cause of connectivity issues.\n"
            summary += "  Recommend moving closer to AP or checking for interference.\n"
        elif sig < 60:
            summary += f"\n⚠ MARGINAL SIGNAL ({sig}%) — may cause intermittent drops.\n"

    return summary


def get_nearby_networks():
    """List nearby wireless networks. No admin needed."""
    output = _run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"])
    if not output or output.startswith("["):
        return "Nearby network scan unavailable.\n" + output
    return "=== Nearby Wireless Networks ===\n\n" + output


def get_ip_config():
    """Get IP configuration. No admin needed."""
    output = _run_cmd(["ipconfig", "/all"])
    if not output or output.startswith("["):
        return "IP configuration unavailable.\n" + output

    sections = re.split(r"\r?\n(?=\S)", output)
    relevant = []
    for section in sections:
        lower = section.lower()
        if any(k in lower for k in ("wi-fi", "wireless", "wlan", "dns")):
            relevant.append(section)

    if relevant:
        return "=== IP Configuration (Wi-Fi) ===\n\n" + "\n\n".join(relevant)
    return "=== IP Configuration ===\n\n" + output


def test_dns_resolution():
    """Test DNS resolution for common targets. No admin needed."""
    targets = ["www.google.com", "dns.google", "login.microsoftonline.com"]
    results = "=== DNS Resolution Test ===\n\n"

    for target in targets:
        output = _run_cmd(["nslookup", target], timeout=5)
        if "Non-authoritative answer" in output or "Address" in output:
            addresses = re.findall(r"Address:\s*(.+)", output)
            resolved = addresses[1:] if len(addresses) > 1 else addresses
            results += f"  ✓ {target} → {', '.join(a.strip() for a in resolved)}\n"
        else:
            results += f"  ✗ {target} → FAILED to resolve\n"

    return results


def test_gateway_ping():
    """Ping default gateway. No admin needed."""
    ipconfig = _run_cmd(["ipconfig"])
    gateway_match = re.search(r"Default Gateway.*?:\s*([\d.]+)", ipconfig)
    if not gateway_match:
        return "=== Gateway Ping Test ===\n\n  Could not determine default gateway.\n"

    gateway = gateway_match.group(1)
    output = _run_cmd(["ping", "-n", "4", "-w", "1000", gateway], timeout=15)

    results = f"=== Gateway Ping Test ({gateway}) ===\n\n"
    results += output + "\n"

    if "Reply from" in output:
        loss_match = re.search(r"\((\d+)% loss\)", output)
        avg_match = re.search(r"Average = (\d+)ms", output)
        if loss_match and int(loss_match.group(1)) > 0:
            results += f"\n⚠ Packet loss ({loss_match.group(1)}%) — interference or congestion.\n"
        if avg_match and int(avg_match.group(1)) > 50:
            results += f"\n⚠ High latency ({avg_match.group(1)}ms) — expected <10ms for local GW.\n"
        elif avg_match:
            results += f"\n  ✓ Gateway reachable, {avg_match.group(1)}ms — healthy.\n"
    elif "Request timed out" in output or "Destination host unreachable" in output:
        results += "\n✗ GATEWAY UNREACHABLE — L2 up but no L3. Check VLAN/DHCP/ACLs.\n"

    return results


def get_nic_driver_info():
    """Get Wi-Fi NIC adapter and driver info. No admin needed."""
    ps_cmd = (
        "Get-NetAdapter | Where-Object {$_.PhysicalMediaType -match 'Wireless|Native 802.11' -or "
        "$_.Name -match 'Wi-Fi|Wireless|WLAN'} | "
        "Format-List Name, InterfaceDescription, Status, LinkSpeed, MacAddress, "
        "DriverVersion, DriverDate, DriverProvider, NdisVersion"
    )
    output = _run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=12)

    results = "=== NIC & Driver Information ===\n\n"
    if output and not output.startswith("["):
        results += output + "\n"
    else:
        fallback = _run_cmd(["netsh", "wlan", "show", "drivers"])
        results += fallback + "\n" if fallback else "Could not retrieve NIC driver info.\n"

    # Check driver age
    date_cmd = "(Get-NetAdapter | Where-Object {$_.Name -match 'Wi-Fi|Wireless|WLAN'}).DriverDate"
    date_output = _run_cmd(["powershell", "-NoProfile", "-Command", date_cmd], timeout=10)
    if date_output and not date_output.startswith("["):
        try:
            date_str = date_output.strip().split("\n")[0].strip()
            driver_date = None
            for fmt in ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                        "%m/%d/%Y %H:%M:%S"):
                try:
                    driver_date = datetime.strptime(date_str, fmt)
                    break
                except ValueError:
                    continue
            if driver_date:
                age_days = (datetime.now() - driver_date).days
                if age_days > 365:
                    results += (
                        f"\n⚠ DRIVER IS {age_days // 365} YEAR(S) OLD "
                        f"(dated {driver_date.strftime('%Y-%m-%d')}).\n"
                        f"  Outdated drivers cause Wi-Fi instability. Update from vendor.\n"
                    )
        except Exception:
            pass

    return results


def get_wlan_profiles():
    """Get WLAN profile configuration. No admin needed (keys excluded)."""
    list_output = _run_cmd(["netsh", "wlan", "show", "profiles"])
    if not list_output or "is not running" in list_output:
        return "WLAN service not running or no profiles found.\n"

    profiles = re.findall(r"All User Profile\s*:\s*(.+)", list_output)
    if not profiles:
        profiles = re.findall(r"Current User Profile\s*:\s*(.+)", list_output)
    if not profiles:
        return "No WLAN profiles found.\n" + list_output

    results = "=== Saved WLAN Profiles ===\n\n"
    results += f"Found {len(profiles)} profile(s):\n\n"

    for profile_name in profiles:
        profile_name = profile_name.strip()
        detail = _run_cmd(["netsh", "wlan", "show", "profile", f"name={profile_name}"])
        results += f"{'─' * 60}\nProfile: {profile_name}\n{'─' * 60}\n"

        important_fields = [
            "SSID name", "Network type", "Connection mode", "Authentication",
            "Cipher", "Security key", "802.1X", "EAP Type",
            "Number of SSIDs", "Connection type", "802.1X auth credential",
        ]
        for line in detail.splitlines():
            stripped = line.strip()
            for field in important_fields:
                if stripped.startswith(field):
                    results += f"  {stripped}\n"
                    break

        auth_match = re.search(r"Authentication\s*:\s*(.+)", detail)
        if auth_match:
            auth = auth_match.group(1).strip()
            if auth.lower() == "open":
                results += "  ⚠ OPEN network — no encryption!\n"

        onex_match = re.search(r"802\.1X\s*:\s*(.+)", detail)
        if onex_match and "enabled" in onex_match.group(1).lower():
            results += "  ℹ 802.1X enabled — uses certificate or credential-based auth\n"
            # Show EAP credential type
            cred_match = re.search(r"802\.1X auth credential\s*:\s*(.+)", detail, re.IGNORECASE)
            if cred_match:
                results += f"  ℹ Credential: {cred_match.group(1).strip()}\n"

        results += "\n"

    return results


def get_certificate_inventory():
    """
    List certificates relevant to 802.1X (Client Authentication EKU).
    Checks user store and machine store. No admin needed for user store.
    Machine store may be limited without admin but usually readable.
    """
    results = "=== Certificate Inventory (802.1X Relevant) ===\n\n"

    # User certificate store
    ps_user = (
        "$now = Get-Date; "
        "Get-ChildItem Cert:\\CurrentUser\\My | Where-Object {"
        "$_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.2'"  # Client Auth OID
        "} | ForEach-Object {"
        "$exp = $_.NotAfter; $days = ($exp - $now).Days; "
        "$status = if($days -lt 0){'EXPIRED'}elseif($days -lt 30){'EXPIRING SOON'}else{'Valid'}; "
        "Write-Output ('  Subject:    ' + $_.Subject); "
        "Write-Output ('  Issuer:     ' + $_.Issuer); "
        "Write-Output ('  Thumbprint: ' + $_.Thumbprint); "
        "Write-Output ('  Expires:    ' + $exp.ToString('yyyy-MM-dd') + ' (' + $status + ', ' + $days.ToString() + ' days)'); "
        "Write-Output ('  Has Key:    ' + $_.HasPrivateKey.ToString()); "
        "Write-Output ''; "
        "}"
    )
    user_output = _run_cmd(["powershell", "-NoProfile", "-Command", ps_user], timeout=15)

    results += "── User Certificate Store (CurrentUser\\My) ──\n\n"
    if user_output and not user_output.startswith("[") and user_output.strip():
        results += user_output + "\n"
    else:
        results += "  No Client Authentication certificates found in user store.\n\n"

    # Machine certificate store
    ps_machine = (
        "$now = Get-Date; "
        "Get-ChildItem Cert:\\LocalMachine\\My -ErrorAction SilentlyContinue | Where-Object {"
        "$_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.2'"
        "} | ForEach-Object {"
        "$exp = $_.NotAfter; $days = ($exp - $now).Days; "
        "$status = if($days -lt 0){'EXPIRED'}elseif($days -lt 30){'EXPIRING SOON'}else{'Valid'}; "
        "Write-Output ('  Subject:    ' + $_.Subject); "
        "Write-Output ('  Issuer:     ' + $_.Issuer); "
        "Write-Output ('  Thumbprint: ' + $_.Thumbprint); "
        "Write-Output ('  Expires:    ' + $exp.ToString('yyyy-MM-dd') + ' (' + $status + ', ' + $days.ToString() + ' days)'); "
        "Write-Output ('  Has Key:    ' + $_.HasPrivateKey.ToString()); "
        "Write-Output ''; "
        "}"
    )
    machine_output = _run_cmd(["powershell", "-NoProfile", "-Command", ps_machine], timeout=15)

    results += "── Machine Certificate Store (LocalMachine\\My) ──\n\n"
    if machine_output and not machine_output.startswith("[") and machine_output.strip():
        results += machine_output + "\n"
    else:
        results += "  No Client Authentication certificates found (or access denied).\n\n"

    # Check Trusted Root for enterprise CAs
    ps_root = (
        "Get-ChildItem Cert:\\LocalMachine\\Root -ErrorAction SilentlyContinue | "
        "Where-Object {$_.Subject -match 'DC=|CA|Certificate Authority'} | "
        "Select-Object -First 10 | ForEach-Object {"
        "Write-Output ('  ' + $_.Subject.Substring(0, [Math]::Min(80, $_.Subject.Length)) + "
        "' [Expires: ' + $_.NotAfter.ToString('yyyy-MM-dd') + ']'); "
        "}"
    )
    root_output = _run_cmd(["powershell", "-NoProfile", "-Command", ps_root], timeout=10)

    results += "── Enterprise Root CAs in Trusted Root Store ──\n\n"
    if root_output and not root_output.startswith("[") and root_output.strip():
        results += root_output + "\n"
    else:
        results += "  No enterprise CAs found (or access denied).\n\n"

    # Flag issues
    if user_output and "EXPIRED" in user_output:
        results += "\n⚠ EXPIRED CERTIFICATE(S) in user store! 802.1X will fail.\n"
    if machine_output and "EXPIRED" in machine_output:
        results += "\n⚠ EXPIRED CERTIFICATE(S) in machine store! Machine auth will fail.\n"
    if (not user_output or not user_output.strip()) and (not machine_output or not machine_output.strip()):
        results += (
            "\n⚠ NO CLIENT AUTH CERTIFICATES FOUND.\n"
            "  If using EAP-TLS, the device needs a valid certificate with\n"
            "  Client Authentication EKU (OID 1.3.6.1.5.5.7.3.2).\n"
            "  Check auto-enrollment GPO or SCEP/MDM certificate deployment.\n"
        )

    return results


def generate_wlan_report():
    """
    Trigger Windows built-in WLAN Report and extract summary.
    The report is generated at C:\\ProgramData\\Microsoft\\Windows\\WlanReport\\
    No admin needed to generate.
    """
    results = "=== Windows WLAN Report ===\n\n"

    # Generate the report
    output = _run_cmd(["netsh", "wlan", "show", "wlanreport"], timeout=30)

    report_path = os.path.join(
        os.environ.get("ProgramData", "C:\\ProgramData"),
        "Microsoft", "Windows", "WlanReport", "wlan-report-latest.html"
    )

    if os.path.exists(report_path):
        results += f"Report generated: {report_path}\n\n"

        # Read and extract key info from the HTML report
        try:
            with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                html = f.read()

            # Extract summary stats
            # Look for session durations, disconnect counts, error summaries
            results += "── Report Summary ──\n\n"

            # Connection sessions
            sessions = re.findall(r"Session Duration.*?(\d+:\d+:\d+)", html)
            if sessions:
                results += f"  Connection sessions found: {len(sessions)}\n"
                for i, s in enumerate(sessions[:10], 1):
                    results += f"    Session {i}: Duration {s}\n"

            # Disconnection reasons
            disconnect_reasons = re.findall(
                r"Disconnect Reason.*?:.*?(\d+)", html
            )
            if disconnect_reasons:
                results += f"\n  Disconnect events: {len(disconnect_reasons)}\n"
                reason_counts = defaultdict(int)
                for code in disconnect_reasons:
                    reason_counts[int(code)] += 1
                for code, count in sorted(reason_counts.items(), key=lambda x: -x[1])[:5]:
                    reason_text = WLAN_REASON_CODES.get(code, f"Unknown code {code}")
                    results += f"    Code {code} ({reason_text}): {count}x\n"

            # Interface errors
            errors = re.findall(r"(?:Error|Failed|Failure).*", html, re.IGNORECASE)
            unique_errors = set()
            for err in errors:
                # Clean HTML tags
                clean = re.sub(r"<[^>]+>", "", err).strip()
                if clean and len(clean) < 200:
                    unique_errors.add(clean)
            if unique_errors:
                results += f"\n  Error indicators ({len(unique_errors)} unique):\n"
                for err in list(unique_errors)[:10]:
                    results += f"    • {err[:100]}\n"

            if not sessions and not disconnect_reasons:
                results += "  Could not extract structured data from report.\n"
                results += f"  Open the HTML file directly for the full graphical view:\n"
                results += f"    {report_path}\n"

        except Exception as e:
            results += f"  Could not parse report: {e}\n"
            results += f"  Open directly: {report_path}\n"
    else:
        results += "Report generation failed or file not found.\n"
        if output:
            results += output + "\n"

    return results


# =============================================================================
# Event Log Reading & Analysis
# =============================================================================

class LogEvent:
    """Single parsed event from Windows Event Log."""
    __slots__ = ("timestamp", "event_id", "source", "label", "description",
                 "message", "severity", "reason_code")

    def __init__(self, timestamp, event_id, source, label, description,
                 message, severity, reason_code=None):
        self.timestamp = timestamp
        self.event_id = event_id
        self.source = source
        self.label = label
        self.description = description
        self.message = message
        self.severity = severity
        self.reason_code = reason_code


def _extract_reason_code(message):
    """Try to extract a reason code from event message string inserts."""
    # Reason codes often appear as a numeric field in the message
    match = re.search(r"Reason Code:\s*(\d+)|reason[:\s]+(\d+)", message, re.IGNORECASE)
    if match:
        code = int(match.group(1) or match.group(2))
        return code
    # Also check for raw numeric values that look like reason codes
    # in specific positions for WLAN events
    parts = message.split("|")
    for part in parts:
        part = part.strip()
        if part.isdigit():
            val = int(part)
            if val in WLAN_REASON_CODES:
                return val
    return None


def read_events(log_name, event_map, hours_back=24):
    """Read events from a Windows Event Log channel.
    Returns list of LogEvent, or None if the channel is inaccessible/disabled."""
    events = []
    cutoff = datetime.now() - timedelta(hours=hours_back)

    # Special handling for System log — we only want NIC driver events
    is_system_log = (log_name == "System")
    is_security_log = (log_name == "Security")

    try:
        handle = win32evtlog.OpenEventLog(None, log_name)
    except Exception:
        return None

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    try:
        while True:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break
            for record in records:
                ts = record.TimeGenerated
                try:
                    timestamp = datetime(ts.year, ts.month, ts.day,
                                         ts.hour, ts.minute, ts.second)
                except Exception:
                    continue

                if timestamp < cutoff:
                    return events

                eid = record.EventID & 0xFFFF
                source_name = record.SourceName or ""

                # For System log, filter by NIC driver source names
                if is_system_log:
                    if not NIC_SOURCE_PATTERNS.search(source_name):
                        continue
                    if eid not in event_map:
                        # Capture any event from NIC driver sources as generic
                        msg_parts = record.StringInserts or []
                        message = " | ".join(msg_parts) if msg_parts else ""
                        # Only include errors/warnings from EventType
                        evt_type = record.EventType
                        if evt_type == 1:  # Error
                            events.append(LogEvent(
                                timestamp, eid, f"System/{source_name}",
                                f"NIC Driver Error ({source_name})",
                                f"Driver event ID {eid}",
                                message, "ERROR"
                            ))
                        elif evt_type == 2:  # Warning
                            events.append(LogEvent(
                                timestamp, eid, f"System/{source_name}",
                                f"NIC Driver Warning ({source_name})",
                                f"Driver event ID {eid}",
                                message, "WARNING"
                            ))
                        continue

                # For Security log, only grab wireless 802.1X events
                if is_security_log and eid not in event_map:
                    continue

                if eid in event_map:
                    label, desc = event_map[eid]
                    msg_parts = record.StringInserts or []
                    message = " | ".join(msg_parts) if msg_parts else ""

                    # Event IDs are only meaningful within their channel.
                    severity = _event_severity(log_name, eid)

                    # Extract reason code for WLAN disconnect/fail events
                    reason_code = None
                    if eid in (8002, 8003, 8006, 11002, 11006, 12013):
                        reason_code = _extract_reason_code(message)

                    # For System log events, include source in the log name
                    ev_source = f"System/{source_name}" if is_system_log else log_name

                    events.append(LogEvent(
                        timestamp, eid, ev_source, label, desc,
                        message, severity, reason_code
                    ))
    except Exception:
        pass
    finally:
        win32evtlog.CloseEventLog(handle)

    return events


def analyze_connection_timeline(events):
    """
    Analyze events to build the full enterprise wireless onboarding path.
    Returns list of (start_time, end_time, duration_seconds, outcome, details).
    """
    # ponytail: sequential scan correlating events by time proximity.
    # Upgrade: correlate by interface GUID for multi-adapter scenarios.
    timelines = []
    events_sorted = sorted(events, key=lambda e: e.timestamp)

    connection_start = None
    connection_phases = []

    START_IDS = {8000}
    SUCCESS_IDS = {8001}
    FAIL_IDS = {8003, 8006, 8015, 11002, 11006, 2003, 2102, 3, 6}

    for ev in events_sorted:
        if ev.event_id in START_IDS:
            if connection_start and connection_phases:
                last = connection_phases[-1]
                timelines.append((
                    connection_start, last.timestamp,
                    (last.timestamp - connection_start).total_seconds(),
                    "INCOMPLETE", "; ".join(p.label for p in connection_phases)
                ))
            connection_start = ev.timestamp
            connection_phases = [ev]

        elif ev.event_id == 11000 and connection_start is None:
            connection_start = ev.timestamp
            connection_phases = [ev]

        elif ev.event_id in (2001, 1) and connection_start is None:
            # EAP or OneX started without prior WLAN connect
            connection_start = ev.timestamp
            connection_phases = [ev]

        elif ev.event_id in SUCCESS_IDS:
            connection_phases.append(ev)
            if connection_start:
                timelines.append((
                    connection_start, ev.timestamp,
                    (ev.timestamp - connection_start).total_seconds(),
                    "SUCCESS", "; ".join(p.label for p in connection_phases)
                ))
            else:
                timelines.append((ev.timestamp, ev.timestamp, 0, "SUCCESS", ev.label))
            connection_start = None
            connection_phases = []

        elif ev.event_id in FAIL_IDS:
            connection_phases.append(ev)
            if connection_start:
                # Include reason code in the detail if available
                detail_parts = [p.label for p in connection_phases]
                if ev.reason_code is not None:
                    reason_text = WLAN_REASON_CODES.get(ev.reason_code, f"Code {ev.reason_code}")
                    detail_parts.append(f"[Reason: {reason_text}]")
                timelines.append((
                    connection_start, ev.timestamp,
                    (ev.timestamp - connection_start).total_seconds(),
                    "FAILED", "; ".join(detail_parts)
                ))
            else:
                detail = ev.label
                if ev.reason_code is not None:
                    detail += f" [Reason: {WLAN_REASON_CODES.get(ev.reason_code, str(ev.reason_code))}]"
                timelines.append((ev.timestamp, ev.timestamp, 0, "FAILED", detail))
            connection_start = None
            connection_phases = []

        elif connection_start:
            connection_phases.append(ev)

    if connection_start and connection_phases:
        last = connection_phases[-1]
        timelines.append((
            connection_start, last.timestamp,
            (last.timestamp - connection_start).total_seconds(),
            "INCOMPLETE", "; ".join(p.label for p in connection_phases)
        ))

    # Fallback: NetworkProfile disconnect→connect pairs
    if not timelines:
        np_events = [e for e in events_sorted
                     if e.source.endswith("NetworkProfile/Operational")]
        disconnect_time = None
        for ev in np_events:
            if ev.event_id == 10001:
                disconnect_time = ev.timestamp
            elif ev.event_id == 10000 and disconnect_time:
                duration = (ev.timestamp - disconnect_time).total_seconds()
                timelines.append((
                    disconnect_time, ev.timestamp, duration,
                    "SUCCESS", "Network Disconnected; Network Connected"
                ))
                disconnect_time = None

    return timelines


def find_issues(events):
    """Identify potential issues from the event stream."""
    issues = []
    error_events = [e for e in events if e.severity == "ERROR"]

    # WLAN auth failures
    auth_failures = [e for e in error_events if e.event_id in (8006, 11006, 15502)]
    if auth_failures:
        issues.append(
            f"AUTHENTICATION FAILURES: {len(auth_failures)} auth failure(s). "
            f"Check credentials, certificates, or RADIUS reachability."
        )

    # EAP failures
    eap_failures = [e for e in error_events if e.event_id in (2003, 2102)]
    if eap_failures:
        issues.append(
            f"EAP FAILURES: {len(eap_failures)} EAP failure(s). "
            f"EAP-TLS: verify client cert valid + correct EKU. PEAP: check credentials."
        )

    # OneX supplicant
    onex_failures = [e for e in error_events if e.event_id in (3, 6)]
    onex_timeouts = [e for e in onex_failures if e.event_id == 6]
    if onex_failures:
        msg = f"802.1X SUPPLICANT: {len(onex_failures)} failure(s). "
        if onex_timeouts:
            msg += f"{len(onex_timeouts)} timeout(s) — RADIUS unreachable/overloaded."
        else:
            msg += "Check EAP config and credential/cert validity."
        issues.append(msg)

    # Certificate issues (CAPI2)
    cert_expired = [e for e in error_events if e.event_id == 53]
    cert_verify = [e for e in error_events if e.event_id == 30]
    cert_revoke = [e for e in error_events if e.event_id == 41]
    cert_trust = [e for e in error_events if e.event_id == 50]
    cert_enroll = [e for e in error_events if e.event_id == 82]

    if cert_expired:
        issues.append(
            f"CERT EXPIRED: {len(cert_expired)} expired cert(s). "
            f"Check validity dates and system clock."
        )
    if cert_verify:
        issues.append(
            f"CERT VERIFICATION FAILED: {len(cert_verify)} failure(s). "
            f"Missing intermediate CA or RADIUS cert name mismatch."
        )
    if cert_revoke:
        issues.append(
            f"CERT REVOCATION CHECK FAILED: {len(cert_revoke)} failure(s). "
            f"CRL/OCSP unreachable — may need pre-auth network access."
        )
    if cert_trust:
        issues.append(
            f"CERT TRUST ERROR: {len(cert_trust)} error(s). "
            f"Root CA not trusted. Deploy via GPO/MDM."
        )
    if cert_enroll:
        issues.append(
            f"CERT AUTO-ENROLLMENT FAILED: {len(cert_enroll)} failure(s). "
            f"Check template permissions and CA availability."
        )

    # Certificate lifecycle events
    cert_lifecycle_fail = [e for e in error_events if e.event_id in (1002, 1004, 1008)
                          and "CertificateServicesClient" in e.source]
    if cert_lifecycle_fail:
        issues.append(
            f"CERT LIFECYCLE ISSUES: {len(cert_lifecycle_fail)} enrollment/renewal failure(s). "
            f"Certificate may not be getting issued or renewed properly."
        )

    # Connection failures
    conn_failures = [e for e in error_events if e.event_id == 8003]
    if conn_failures:
        # Include reason codes if available
        reasons = [e.reason_code for e in conn_failures if e.reason_code]
        msg = f"CONNECTION FAILURES: {len(conn_failures)} failed attempt(s)."
        if reasons:
            top_reason = max(set(reasons), key=reasons.count)
            msg += f" Most common reason: {WLAN_REASON_CODES.get(top_reason, f'Code {top_reason}')}."
        issues.append(msg)

    # Association failures
    assoc_failures = [e for e in error_events if e.event_id == 11002]
    if assoc_failures:
        issues.append(
            f"ASSOCIATION FAILURES: {len(assoc_failures)} failure(s). "
            f"AP overload, security mismatch, or MAC filtering."
        )

    # 4-way handshake failures
    handshake_fails = [e for e in error_events if e.event_id == 11006]
    if handshake_fails:
        issues.append(
            f"4-WAY HANDSHAKE FAILURES: {len(handshake_fails)} failure(s). "
            f"Key derivation issue — possible PMK mismatch after auth. "
            f"Check if RADIUS is sending correct keys."
        )

    # Security negotiation failures
    sec_fails = [e for e in error_events if e.event_id == 8015]
    if sec_fails:
        issues.append(
            f"SECURITY NEGOTIATION FAILED: {len(sec_fails)} failure(s). "
            f"Cipher/auth mismatch between profile and AP configuration."
        )

    # DHCP
    dhcp_failures = [e for e in error_events if e.event_id in (50039, 50040, 1003)]
    if dhcp_failures:
        issues.append(
            f"DHCP ISSUES: {len(dhcp_failures)} failure(s). "
            f"Check DHCP server, scope exhaustion, or VLAN assignment."
        )

    # Disconnects
    disconnects = [e for e in events if e.event_id == 8002]
    if len(disconnects) >= 3:
        reason_codes = [e.reason_code for e in disconnects if e.reason_code]
        msg = f"FREQUENT DISCONNECTS: {len(disconnects)} in the time window."
        if reason_codes:
            top = max(set(reason_codes), key=reason_codes.count)
            msg += f" Top reason: {WLAN_REASON_CODES.get(top, f'Code {top}')}."
        issues.append(msg)

    # Roaming
    roam_failures = [e for e in error_events if e.event_id == 12013]
    if roam_failures:
        issues.append(
            f"ROAMING FAILURES: {len(roam_failures)} failed roam(s). "
            f"Check 802.11r/k/v, AP neighbor lists, signal overlap."
        )

    # NIC driver errors
    nic_errors = [e for e in error_events if "System/" in e.source]
    if nic_errors:
        issues.append(
            f"NIC DRIVER ERRORS: {len(nic_errors)} error(s) from wireless adapter driver. "
            f"Firmware crash, adapter reset, or power management issue. "
            f"Update driver or disable power saving for Wi-Fi adapter."
        )

    # Security audit 802.1X
    sec_audit = [e for e in events if e.event_id == 5632]
    if sec_audit:
        issues.append(
            f"802.1X SECURITY AUDIT: {len(sec_audit)} authentication request(s) logged. "
            f"Check All Events tab for identity and result details."
        )

    if not issues:
        issues.append("No significant issues detected in the analyzed time window.")

    return issues


# =============================================================================
# GUI Application
# =============================================================================

class NetworkLogAnalyzerApp:
    """Tkinter GUI for the network log analyzer."""

    def __init__(self, root):
        self.root = root
        self.root.title("Windows Network Log Analyzer — Enterprise Wireless")
        self.root.geometry("1200x850")
        self.root.minsize(1000, 700)

        self.events = []
        self.diagnostics_text_content = ""
        self.profile_text_content = ""
        self.cert_text_content = ""
        self.wlan_report_content = ""
        self._build_ui()

    def _build_ui(self):
        # --- Top control bar ---
        ctrl_frame = ttk.Frame(self.root, padding=5)
        ctrl_frame.pack(fill=tk.X)

        ttk.Label(ctrl_frame, text="Hours back:").pack(side=tk.LEFT)
        self.hours_var = tk.StringVar(value="24")
        hours_spin = ttk.Spinbox(ctrl_frame, from_=1, to=168, width=5,
                                 textvariable=self.hours_var)
        hours_spin.pack(side=tk.LEFT, padx=(2, 10))

        self.scan_btn = ttk.Button(ctrl_frame, text="Scan Logs",
                                   command=self._start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.diag_btn = ttk.Button(ctrl_frame, text="Run Diagnostics",
                                   command=self._start_diagnostics)
        self.diag_btn.pack(side=tk.LEFT, padx=5)

        self.export_btn = ttk.Button(ctrl_frame, text="Export Report",
                                     command=self._export_report)
        self.export_btn.pack(side=tk.LEFT, padx=5)

        self.status_var = tk.StringVar(value="Ready — Scan Logs or Run Diagnostics")
        ttk.Label(ctrl_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=15)

        # --- Notebook with tabs ---
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Tab 1: Connection Timeline
        timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(timeline_frame, text="Connection Timeline")
        self.timeline_tree = ttk.Treeview(
            timeline_frame,
            columns=("start", "duration", "outcome", "phases"),
            show="headings", selectmode="browse",
        )
        self.timeline_tree.heading("start", text="Start Time")
        self.timeline_tree.heading("duration", text="Duration (s)")
        self.timeline_tree.heading("outcome", text="Outcome")
        self.timeline_tree.heading("phases", text="Phases / Reason")
        self.timeline_tree.column("start", width=160)
        self.timeline_tree.column("duration", width=90, anchor=tk.CENTER)
        self.timeline_tree.column("outcome", width=100, anchor=tk.CENTER)
        self.timeline_tree.column("phases", width=700)
        ts1 = ttk.Scrollbar(timeline_frame, orient=tk.VERTICAL,
                            command=self.timeline_tree.yview)
        self.timeline_tree.configure(yscrollcommand=ts1.set)
        self.timeline_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ts1.pack(side=tk.RIGHT, fill=tk.Y)

        # Tab 2: Issues & Recommendations
        issues_frame = ttk.Frame(self.notebook)
        self.notebook.add(issues_frame, text="Issues & Recommendations")
        self.issues_text = scrolledtext.ScrolledText(
            issues_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.issues_text.pack(fill=tk.BOTH, expand=True)

        # Tab 3: All Events
        events_frame = ttk.Frame(self.notebook)
        self.notebook.add(events_frame, text="All Events")
        self.events_tree = ttk.Treeview(
            events_frame,
            columns=("time", "severity", "source", "label", "reason", "message"),
            show="headings", selectmode="browse",
        )
        self.events_tree.heading("time", text="Time")
        self.events_tree.heading("severity", text="Severity")
        self.events_tree.heading("source", text="Source")
        self.events_tree.heading("label", text="Event")
        self.events_tree.heading("reason", text="Reason Code")
        self.events_tree.heading("message", text="Details")
        self.events_tree.column("time", width=145)
        self.events_tree.column("severity", width=65, anchor=tk.CENTER)
        self.events_tree.column("source", width=150)
        self.events_tree.column("label", width=170)
        self.events_tree.column("reason", width=130)
        self.events_tree.column("message", width=400)
        ts2 = ttk.Scrollbar(events_frame, orient=tk.VERTICAL,
                            command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=ts2.set)
        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ts2.pack(side=tk.RIGHT, fill=tk.Y)
        self.events_tree.tag_configure("ERROR", foreground="red")
        self.events_tree.tag_configure("WARNING", foreground="orange")
        self.events_tree.tag_configure("INFO", foreground="black")

        # Tab 4: Diagnostics
        diag_frame = ttk.Frame(self.notebook)
        self.notebook.add(diag_frame, text="Diagnostics")
        self.diag_text = scrolledtext.ScrolledText(
            diag_frame, wrap=tk.WORD, font=("Consolas", 9))
        self.diag_text.pack(fill=tk.BOTH, expand=True)

        # Tab 5: Certificates
        cert_frame = ttk.Frame(self.notebook)
        self.notebook.add(cert_frame, text="Certificates")
        self.cert_text = scrolledtext.ScrolledText(
            cert_frame, wrap=tk.WORD, font=("Consolas", 9))
        self.cert_text.pack(fill=tk.BOTH, expand=True)

        # Tab 6: WLAN Profiles
        profile_frame = ttk.Frame(self.notebook)
        self.notebook.add(profile_frame, text="WLAN Profiles")
        self.profile_text = scrolledtext.ScrolledText(
            profile_frame, wrap=tk.WORD, font=("Consolas", 9))
        self.profile_text.pack(fill=tk.BOTH, expand=True)

        # Tab 7: WLAN Report
        report_frame = ttk.Frame(self.notebook)
        self.notebook.add(report_frame, text="WLAN Report")
        self.report_text = scrolledtext.ScrolledText(
            report_frame, wrap=tk.WORD, font=("Consolas", 9))
        self.report_text.pack(fill=tk.BOTH, expand=True)

    # --- Log Scanning ---

    def _start_scan(self):
        if win32evtlog is None:
            messagebox.showerror(
                "Missing Dependency",
                "pywin32 is required.\n\nInstall with:\n  pip install pywin32"
            )
            return
        self.scan_btn.configure(state=tk.DISABLED)
        self.status_var.set("Scanning event logs...")
        threading.Thread(target=self._scan_logs, daemon=True).start()

    def _scan_logs(self):
        try:
            hours = int(self.hours_var.get())
        except ValueError:
            hours = 24

        all_events = []
        disabled_logs = []
        for log_name, event_map in LOG_SOURCES:
            evts = read_events(log_name, event_map, hours_back=hours)
            if evts is None:
                disabled_logs.append(log_name)
            else:
                all_events.extend(evts)

        all_events.sort(key=lambda e: e.timestamp)
        self.events = all_events

        timelines = analyze_connection_timeline(all_events)
        issues = find_issues(all_events)

        if disabled_logs:
            note = (
                "NOTE — These log channels are disabled/inaccessible.\n"
                "Ask your admin to enable (requires elevation):\n"
            )
            for log in disabled_logs:
                short = log.replace("Microsoft-Windows-", "")
                note += f"  • {short}\n"
            note += (
                "\nEnable commands (admin):\n"
                "  wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true\n"
                "  wevtutil sl Microsoft-Windows-OneX/Operational /e:true\n"
                "  wevtutil sl Microsoft-Windows-CertificateServicesClient-"
                "Lifecycle-System/Operational /e:true\n"
            )
            issues.append(note)

        self.root.after(0, lambda: self._populate_logs_ui(timelines, issues))

    def _populate_logs_ui(self, timelines, issues):
        # Clear
        for item in self.timeline_tree.get_children():
            self.timeline_tree.delete(item)
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        self.issues_text.delete("1.0", tk.END)

        # Timeline
        for start, end, duration, outcome, phases in timelines:
            tag = ("ERROR" if outcome == "FAILED"
                   else "WARNING" if outcome == "INCOMPLETE" else "")
            self.timeline_tree.insert("", tk.END, values=(
                start.strftime("%Y-%m-%d %H:%M:%S"),
                f"{duration:.1f}", outcome, phases
            ), tags=(tag,))
        self.timeline_tree.tag_configure("ERROR", foreground="red")
        self.timeline_tree.tag_configure("WARNING", foreground="orange")

        # Issues
        for i, issue in enumerate(issues, 1):
            self.issues_text.insert(tk.END, f"{i}. {issue}\n\n")

        # All Events
        for ev in self.events:
            reason_str = ""
            if ev.reason_code is not None:
                reason_str = WLAN_REASON_CODES.get(
                    ev.reason_code, f"Code {ev.reason_code}")
            source_short = ev.source.split("/")[0].replace(
                "Microsoft-Windows-", "")
            self.events_tree.insert("", tk.END, values=(
                ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                ev.severity, source_short, ev.label,
                reason_str, ev.message[:200]
            ), tags=(ev.severity,))

        count = len(self.events)
        self.status_var.set(
            f"Done — {count} event(s), {len(timelines)} connection attempt(s)")
        self.scan_btn.configure(state=tk.NORMAL)

    # --- Live Diagnostics ---

    def _start_diagnostics(self):
        self.diag_btn.configure(state=tk.DISABLED)
        self.status_var.set("Running diagnostics (no admin required)...")
        threading.Thread(target=self._run_diagnostics, daemon=True).start()

    def _run_diagnostics(self):
        sections = []
        sections.append(get_wifi_snapshot())
        sections.append(get_ip_config())
        sections.append(test_gateway_ping())
        sections.append(test_dns_resolution())
        sections.append(get_nic_driver_info())
        sections.append(get_nearby_networks())

        full_text = "\n\n".join(sections)
        self.diagnostics_text_content = full_text

        # Certificates
        cert_text = get_certificate_inventory()
        self.cert_text_content = cert_text

        # WLAN Profiles
        profile_text = get_wlan_profiles()
        self.profile_text_content = profile_text

        # WLAN Report
        wlan_report = generate_wlan_report()
        self.wlan_report_content = wlan_report

        self.root.after(0, lambda: self._populate_diagnostics_ui(
            full_text, cert_text, profile_text, wlan_report))

    def _populate_diagnostics_ui(self, diag_text, cert_text,
                                  profile_text, wlan_report):
        self.diag_text.delete("1.0", tk.END)
        self.diag_text.insert("1.0", diag_text)

        self.cert_text.delete("1.0", tk.END)
        self.cert_text.insert("1.0", cert_text)

        self.profile_text.delete("1.0", tk.END)
        self.profile_text.insert("1.0", profile_text)

        self.report_text.delete("1.0", tk.END)
        self.report_text.insert("1.0", wlan_report)

        self.status_var.set("Diagnostics complete")
        self.diag_btn.configure(state=tk.NORMAL)
        self.notebook.select(3)  # Switch to Diagnostics tab

    # --- Export Report ---

    def _export_report(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"network_diag_{timestamp}.txt"

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=default_name,
            title="Export Diagnostic Report"
        )
        if not filepath:
            return

        report = self._build_report()
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report)
            self.status_var.set(f"Report exported: {os.path.basename(filepath)}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not write file:\n{e}")

    def _build_report(self):
        lines = []
        lines.append("=" * 70)
        lines.append("WINDOWS NETWORK DIAGNOSTIC REPORT — ENTERPRISE WIRELESS")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Computer:  {os.environ.get('COMPUTERNAME', 'Unknown')}")
        lines.append(f"User:      {os.environ.get('USERNAME', 'Unknown')}")
        lines.append(f"Domain:    {os.environ.get('USERDOMAIN', 'Unknown')}")
        lines.append("=" * 70)
        lines.append("")

        # Issues
        issues_content = self.issues_text.get("1.0", tk.END).strip()
        if issues_content:
            lines.append("─" * 70)
            lines.append("ISSUES & RECOMMENDATIONS")
            lines.append("─" * 70)
            lines.append(issues_content)
            lines.append("")

        # Timeline
        timeline_items = self.timeline_tree.get_children()
        if timeline_items:
            lines.append("─" * 70)
            lines.append("CONNECTION TIMELINE")
            lines.append("─" * 70)
            lines.append(f"{'Start Time':<22}{'Duration':<12}{'Outcome':<12}Phases")
            lines.append("-" * 70)
            for item in timeline_items:
                vals = self.timeline_tree.item(item, "values")
                lines.append(f"{vals[0]:<22}{vals[1]:<12}{vals[2]:<12}{vals[3]}")
            lines.append("")

        # Certificates
        if self.cert_text_content:
            lines.append("─" * 70)
            lines.append("CERTIFICATE INVENTORY")
            lines.append("─" * 70)
            lines.append(self.cert_text_content)
            lines.append("")

        # Diagnostics
        if self.diagnostics_text_content:
            lines.append("─" * 70)
            lines.append("LIVE DIAGNOSTICS")
            lines.append("─" * 70)
            lines.append(self.diagnostics_text_content)
            lines.append("")

        # WLAN Profiles
        if self.profile_text_content:
            lines.append("─" * 70)
            lines.append("WLAN PROFILES")
            lines.append("─" * 70)
            lines.append(self.profile_text_content)
            lines.append("")

        # WLAN Report
        if self.wlan_report_content:
            lines.append("─" * 70)
            lines.append("WLAN REPORT SUMMARY")
            lines.append("─" * 70)
            lines.append(self.wlan_report_content)
            lines.append("")

        # All Events
        event_items = self.events_tree.get_children()
        if event_items:
            lines.append("─" * 70)
            lines.append("ALL EVENTS (chronological)")
            lines.append("─" * 70)
            lines.append(
                f"{'Time':<22}{'Sev':<9}{'Source':<18}{'Event':<22}"
                f"{'Reason':<20}Details")
            lines.append("-" * 70)
            for item in event_items:
                vals = self.events_tree.item(item, "values")
                lines.append(
                    f"{vals[0]:<22}{vals[1]:<9}{vals[2]:<18}{vals[3]:<22}"
                    f"{vals[4]:<20}{vals[5]}")

        return "\n".join(lines)


# =============================================================================
# Self-check
# =============================================================================

def _self_check():
    """Assert-based check that core logic works on synthetic events."""
    now = datetime.now()

    # Test successful enterprise connection timeline
    fake_events = [
        LogEvent(now - timedelta(seconds=15), 8000, "WLAN", "Connecting", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=14), 11000, "WLAN", "Association Started", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=13), 11001, "WLAN", "Association Succeeded", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=12), 2001, "EapHost", "EAP Auth Started", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=11), 2004, "EapHost", "EAP Method Selected", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=10), 2100, "EapHost", "EAP-TLS Started", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=8), 11, "CAPI2", "Cert Chain Built", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=7), 2101, "EapHost", "EAP-TLS Succeeded", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=6), 2002, "EapHost", "EAP Auth Succeeded", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=5), 11004, "WLAN", "4-Way Handshake Started", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=4), 11005, "WLAN", "4-Way Handshake Succeeded", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=3), 8001, "WLAN", "Connected", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=2), 1000, "DHCP", "DHCP Lease Obtained", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=1), 10000, "NetworkProfile/Operational", "Network Connected", "", "", "INFO"),
    ]
    timelines = analyze_connection_timeline(fake_events)
    assert len(timelines) == 1, f"Expected 1 timeline, got {len(timelines)}"
    assert timelines[0][3] == "SUCCESS"
    assert 11.5 <= timelines[0][2] <= 12.5, f"Expected ~12s, got {timelines[0][2]}"

    # Test failure with reason code
    fail_events = [
        LogEvent(now - timedelta(seconds=5), 8000, "WLAN", "Connecting", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=3), 8003, "WLAN", "Connection Failed", "",
                 "Reason Code: 23", "ERROR", 23),
    ]
    timelines2 = analyze_connection_timeline(fail_events)
    assert len(timelines2) == 1
    assert timelines2[0][3] == "FAILED"
    assert "802.1X authentication failed" in timelines2[0][4]

    # Test issue detection
    issues = find_issues(fail_events)
    assert any("CONNECTION FAILURES" in i for i in issues)

    # Test cert/EAP failures
    cert_events = [
        LogEvent(now - timedelta(seconds=5), 2001, "EapHost", "EAP Auth Started", "", "", "INFO"),
        LogEvent(now - timedelta(seconds=3), 2102, "EapHost", "EAP-TLS Failed", "", "", "ERROR"),
        LogEvent(now - timedelta(seconds=2), 30, "CAPI2", "Cert Verify Failed", "", "", "ERROR"),
        LogEvent(now - timedelta(seconds=1), 53, "CAPI2", "Cert Expired", "", "", "ERROR"),
    ]
    cert_issues = find_issues(cert_events)
    assert any("EAP" in i for i in cert_issues)
    assert any("VERIFICATION" in i for i in cert_issues)
    assert any("EXPIRED" in i for i in cert_issues)

    # Test NIC driver error detection
    nic_events = [
        LogEvent(now - timedelta(seconds=2), 5002, "System/Netwtw06",
                 "NIC Firmware Error", "", "", "ERROR"),
    ]
    nic_issues = find_issues(nic_events)
    assert any("NIC DRIVER" in i for i in nic_issues)

    # Test reason code extraction
    assert _extract_reason_code("Reason Code: 23") == 23
    assert _extract_reason_code("some | 15 | data") == 15

    # Event IDs must be interpreted within their source channel
    assert _event_severity("Microsoft-Windows-Dhcp-Client/Admin", 1002) == "INFO"
    assert _event_severity(
        "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
        1002,
    ) == "ERROR"
    assert _event_severity("Microsoft-Windows-Dhcp-Client/Admin", 1003) == "ERROR"
    assert _event_severity(
        "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
        1003,
    ) == "WARNING"

    # Test that command failures expose stderr and the exit code
    failed_command = _run_cmd([
        sys.executable, "-c",
        "import sys; sys.stderr.write('expected failure'); sys.exit(3)",
    ])
    assert failed_command.startswith("[Command failed with exit code 3:")
    assert "expected failure" in failed_command

    # Test NetworkProfile fallback
    np_events = [
        LogEvent(now - timedelta(seconds=30), 10001,
                 "Microsoft-Windows-NetworkProfile/Operational",
                 "Network Disconnected", "", "", "WARNING"),
        LogEvent(now - timedelta(seconds=20), 10000,
                 "Microsoft-Windows-NetworkProfile/Operational",
                 "Network Connected", "", "", "INFO"),
    ]
    np_timelines = analyze_connection_timeline(np_events)
    assert len(np_timelines) == 1
    assert np_timelines[0][3] == "SUCCESS"
    assert 9.5 <= np_timelines[0][2] <= 10.5

    print("Self-check passed.")


if __name__ == "__main__":
    import sys
    if "--self-check" in sys.argv:
        _self_check()
    else:
        root = tk.Tk()
        app = NetworkLogAnalyzerApp(root)
        root.mainloop()
