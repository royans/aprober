import datetime
import nmap
import ipaddress # Added for CIDR validation
import os
import requests
import socket
import errno # Needed for GetSshServerVersion error check
from urllib.parse import urlparse # To help validate input
from zoneinfo import ZoneInfo
from google.adk.agents import Agent
from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm
import nvdlib
import cpe


def NmapHostDiscoveryScan(network_cidr: str) -> dict:
    """Performs an Nmap Ping Scan (-sn) to discover active hosts
       within a specified network range (CIDR notation). Does *not*
       perform port scanning. Requires nmap to be installed, but
       generally *does not* require root privileges.

    Args:
        network_cidr (str): The network range to scan in CIDR notation
                            (e.g., "192.168.1.0/24", "10.0.0.0/8",
                            "2001:db8::/64").

    Returns:
        dict: A dictionary containing:
              - 'status': 'success' or 'error'.
              - 'active_hosts': A list of IP addresses (str) found to be active/up.
                                Returns an empty list if no hosts responded.
              - 'error_message': A description of the error (if failed).
              - 'scan_stats': A dictionary with Nmap scan statistics (e.g.,
                              elapsed time, hosts up/down).
    """
    nm = None

    # --- Validate Input CIDR ---
    try:
        # Use ipaddress module to check if it's a valid network address
        ipaddress.ip_network(network_cidr, strict=False) # strict=False allows host bits set
    except ValueError:
        return {
            "status": "error",
            "error_message": f"Invalid CIDR notation provided: '{network_cidr}'",
            "active_hosts": [],
            "scan_stats": {}
        }
    except Exception as e: # Catch other potential validation errors
        return {
            "status": "error",
            "error_message": f"Error validating CIDR '{network_cidr}': {e}",
            "active_hosts": [],
            "scan_stats": {}
        }

    # --- Initialize Nmap Scanner ---
    try:
         nm = nmap.PortScanner()
    except nmap.PortScannerError as e:
        if "nmap program was not found" in str(e):
             error_msg = "Nmap executable not found. Please install Nmap and ensure it's in your system's PATH."
        else:
             error_msg = f"Nmap initialization error: {e}"
        return {
            "status": "error",
            "error_message": error_msg,
            "active_hosts": [],
            "scan_stats": {}
        }
    except Exception as e: # Catch other init errors
        return {
            "status": "error",
            "error_message": f"Unexpected error initializing Nmap: {e}",
            "active_hosts": [],
            "scan_stats": {}
        }

    # --- Perform Host Discovery Scan ---
    try:
        print(f"Starting Nmap Host Discovery scan (-sn) on {network_cidr}. This may take some time depending on network size...")
        # -sn: Ping Scan (Host Discovery) - disables port scan
        # It sends ICMP echo, TCP SYN to 443, TCP ACK to 80, ICMP timestamp by default
        scan_args = '-sn'
        # Note: For potentially better results on firewalled networks, consider adding
        # probe types like -PS (TCP SYN), -PA (TCP ACK), -PU (UDP), -PE (ICMP Echo)
        # e.g., scan_args = '-sn -PS80,443 -PA80 -PU53 -PE'
        # However, some of these might require root privileges. -sn is usually sufficient.
        scan_results = nm.scan(hosts=network_cidr, arguments=scan_args, sudo=False) # Explicitly avoid sudo for -sn
        print(f"Host discovery scan complete for {network_cidr}.")

        # --- Process Results ---
        active_hosts = nm.all_hosts() # Returns a list of IPs that are 'up'
        scan_stats = scan_results.get('nmap', {}).get('scanstats', {})

        print(f"Scan Summary: {scan_stats.get('uphosts', '0')} hosts up, "
              f"{scan_stats.get('downhosts', '0')} hosts down in "
              f"{scan_stats.get('elapsed', '?')} seconds.")

        return {
            "status": "success",
            "active_hosts": active_hosts, # List of IPs found up
            "scan_stats": scan_stats     # Dictionary of scan statistics
        }

    except nmap.PortScannerError as e:
        # Catch errors during the scan execution phase
        error_msg = f"Nmap PortScannerError during scan: {e}. "
        if "nmap program was not found" in str(e):
             error_msg += "Please install Nmap and ensure it's in your system's PATH."
        # Although -sn usually doesn't need root, catch permission errors just in case
        elif "requires root privileges" in str(e).lower() or "permission denied" in str(e).lower():
             error_msg += "Nmap reported a permission error even for host discovery (-sn). This might indicate unusual system configuration or specific probe issues."
        else:
             error_msg += "Check Nmap installation, permissions, network connectivity, and the target specification."
        return {
            "status": "error",
            "error_message": error_msg,
            "active_hosts": [],
            "scan_stats": {}
        }
    except Exception as e:
        # Catch any other unexpected errors
        return {
            "status": "error",
            "error_message": f"An unexpected error occurred scanning {network_cidr} ({type(e).__name__}): {e}",
            "active_hosts": [],
            "scan_stats": {}
        }


def TranslateCpeFormat(cpe_string: str, target_format: str) -> dict:
    """
    Translates a CPE string from its detected format to a specified target format
    using the 'cpe' library.

    Args:
        cpe_string (str): The CPE string to translate (e.g., WFN, URI, FS, 2.3 format).
        target_format (str): The desired output format. Supported values:
                             '2.3' (for CPE 2.3 Formatted String)
                             'fs' (for FileSystem representation)
                             'uri' (for URI representation)
                             'wfn' (for Well-Formed Name representation - returns 2.3 string)

    Returns:
        dict: A dictionary containing:
            - 'status': 'success' or 'error'.
            - 'original_cpe': The input CPE string.
            - 'target_format': The requested target format.
            - 'translated_cpe': The CPE string in the target format (str), or None on error.
            - 'error_message': Description of the error (if status is 'error').
    """
    print(f"Attempting to translate CPE '{cpe_string}' to format '{target_format}'...")
    try:
        # Parse the input CPE string using cpe.CPE
        cpe_obj = cpe.CPE(cpe_string)
        print(f"Successfully parsed input CPE. Detected version: {cpe_obj.get_version()}")

        translated_cpe = None
        # Convert to the target format
        # Use the appropriate methods available on the parsed CPE object
        if target_format == '2.3':
            # The as_cpe23_string() method should exist on the base CPE object
            translated_cpe = cpe_obj.as_cpe23_string()
        elif target_format == 'fs':
            translated_cpe = cpe_obj.as_fs_string()
        elif target_format == 'uri':
            translated_cpe = cpe_obj.as_uri_string()
        elif target_format == 'wfn':
            # WFN is the internal representation; as_cpe23_string is a reliable string output
            print("Note: 'wfn' represents the internal parsed structure. Returning CPE 2.3 string instead.")
            translated_cpe = cpe_obj.as_cpe23_string()
        else:
            # Handle unsupported target format
            error_msg = f"Unsupported target format: '{target_format}'. Supported formats: '2.3', 'fs', 'uri'."
            print(error_msg)
            return {
                "status": "error",
                "original_cpe": cpe_string,
                "target_format": target_format,
                "translated_cpe": None,
                "error_message": error_msg,
            }

        print(f"Successfully translated to format '{target_format}'.")
        return {
            "status": "success",
            "original_cpe": cpe_string,
            "target_format": target_format,
            "translated_cpe": translated_cpe,
        }

    except NotImplementedError as e:                # <- NEW CODE
        # Handle errors during parsing (e.g., invalid CPE string)
        # The error message indicates a version/format issue
        error_msg = f"CPE parsing error: {e}" # Consider adjusting the message if needed
        print(error_msg)
        return {
            "status": "error",
            "original_cpe": cpe_string,
            "target_format": target_format,
            "translated_cpe": None,
            "error_message": error_msg,
        }
    except AttributeError as e:
        # Catch potential AttributeError if a method is missing (like the original error)
        error_msg = f"CPE translation method error: {e}. The parsed CPE object might not support the requested conversion directly."
        print(error_msg)
        return {
            "status": "error",
            "original_cpe": cpe_string,
            "target_format": target_format,
            "translated_cpe": None,
            "error_message": error_msg,
        }
    except Exception as e:
        # Catch any other unexpected errors
        error_msg = f"An unexpected error occurred during CPE translation ({type(e).__name__}): {e}"
        print(error_msg)
        return {
            "status": "error",
            "original_cpe": cpe_string,
            "target_format": target_format,
            "translated_cpe": None,
            "error_message": error_msg,
        }



def GetCpeInfo(cpe_string: str) -> dict:
    """
    Retrieves information about a specific CPE (Common Platform Enumeration)
    string and its associated CVEs from the National Vulnerability Database (NVD)
    using the nvdlib library.

    Args:
        cpe_string (str): The CPE string to query (e.g., "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*").
                          Must be in the CPE 2.3 format.

    Returns:
        dict: A dictionary containing:
            - 'status': 'success' or 'error'.
            - 'cpe_checked': The input CPE string.
            - 'cpe_details': A dictionary with details of the first matching CPE found
                             (or None if no match):
                - 'name': The CPE string name.
                - 'title': The human-readable title.
                - 'created': Creation date (ISO format string).
                - 'lastModified': Last modification date (ISO format string).
                - 'deprecated': Boolean indicating if the CPE is deprecated.
            - 'associated_cves': A list of dictionaries, each representing a CVE linked
                                 to the CPE (limited results, e.g., first 10). Each dict contains:
                - 'id': The CVE ID (e.g., "CVE-2021-12345").
                - 'description': A summary of the vulnerability.
                - 'cvss_v3_severity': The CVSS v3 base severity (e.g., "HIGH", "MEDIUM") or None.
                - 'cvss_v3_score': The CVSS v3 base score (float) or None.
                - 'cvss_v2_severity': The CVSS v2 base severity (e.g., "HIGH") or None (fallback).
                - 'cvss_v2_score': The CVSS v2 base score (float) or None (fallback).
                - 'published_date': CVE publication date (ISO format string).
                - 'last_modified_date': CVE last modification date (ISO format string).
                - 'url': Link to the NVD page for the CVE.
            - 'error_message': Description of the error (if status is 'error').
            - 'cve_search_limit_hit': Boolean indicating if the CVE search limit was reached.
    """
    # Basic validation of CPE format
    if not isinstance(cpe_string, str) or not cpe_string.startswith("cpe:2.3:"):
        return {
            "status": "error",
            "cpe_checked": cpe_string,
            "error_message": "Invalid CPE string format. Must start with 'cpe:2.3:'.",
            "cpe_details": None,
            "associated_cves": [],
        }

    print(f"Querying NVD for CPE: {cpe_string}")
    cpe_details_result = None
    cve_list_result = []
    cve_limit = 20 # How many associated CVEs to fetch at most
    cve_search_limit_hit = False

    try:
        # --- Search for CPE Details ---
        # Use cpeMatchString for exact or pattern matching based on the input string
        # Limit to 1 as we typically want info for the specific string provided
        print(f"Searching for CPE details using cpeMatchString...")
        cpe_results = nvdlib.searchCPE(cpeMatchString=cpe_string, limit=1, key=None, delay=None) # Use delay=None for default handling

        if cpe_results:
            cpe_obj = cpe_results[0] # Get the first (and likely only) result
            cpe_details_result = {
                "name": getattr(cpe_obj, 'cpeName', 'N/A'),
                "title": getattr(cpe_obj.title[0], 'title', 'N/A') if hasattr(cpe_obj, 'title') and cpe_obj.title else 'N/A',
                "created": getattr(cpe_obj, 'created', 'N/A'),
                "lastModified": getattr(cpe_obj, 'lastModified', 'N/A'),
                "deprecated": getattr(cpe_obj, 'deprecated', False)
            }
            print(f"Found CPE details for: {cpe_details_result['name']}")
        else:
            print("No specific details found for this exact CPE string via searchCPE.")
            # Still proceed to search for CVEs using this CPE name

        # --- Search for Associated CVEs ---
        # Use cpeName for finding CVEs linked to this CPE
        print(f"Searching for CVEs associated with CPE: {cpe_string} (limit {cve_limit})...")
        cve_results = nvdlib.searchCVE(cpeName=cpe_string, limit=cve_limit, key=None, delay=None)

        if len(cve_results) == cve_limit:
            cve_search_limit_hit = True
            print(f"Reached CVE search limit ({cve_limit}). More CVEs might exist.")

        print(f"Found {len(cve_results)} associated CVE(s).")
        for cve in cve_results:
            # Extract CVSS scores and severities carefully
            cvss_v3_severity = None
            cvss_v3_score = None
            cvss_v2_severity = None
            cvss_v2_score = None

            # Prefer CVSS v3
            if hasattr(cve, 'v3severity') and cve.v3severity:
                 cvss_v3_severity = cve.v3severity
                 cvss_v3_score = getattr(cve, 'v3score', None)
            # Fallback to CVSS v2
            elif hasattr(cve, 'v2severity') and cve.v2severity:
                 cvss_v2_severity = cve.v2severity
                 cvss_v2_score = getattr(cve, 'v2score', None)

            cve_info = {
                'id': getattr(cve, 'id', 'N/A'),
                'description': getattr(cve.descriptions[0], 'value', 'No description available.') if hasattr(cve, 'descriptions') and cve.descriptions else 'No description available.',
                'cvss_v3_severity': cvss_v3_severity,
                'cvss_v3_score': cvss_v3_score,
                'cvss_v2_severity': cvss_v2_severity,
                'cvss_v2_score': cvss_v2_score,
                'published_date': getattr(cve, 'published', 'N/A'),
                'last_modified_date': getattr(cve, 'lastModified', 'N/A'),
                'url': getattr(cve, 'url', '#') # Link to NVD entry
            }
            cve_list_result.append(cve_info)

        return {
            "status": "success",
            "cpe_checked": cpe_string,
            "cpe_details": cpe_details_result,
            "associated_cves": cve_list_result,
            "cve_search_limit_hit": cve_search_limit_hit
        }

    except requests.exceptions.RequestException as e:
        error_msg = f"Network error connecting to NVD: {e}"
        print(error_msg)
        return {
            "status": "error",
            "cpe_checked": cpe_string,
            "error_message": error_msg,
            "cpe_details": None,
            "associated_cves": [],
        }
    except Exception as e:
        # Catch potential errors from nvdlib or other issues
        error_msg = f"An unexpected error occurred during NVD query ({type(e).__name__}): {e}"
        print(error_msg)
        return {
            "status": "error",
            "cpe_checked": cpe_string,
            "error_message": error_msg,
            "cpe_details": None,
            "associated_cves": [],
        }


def NmapTCPVersionScan(target: str) -> dict:
    """Performs an Nmap TCP Connect scan (-sT) combined with version
       detection (-sV) on a target host or IP address. Finds open TCP ports
       and attempts to determine the service and version running on them.
       Requires nmap to be installed but generally *does not* require
       root privileges. Handles hostname inputs correctly by using the
       resolved IP from results.

    Args:
        target (str): The hostname or IP address to scan.

    Returns:
        dict: A dictionary containing:
              - 'status': 'success' or 'error'.
              - 'port_info': A dictionary where keys are open TCP port numbers (int)
                             and values are dictionaries containing service details
                             (e.g., {'service': 'ssh', 'product': 'OpenSSH', 'version': '8.2p1'}).
                             Returns an empty dict if no open ports with version info found.
              - 'error_message': A description of the error (if failed).
              - 'scanned_ip': The actual IP address scanned (if successful).
    """
    nm = None
    original_target = str(target) # Keep original target for messages

    try:
        # --- Validate Target ---
        # Attempt to resolve hostname/IP to catch basic errors early
        try:
            # Use socket.getaddrinfo for potentially more robust resolution (IPv4/IPv6)
            # We only need to know if it *can* be resolved, not the specific IP yet.
            socket.getaddrinfo(original_target, None)
        except socket.gaierror:
            return {
                "status": "error",
                "error_message": f"Could not resolve hostname/IP: {original_target}",
            }
        except Exception as e: # Catch other potential socket errors
             return {
                "status": "error",
                "error_message": f"Error validating target {original_target}: {e}",
            }

        # --- Initialize Nmap Scanner ---
        try:
             nm = nmap.PortScanner()
        except nmap.PortScannerError as e:
             # Handle Nmap not found error during initialization
            if "nmap program was not found" in str(e):
                 error_msg = "Nmap executable not found. Please install Nmap and ensure it's in your system's PATH."
            else:
                 error_msg = f"Nmap initialization error: {e}"
            return {
                "status": "error",
                "error_message": error_msg,
            }


        # --- Perform Scan ---
        # -sT: TCP Connect scan
        # -sV: Version detection
        # You can add --version-intensity <0-9> for more or less thorough version probing
        # e.g., arguments='-sT -sV --version-intensity 5'
        # Default intensity is usually sufficient.
        print(f"Starting Nmap TCP Version scan (-sT -sV) on {original_target}. This might take longer...")
        scan_args = '-sT -sV'
        scan_results = nm.scan(hosts=original_target, arguments=scan_args)
        print("Scan complete.")

        # --- Process Results ---
        port_info = {} # Dictionary to store {port: {details}}

        # Check if Nmap found any hosts at all.
        if not nm.all_hosts():
            error_output = "Scan completed but no hosts were found or up."
            # Try to get more specific info from scanstats if available
            if scan_results and 'nmap' in scan_results and 'scanstats' in scan_results['nmap']:
                 stats = scan_results['nmap']['scanstats']
                 down_hosts = stats.get('downhosts', '0')
                 uphosts = stats.get('uphosts', '0')
                 totalhosts = stats.get('totalhosts', 'unknown')
                 error_output = f"{down_hosts}/{totalhosts} hosts down. "
                 if uphosts == '0':
                     error_output += "Target may be unresponsive or scan blocked. "
                 if 'warning' in stats:
                     error_output += f"Nmap warning: {stats['warning']}"

            if "Couldn't resolve" in error_output:
                 error_output = f"Nmap couldn't resolve host: {original_target}"

            return {
                "status": "error",
                "error_message": f"Scan failed for target '{original_target}'. Reason: {error_output}",
            }

        # --- Get Resolved IP ---
        scanned_ip = nm.all_hosts()[0]
        print(f"Target '{original_target}' resolved to IP '{scanned_ip}' for scanning.")
        host_info = nm[scanned_ip]

        # Check host status
        if host_info.state() != 'up':
             return {
                "status": "error",
                "error_message": f"Host {scanned_ip} (target: {original_target}) reported as {host_info.state()}",
             }

        # Check if TCP protocol was scanned and has results
        if 'tcp' not in host_info or not host_info['tcp']:
             # Check if the scan was even attempted for TCP
             scaninfo = nm.scaninfo()
             if 'tcp' not in scaninfo.get('services', ''):
                 return {
                     "status": "error",
                     "error_message": f"TCP scan was not performed or yielded no results for {scanned_ip} (target: {original_target}). Check scan arguments.",
                 }
             else:
                 # TCP was scanned, but no ports found (open, closed, or filtered)
                 # This case should ideally result in success but with empty port_info
                 print(f"No TCP ports found (open, closed, or filtered) for {scanned_ip}.")
                 # Proceed to return success with empty port_info below
                 pass # Fall through to return success


        # Extract open TCP ports and their version info
        if 'tcp' in host_info:
            tcp_ports = host_info['tcp']
            for port, details in tcp_ports.items():
                if details.get('state') == 'open':
                    port_number = int(port)
                    port_info[port_number] = {
                        'service': details.get('name', ''), # Service name (e.g., http, ssh)
                        'product': details.get('product', ''), # Specific product (e.g., Apache httpd, OpenSSH)
                        'version': details.get('version', ''), # Version number (e.g., 2.4.41, 8.2p1)
                        'extrainfo': details.get('extrainfo', ''), # Extra info (e.g., protocol, OS type)
                        'cpe': details.get('cpe', '') # Common Platform Enumeration string
                    }

        return {
            "status": "success",
            "port_info": port_info, # Return dict of {port: details}
            "scanned_ip": scanned_ip # Include the scanned IP
        }

    except nmap.PortScannerError as e:
        # Catch errors during the scan execution phase
        if "nmap program was not found" in str(e):
             error_msg = "Nmap executable not found. Please install Nmap and ensure it's in your system's PATH."
        # Check if Nmap failed because -sV requires privileges (less common with -sT, but possible)
        elif "requires root privileges" in str(e).lower() or "permission denied" in str(e).lower():
             error_msg = f"Nmap reported permission error during scan (-sT -sV). While -sT usually works, -sV might require privileges on some systems or for certain probes. Error: {e}"
        else:
             error_msg = f"Nmap PortScannerError during scan: {e}. Check Nmap installation and permissions."
        return {
            "status": "error",
            "error_message": error_msg,
        }
    except KeyError as e:
        # Handle cases where expected keys are missing in the result dictionary
        return {
            "status": "error",
            "error_message": f"Error parsing Nmap results for {original_target}. Missing key: {e}. Host might be down or scan blocked.",
        }
    except Exception as e:
        # Catch any other unexpected errors
        return {
            "status": "error",
            "error_message": f"An unexpected error occurred scanning {original_target} ({type(e).__name__}): {e}",
        }


def GetSshServerVersion(target: str, port: int = 22) -> dict:
    """
    Attempts to retrieve the SSH server identification banner by connecting
    to the specified target and port (default 22).

    Args:
        target (str): The hostname or IP address of the SSH server.
        port (int): The port number the SSH server is listening on (default is 22).

    Returns:
        dict: A dictionary containing:
              - 'status': 'success' or 'error'.
              - 'ssh_banner': The raw SSH banner string (str or None if not retrieved).
              - 'error_message': A description of the error (if failed).
              - 'target_checked': The actual hostname/IP checked.
              - 'port_checked': The port number checked.
    """
    hostname = str(target) # Use the input directly as hostname/IP for SSH
    port_to_check = int(port)
    timeout_seconds = 5 # Connection and read timeout

    # --- Validate Target Resolution ---
    try:
        resolved_ip = socket.gethostbyname(hostname)
        print(f"Validated target: '{hostname}' resolves to '{resolved_ip}'")
    except socket.gaierror:
        return {
            "status": "error",
            "error_message": f"Could not resolve hostname/IP: {hostname}",
            "target_checked": hostname,
            "port_checked": port_to_check,
        }
    except Exception as e: # Catch other potential socket errors during resolution
         return {
            "status": "error",
            "error_message": f"Error during initial validation of {hostname}: {e}",
            "target_checked": hostname,
            "port_checked": port_to_check,
        }

    # --- Attempt Socket Connection and Banner Read ---
    sock = None # Initialize socket variable
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for blocking operations (connect, recv)
        sock.settimeout(timeout_seconds)

        # Connect to the server
        print(f"Attempting to connect to {hostname}:{port_to_check}...")
        sock.connect((hostname, port_to_check))
        print("Connection successful.")

        # Receive the banner (typically sent immediately)
        # SSH banner is usually less than 1024 bytes
        # Format: SSH-ProtoVersion-SoftwareVersion Comments
        print("Attempting to receive SSH banner...")
        banner_bytes = sock.recv(1024)

        # Decode the banner bytes to a string
        # Use 'ignore' or 'replace' for errors if non-UTF8 chars are possible
        ssh_banner = banner_bytes.decode('utf-8', errors='replace').strip()
        print(f"Received banner: {ssh_banner}")

        # Check if the received data looks like an SSH banner
        if ssh_banner.startswith("SSH-"):
             return {
                "status": "success",
                "ssh_banner": ssh_banner,
                "target_checked": hostname,
                "port_checked": port_to_check,
            }
        else:
            # Received data, but doesn't look like an SSH banner
            return {
                "status": "error",
                "error_message": f"Connected, but did not receive a valid SSH banner. Received: '{ssh_banner[:100]}...'", # Show snippet
                "target_checked": hostname,
                "port_checked": port_to_check,
            }

    except socket.timeout:
        error_msg = f"Connection or read timed out ({timeout_seconds}s) connecting to {hostname}:{port_to_check}."
        print(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "target_checked": hostname,
            "port_checked": port_to_check,
        }
    except socket.error as e:
        # Handle specific connection errors like 'Connection refused'
        error_msg = f"Socket error connecting to {hostname}:{port_to_check}: {e}"
        if e.errno == errno.ECONNREFUSED:
            error_msg = f"Connection refused by {hostname}:{port_to_check}. SSH server may not be running or firewall blocking."
        print(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "target_checked": hostname,
            "port_checked": port_to_check,
        }
    except Exception as e:
        # Catch any other unexpected errors
        error_msg = f"An unexpected error occurred ({type(e).__name__}): {e}"
        print(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "target_checked": hostname,
            "port_checked": port_to_check,
        }
    finally:
        # Ensure the socket is always closed
        if sock:
            print("Closing socket.")
            sock.close()

def GetWebServerHeader(target: str) -> dict:
    """
    Attempts to retrieve the 'Server' HTTP header from a target host or IP
    address by making HEAD requests (HTTPS first, then HTTP).

    Args:
        target (str): The hostname, IP address, or a full URL (http/https).

    Returns:
        dict: A dictionary containing:
              - 'status': 'success' or 'error'.
              - 'server_header': The value of the Server header (str or None if not found).
              - 'protocol': 'https' or 'http' indicating which protocol succeeded.
              - 'error_message': A description of the error (if failed).
              - 'target_checked': The actual hostname/IP checked after parsing input.
    """
    original_target = str(target)
    protocols_to_try = ['https', 'http']
    headers = {
        # Use a common User-Agent to avoid being blocked by some servers
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    timeout_seconds = 5 # Set a reasonable timeout

    # --- Basic Input Parsing and Validation ---
    parsed_url = urlparse(original_target)
    # If scheme (http/https) is provided, use it directly
    if parsed_url.scheme in protocols_to_try:
        hostname = parsed_url.netloc.split(':')[0] # Remove port if present
        protocols_to_try = [parsed_url.scheme] # Only try the specified protocol
    # If no scheme, assume it's a hostname or IP
    elif not parsed_url.scheme and parsed_url.path:
         hostname = parsed_url.path.split(':')[0] # Treat path as hostname if no scheme
    # Handle cases like just "example.com"
    elif not parsed_url.scheme and parsed_url.netloc:
         hostname = parsed_url.netloc.split(':')[0]
    else: # Fallback if parsing is unclear, treat input as hostname
        hostname = original_target.split(':')[0]

    # Validate the extracted hostname/IP
    try:
        socket.gethostbyname(hostname)
        print(f"Validated target: '{hostname}' (from input '{original_target}')")
    except socket.gaierror:
        return {
            "status": "error",
            "error_message": f"Could not resolve hostname/IP: {hostname} (from input '{original_target}')",
            "target_checked": hostname,
        }
    except Exception as e: # Catch other potential socket errors
         return {
            "status": "error",
            "error_message": f"Error validating target {hostname}: {e}",
            "target_checked": hostname,
        }

    # --- Attempt HTTP/HTTPS Requests ---
    last_error = None
    for protocol in protocols_to_try:
        url = f"{protocol}://{hostname}"
        print(f"Attempting {protocol.upper()} request to {url}...")
        try:
            # Use HEAD request to fetch only headers (more efficient)
            # allow_redirects=True to follow redirects which might reveal the final server
            response = requests.head(
                url,
                headers=headers,
                timeout=timeout_seconds,
                allow_redirects=True,
                verify=True # Enable SSL verification by default
            )

            # Check if request was successful (status code 2xx)
            response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)

            # --- Extract Server Header ---
            server_header = response.headers.get('Server') # Case-insensitive get

            print(f"Successfully connected via {protocol.upper()}. Status: {response.status_code}")
            return {
                "status": "success",
                "server_header": server_header, # Will be None if header not present
                "protocol": protocol,
                "target_checked": hostname,
            }

        except requests.exceptions.SSLError as e:
            print(f"SSL Error for {url}: {e}")
            last_error = f"SSL Error connecting via {protocol.upper()}: {e}"
            # If HTTPS fails with SSL error, we automatically try HTTP next (if applicable)
            continue
        except requests.exceptions.ConnectionError as e:
            print(f"Connection Error for {url}: {e}")
            last_error = f"Could not connect via {protocol.upper()} ({e})"
            # Continue to try the next protocol if available
            continue
        except requests.exceptions.Timeout as e:
            print(f"Timeout for {url}: {e}")
            last_error = f"Request timed out for {protocol.upper()}"
            # Continue to try the next protocol if available
            continue
        except requests.exceptions.HTTPError as e:
             print(f"HTTP Error for {url}: {e}")
             # Even with an HTTP error, we might get a server header
             server_header = e.response.headers.get('Server')
             last_error = f"{protocol.upper()} request failed with status {e.response.status_code}"
             # Return success *if* we got a server header despite the error status
             if server_header:
                 print(f"Connected via {protocol.upper()} but received status {e.response.status_code}. Found Server header.")
                 return {
                    "status": "success", # Treat as success because we got the header
                    "server_header": server_header,
                    "protocol": protocol,
                    "target_checked": hostname,
                    "warning": last_error # Add a warning about the HTTP status
                 }
             # Otherwise, continue to try next protocol or fail
             continue
        except requests.exceptions.RequestException as e:
            print(f"General Request Error for {url}: {e}")
            last_error = f"An error occurred during {protocol.upper()} request: {e}"
            # Continue to try the next protocol if available
            continue
        except Exception as e:
            # Catch any other unexpected errors during the request
            print(f"Unexpected Error during {protocol.upper()} request for {url}: {e}")
            last_error = f"An unexpected error occurred ({type(e).__name__}): {e}"
            # Stop trying if an unexpected error occurs
            break

    # If loop finishes without success
    return {
        "status": "error",
        "error_message": last_error or f"Failed to connect to {hostname} via {', '.join(protocols_to_try)}.",
        "target_checked": hostname,
    }


url_env=None
model_env=None

description_env = "Agent to probe and answer questions about a specific host on the internet."
instruction_env = """I can take an IP address or hostname, probe it and  generate a professional looking (but short) report for 
            you to review. 
            
            Here are the steps I'll take            
            (1) Do an initial probe to understand which of the host/hosts requested by you are online
            (2) Gather server headers (for server name and version) if available using nmap
            (3) Make direct Web server and SSH server requests to gather more info on server names and versions as well
            (4) If I have more information about server names and versions and can create a CPE, I'll check if it matches any known issues
            (5) If there are any CVEs mapped to this, I'll pull more information on them as well
            (6) At the end, I'll generate a high level report which provides insight into what services are running,
                what versions may be outdated and may require an update,
                share info on what CVEs one would have to pay attention to
                and provide more details on the CVEs to judge the severity of the issue.
            
            The final report would be a nicely formated Text (use spaces to highlight report sections)  which is easy to read 
            and consume by security experts who are trying to identify and fix the top issues.
            
            For example the report could look like this
            
            
            Scanned host: scanme.nmap.org (45.33.32.156)
            [Summary]
                *   The host is running an Ubuntu Linux kernel.
                *   Open ports: 22 (SSH), 53 (domain), 80 (HTTP), 9929, 31337
                *   Web server: Apache 2.4.7 (Ubuntu)
                *   SSH server: OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
            
            
            
            
            """

try:
    url_env=os.environ["aprober_llm_url"]
    model_env=os.environ["aprober_llm_model"]
except:
    print("Using default config")    

if url_env and model_env:
    model=LiteLlm(model=model_env,api_base=url_env,)
    root_agent = LlmAgent(
        name="aprobe",
        model=LiteLlm(model="ollama/gemma2:latest",api_base="http://torque:11434",),
        description=(description_env),
        instruction=(instruction_env),
        tools=[
            NmapTCPVersionScan,
            GetWebServerHeader,
            GetSshServerVersion,
            GetCpeInfo, 
            TranslateCpeFormat,
            NmapHostDiscoveryScan,
        ],
    )

else:
    root_agent = Agent(
        name="aprober",
        model="gemini-2.0-flash-exp",
        description=(description_env),
        instruction=(instruction_env),
        tools=[
                NmapTCPVersionScan,
                GetWebServerHeader,
                GetSshServerVersion,
                GetCpeInfo, 
                TranslateCpeFormat,
                NmapHostDiscoveryScan,
            ],
    )
    
        
  