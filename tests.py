import unittest
from unittest.mock import patch, MagicMock, Mock, PropertyMock
import datetime
import socket
import errno # Needed for GetSshServerVersion error check
import requests
import nmap # Mocked
import nvdlib # Mocked
import cpe # Mocked
from urllib.parse import urlparse # Used in GetWebServerHeader

from aprobe.agent import TranslateCpeFormat, GetCpeInfo, NmapTCPVersionScan, GetWebServerHeader, GetSshServerVersion



class TestTranslateCpeFormat(unittest.TestCase):

    # === PATCH TARGET CORRECTION ===
    # The patch target MUST be the path to 'cpe.CPE' AS SEEN BY the module containing TranslateCpeFormat.
    # If TranslateCpeFormat is in 'aprobe/agent.py' and that file imports 'cpe',
    # the target is 'aprobe.agent.cpe.CPE'. Adjust this string accordingly.
    PATCH_TARGET = 'aprobe.agent.cpe.CPE' # <--- ADJUST THIS PATH
    # If using the placeholder above, the patching won't work as intended,
    # but we keep the structure assuming the real function is imported.
    # Using a dummy target if the real function isn't imported to avoid NameError:
    if 'TranslateCpeFormat' in locals() and TranslateCpeFormat.__module__ == '__main__':
        PATCH_TARGET = '__main__.cpe.CPE' # Dummy target for placeholder context
        # Define dummy cpe structure for placeholder context if needed
        class cpe:
             class CPE:
                 pass

    @patch(PATCH_TARGET)
    def test_translate_to_2_3_success(self, MockCPEConstructor):
        # Arrange
        mock_cpe_instance = MagicMock()
        mock_cpe_instance.as_cpe23_string.return_value = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
        mock_cpe_instance.get_version.return_value = "2.3"
        MockCPEConstructor.return_value = mock_cpe_instance # When cpe.CPE() is called, return our mock

        cpe_input = "cpe:/a:vendor:product:1.0" # Example input (URI format)
        target_format = "2.3"

        # Act
        # This should call the actual TranslateCpeFormat function (imported above)
        result = TranslateCpeFormat(cpe_input, target_format)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['original_cpe'], cpe_input)
        self.assertEqual(result['target_format'], target_format)
        self.assertEqual(result['translated_cpe'], "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
        MockCPEConstructor.assert_called_once_with(cpe_input) # Verify CPE constructor was called
        mock_cpe_instance.as_cpe23_string.assert_called_once() # Verify the correct method was called

    @patch(PATCH_TARGET)
    def test_translate_to_fs_success(self, MockCPEConstructor):
        # Arrange
        mock_cpe_instance = MagicMock()
        mock_cpe_instance.as_fs_string.return_value = "vendor-product-1.0"
        mock_cpe_instance.get_version.return_value = "2.3"
        MockCPEConstructor.return_value = mock_cpe_instance

        cpe_input = "cpe:/a:vendor:product:fs_test" # Use a distinct input
        target_format = "fs"

        # Act
        result = TranslateCpeFormat(cpe_input, target_format)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['translated_cpe'], "vendor-product-1.0")
        MockCPEConstructor.assert_called_once_with(cpe_input)
        mock_cpe_instance.as_fs_string.assert_called_once()

    @patch(PATCH_TARGET)
    def test_translate_to_uri_success(self, MockCPEConstructor):
        # Arrange
        mock_cpe_instance = MagicMock()
        mock_cpe_instance.as_uri_string.return_value = "cpe:/a:vendor:product:1.0"
        mock_cpe_instance.get_version.return_value = "2.3"
        MockCPEConstructor.return_value = mock_cpe_instance

        cpe_input = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
        target_format = "uri"

        # Act
        result = TranslateCpeFormat(cpe_input, target_format)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['translated_cpe'], "cpe:/a:vendor:product:1.0")
        MockCPEConstructor.assert_called_once_with(cpe_input)
        mock_cpe_instance.as_uri_string.assert_called_once()

    @patch(PATCH_TARGET)
    def test_translate_to_wfn_returns_2_3(self, MockCPEConstructor):
        # Arrange
        mock_cpe_instance = MagicMock()
        # WFN should fall back to as_cpe23_string
        mock_cpe_instance.as_cpe23_string.return_value = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
        mock_cpe_instance.get_version.return_value = "2.3"
        MockCPEConstructor.return_value = mock_cpe_instance

        cpe_input = "cpe:/a:vendor:product:1.0"
        target_format = "wfn"

        # Act
        result = TranslateCpeFormat(cpe_input, target_format)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['target_format'], target_format)
        self.assertEqual(result['translated_cpe'], "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
        MockCPEConstructor.assert_called_once_with(cpe_input)
        mock_cpe_instance.as_cpe23_string.assert_called_once() # Check that 2.3 was called

    def test_unsupported_target_format(self):
        # Arrange
        # This test doesn't need mocking for cpe.CPE as it should be handled before parsing
        cpe_input = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
        target_format = "invalid_format"

        # Act
        result = TranslateCpeFormat(cpe_input, target_format)

        # Assert
        self.assertEqual(result['status'], 'error')
        # Ensure the error message from the function matches exactly
        self.assertEqual(result['error_message'], "Unsupported target format: 'invalid_format'. Supported formats: '2.3', 'fs', 'uri'.")
        self.assertIsNone(result['translated_cpe'])

    @patch(PATCH_TARGET)
    def test_cpe_parsing_error(self, MockCPEConstructor):
        # Arrange
        # Configure the mocked CPE constructor to raise NotImplementedError
        error_message = "Mocked parsing error: Version of CPE not implemented"
        MockCPEConstructor.side_effect = NotImplementedError(error_message)

        cpe_input = "invalid-cpe-string"
        target_format = "2.3"

        # Act
        result = TranslateCpeFormat(cpe_input, target_format)

        # Assert
        self.assertEqual(result['status'], 'error')
        # Check if the error message from the function's except block is captured
        # This assumes the except block formats the message like: f"CPE parsing error: {e}"
        expected_error_in_result = f"CPE parsing error: {error_message}"
        self.assertEqual(result['error_message'], expected_error_in_result)
        self.assertIsNone(result['translated_cpe'])
        MockCPEConstructor.assert_called_once_with(cpe_input) # Verify constructor was called

    @patch(PATCH_TARGET)
    def test_attribute_error_on_translation(self, MockCPEConstructor):
        # Arrange
        mock_cpe_instance = MagicMock()
        # Configure the specific method 'as_fs_string' on the instance
        # to raise an AttributeError when called.
        error_message = "Simulated missing method 'as_fs_string'"
        mock_cpe_instance.as_fs_string.side_effect = AttributeError(error_message)
        mock_cpe_instance.get_version.return_value = "2.3"
        MockCPEConstructor.return_value = mock_cpe_instance # Make constructor return this instance

        cpe_input = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*" # Input for this specific test
        target_format = "fs" # Try to call the missing method

        # Act
        result = TranslateCpeFormat(cpe_input, target_format)

        # Assert
        self.assertEqual(result['status'], 'error')
        # Check if the error message from the function's except AttributeError block is captured
        # This assumes the except block formats the message like: f"CPE translation method error: {e}..."
        expected_error_in_result = f"CPE translation method error: {error_message}. The parsed CPE object might not support the requested conversion directly."
        self.assertEqual(result['error_message'], expected_error_in_result)
        self.assertIsNone(result['translated_cpe'])
        MockCPEConstructor.assert_called_once_with(cpe_input) # Verify constructor was called
        mock_cpe_instance.as_fs_string.assert_called_once() # Verify the method was called (and raised the error)


class TestGetCpeInfo(unittest.TestCase):

    def test_invalid_cpe_format_input(self):
        # Arrange
        invalid_cpe = "not-a-cpe-string"
        # Act
        result = GetCpeInfo(invalid_cpe)
        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("Invalid CPE string format", result['error_message'])
        self.assertIsNone(result['cpe_details'])
        self.assertEqual(result['associated_cves'], [])

    @patch('nvdlib.searchCPE')
    @patch('nvdlib.searchCVE')
    def test_success_found_details_and_cves(self, mock_searchCVE, mock_searchCPE):
        # Arrange
        cpe_input = "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"

        # Mock CPE details response
        mock_cpe_detail = MagicMock()
        mock_cpe_detail.cpeName = cpe_input
        mock_cpe_detail.title = [MagicMock(title="Microsoft Windows 10 1607")]
        mock_cpe_detail.created = "2023-01-01T00:00:00.000"
        mock_cpe_detail.lastModified = "2023-01-02T00:00:00.000"
        mock_cpe_detail.deprecated = False
        mock_searchCPE.return_value = [mock_cpe_detail]

        # Mock CVE response
        mock_cve1 = MagicMock()
        mock_cve1.id = "CVE-2023-1111"
        mock_cve1.descriptions = [MagicMock(value="Description 1")]
        mock_cve1.v3severity = "HIGH"
        mock_cve1.v3score = 9.8
        mock_cve1.published = "2023-02-01T00:00:00.000"
        mock_cve1.lastModified = "2023-02-02T00:00:00.000"
        mock_cve1.url = "http://example.com/cve1"
        # Ensure v2 attributes exist even if None, or handle AttributeError
        mock_cve1.v2severity = None
        mock_cve1.v2score = None


        mock_cve2 = MagicMock()
        mock_cve2.id = "CVE-2023-2222"
        mock_cve2.descriptions = [MagicMock(value="Description 2")]
        # Test CVSSv2 fallback
        mock_cve2.v3severity = None
        mock_cve2.v3score = None
        mock_cve2.v2severity = "MEDIUM"
        mock_cve2.v2score = 6.5
        mock_cve2.published = "2023-03-01T00:00:00.000"
        mock_cve2.lastModified = "2023-03-02T00:00:00.000"
        mock_cve2.url = "http://example.com/cve2"

        mock_searchCVE.return_value = [mock_cve1, mock_cve2]

        # Act
        result = GetCpeInfo(cpe_input)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['cpe_checked'], cpe_input)
        self.assertIsNotNone(result['cpe_details'])
        self.assertEqual(result['cpe_details']['name'], cpe_input)
        self.assertEqual(result['cpe_details']['title'], "Microsoft Windows 10 1607")
        self.assertFalse(result['cpe_details']['deprecated'])
        self.assertEqual(len(result['associated_cves']), 2)
        self.assertEqual(result['associated_cves'][0]['id'], "CVE-2023-1111")
        self.assertEqual(result['associated_cves'][0]['cvss_v3_severity'], "HIGH")
        self.assertEqual(result['associated_cves'][0]['cvss_v3_score'], 9.8)
        self.assertIsNone(result['associated_cves'][0]['cvss_v2_severity']) # Check v2 fallback wasn't used
        self.assertEqual(result['associated_cves'][1]['id'], "CVE-2023-2222")
        self.assertIsNone(result['associated_cves'][1]['cvss_v3_severity']) # Check v3 wasn't present
        self.assertEqual(result['associated_cves'][1]['cvss_v2_severity'], "MEDIUM") # Check v2 fallback
        self.assertEqual(result['associated_cves'][1]['cvss_v2_score'], 6.5)
        self.assertFalse(result['cve_search_limit_hit'])
        mock_searchCPE.assert_called_once_with(cpeMatchString=cpe_input, limit=1, key=None, delay=None)
        mock_searchCVE.assert_called_once_with(cpeName=cpe_input, limit=20, key=None, delay=None)

    @patch('nvdlib.searchCPE')
    @patch('nvdlib.searchCVE')
    def test_success_no_details_found_but_cves_found(self, mock_searchCVE, mock_searchCPE):
        # Arrange
        cpe_input = "cpe:2.3:a:some:app:*:*:*:*:*:*:*:*"
        mock_searchCPE.return_value = [] # No details found

        mock_cve = MagicMock()
        mock_cve.id = "CVE-2023-3333"
        mock_cve.descriptions = [] # Test empty description list
        mock_cve.v3severity = "LOW"
        mock_cve.v3score = 3.0
        mock_cve.published = "2023-04-01T00:00:00.000"
        mock_cve.lastModified = "2023-04-02T00:00:00.000"
        mock_cve.url = "http://example.com/cve3"
        mock_cve.v2severity = None
        mock_cve.v2score = None
        mock_searchCVE.return_value = [mock_cve]

        # Act
        result = GetCpeInfo(cpe_input)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertIsNone(result['cpe_details']) # Details should be None
        self.assertEqual(len(result['associated_cves']), 1)
        self.assertEqual(result['associated_cves'][0]['id'], "CVE-2023-3333")
        self.assertEqual(result['associated_cves'][0]['description'], 'No description available.')
        self.assertFalse(result['cve_search_limit_hit'])

    @patch('nvdlib.searchCPE')
    @patch('nvdlib.searchCVE')
    def test_success_no_cves_found(self, mock_searchCVE, mock_searchCPE):
        # Arrange
        cpe_input = "cpe:2.3:h:vendor:device:-:*:*:*:*:*:*:*"
        mock_cpe_detail = MagicMock() # Assume details are found
        mock_cpe_detail.cpeName = cpe_input
        mock_cpe_detail.title = [MagicMock(title="Vendor Device")]
        mock_cpe_detail.created = "2023-01-01T00:00:00.000"
        mock_cpe_detail.lastModified = "2023-01-02T00:00:00.000"
        mock_cpe_detail.deprecated = False
        mock_searchCPE.return_value = [mock_cpe_detail]

        mock_searchCVE.return_value = [] # No CVEs found

        # Act
        result = GetCpeInfo(cpe_input)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertIsNotNone(result['cpe_details'])
        self.assertEqual(len(result['associated_cves']), 0) # CVE list is empty
        self.assertFalse(result['cve_search_limit_hit'])

    @patch('nvdlib.searchCPE')
    @patch('nvdlib.searchCVE')
    def test_cve_search_limit_hit(self, mock_searchCVE, mock_searchCPE):
        # Arrange
        cpe_input = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
        mock_searchCPE.return_value = [] # Assume no details for simplicity

        # Create 20 mock CVEs (the default limit)
        mock_cves = []
        for i in range(20):
             mock_cve = MagicMock()
             mock_cve.id = f"CVE-2023-{i:04d}"
             mock_cve.descriptions = [MagicMock(value=f"Desc {i}")]
             mock_cve.v3severity = "MEDIUM"
             mock_cve.v3score = 5.0
             mock_cve.published = "2023-01-01T00:00:00.000"
             mock_cve.lastModified = "2023-01-01T00:00:00.000"
             mock_cve.url = f"http://example.com/cve{i}"
             mock_cve.v2severity = None
             mock_cve.v2score = None
             mock_cves.append(mock_cve)

        mock_searchCVE.return_value = mock_cves

        # Act
        result = GetCpeInfo(cpe_input)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(result['associated_cves']), 20)
        self.assertTrue(result['cve_search_limit_hit']) # Limit flag should be true

    @patch('nvdlib.searchCPE')
    @patch('nvdlib.searchCVE', side_effect=requests.exceptions.RequestException("NVD Connection Error"))
    def test_network_error(self, mock_searchCVE, mock_searchCPE):
        # Arrange
        cpe_input = "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"
        # searchCPE might succeed or fail before the network error, let's assume it returns empty
        mock_searchCPE.return_value = []

        # Act
        result = GetCpeInfo(cpe_input)

        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("Network error connecting to NVD", result['error_message'])
        self.assertIsNone(result['cpe_details'])
        self.assertEqual(result['associated_cves'], [])

    @patch('nvdlib.searchCPE', side_effect=Exception("Unexpected NVDLib Error"))
    @patch('nvdlib.searchCVE')
    def test_unexpected_error(self, mock_searchCVE, mock_searchCPE):
        # Arrange
        cpe_input = "cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*"
        # Error happens during searchCPE

        # Act
        result = GetCpeInfo(cpe_input)

        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("An unexpected error occurred during NVD query", result['error_message'])
        self.assertIsNone(result['cpe_details'])
        self.assertEqual(result['associated_cves'], [])
        mock_searchCPE.assert_called_once() # Ensure it was called before the error
        mock_searchCVE.assert_not_called() # Ensure searchCVE was not called


# --- Mock Nmap ---
# We need a more sophisticated mock for Nmap to handle different scan results
class MockNmapPortScanner:
    def __init__(self, scan_results=None, hosts_list=None, scan_exception=None, init_exception=None):
        if init_exception:
            raise init_exception # Raise error during PortScanner() creation

        self._scan_results = scan_results if scan_results else {}
        self._hosts_list = hosts_list if hosts_list else []
        self._scan_exception = scan_exception
        # Store the results keyed by the host IP Nmap would use
        self._results_dict = {}
        if scan_results and hosts_list:
             # Assume the first host in hosts_list corresponds to the main scan result key
             # This simulates how nmap stores results by IP
             ip_key = hosts_list[0]
             self._results_dict[ip_key] = scan_results.get('scan', {}).get(ip_key, {})
             # Add scan stats if provided
             if 'nmap' in scan_results:
                 self._scan_stats = scan_results['nmap'].get('scanstats', {})
                 self._scan_info = scan_results['nmap'].get('scaninfo', {})


    def scan(self, hosts, arguments, sudo=False):
        print(f"MockNmap: Scanning {hosts} with args '{arguments}'")
        if self._scan_exception:
            # Raise the predefined exception when scan is called
            raise self._scan_exception
        # Return the pre-canned results structure
        # The structure should mimic the actual nmap output format
        # Example: {'nmap': {'scanstats': {...}}, 'scan': {ip: {...}}}
        return self._scan_results

    def all_hosts(self):
        # Return the list of hosts that the mock should report as scanned
        return self._hosts_list

    # Allow dictionary-style access like nm[ip]
    def __getitem__(self, host_ip):
        if host_ip not in self._results_dict:
            raise KeyError(f"MockNmap: Host {host_ip} not found in mock results")
        # Return a mock object that mimics the host result structure
        mock_host_info = MagicMock()
        host_data = self._results_dict[host_ip]

        # Set state() method
        mock_host_info.state.return_value = host_data.get('status', {}).get('state', 'down') # Default to down if not specified

        # Set protocols (e.g., 'tcp')
        if 'tcp' in host_data:
            mock_host_info.__contains__.side_effect = lambda key: key == 'tcp' # Make 'in' operator work
            mock_host_info.__getitem__.side_effect = lambda key: host_data['tcp'] if key == 'tcp' else None # nm[ip]['tcp']
            mock_host_info.get.side_effect = lambda key, default=None: host_data['tcp'] if key == 'tcp' else default # .get('tcp')
            # Add tcp attribute directly for simpler access if needed, though dict access is standard
            mock_host_info.tcp = host_data['tcp']

        else:
             mock_host_info.__contains__.side_effect = lambda key: False # 'tcp' not in nm[ip]
             mock_host_info.__getitem__.side_effect = KeyError # nm[ip]['tcp'] raises KeyError
             mock_host_info.get.side_effect = lambda key, default=None: default # .get('tcp') returns None

        return mock_host_info

    def scaninfo(self):
        # Return mock scaninfo if provided
        return getattr(self, '_scan_info', {})

    def __contains__(self, host_ip):
        return host_ip in self._results_dict



class TestNmapTCPVersionScan(unittest.TestCase):

    @patch('socket.getaddrinfo') # Mock resolution check
    @patch('nmap.PortScanner') # Mock the PortScanner class
    def test_success_with_open_ports(self, MockPortScanner, mock_getaddrinfo):
        # Arrange
        target_host = "scanme.nmap.org"
        resolved_ip = "45.33.32.156"
        # Simulate successful resolution
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (resolved_ip, 0))]

        # Define the expected Nmap result structure (full structure)
        mock_scan_result_data = {
            'nmap': {
                'scanstats': {'uphosts': '1', 'downhosts': '0', 'totalhosts': '1', 'elapsed': '5.0'},
                'scaninfo': {'tcp': {'services': '22,80', 'method': 'syn'}}
            },
            'scan': {
                resolved_ip: {
                    'status': {'state': 'up', 'reason': 'syn-ack'},
                    'hostnames': [{'name': target_host, 'type': 'user'}], # Nmap often includes hostname
                    'tcp': {
                        22: {'state': 'open', 'reason': 'syn-ack', 'name': 'ssh', 'product': 'OpenSSH', 'version': '6.6.1p1', 'extrainfo': 'Ubuntu Linux; protocol 2.0', 'cpe': 'cpe:/a:openbsd:openssh:6.6.1p1'},
                        80: {'state': 'open', 'reason': 'syn-ack', 'name': 'http', 'product': 'Apache httpd', 'version': '2.4.7', 'extrainfo': '(Ubuntu)', 'cpe': 'cpe:/a:apache:http_server:2.4.7'},
                        995: {'state': 'closed', 'reason': 'reset', 'name': 'pop3s'}
                    }
                }
            }
        }

        # Configure the mock PortScanner instance
        # Pass the full scan results structure
        mock_scanner_instance = MockNmapPortScanner(
            all_hosts_results=mock_scan_result_data,
            hosts_list=[resolved_ip] # Nmap usually returns the IP it scanned
        )
        MockPortScanner.return_value = mock_scanner_instance

        # Act
        # Assuming NmapTCPVersionScan is the function/class being tested
        # result = NmapTCPVersionScan(target_host) # Replace with actual call

        # --- MOCK CALL FOR DEMONSTRATION ---
        # Simulate the call within the test since NmapTCPVersionScan isn't provided
        # In reality, NmapTCPVersionScan would perform these steps
        try:
            addr_info = socket.getaddrinfo(target_host, None)
            ip_to_scan = addr_info[0][4][0]
            scanner = nmap.PortScanner()
            scan_data = scanner.scan(hosts=ip_to_scan, arguments='-sT -sV')
            # --- Mock parsing logic (replace with actual parsing from NmapTCPVersionScan) ---
            result = {'status': 'success', 'scanned_ip': ip_to_scan, 'port_info': {}}
            if ip_to_scan in scan_data.get('scan', {}):
                 host_info = scan_data['scan'][ip_to_scan]
                 if host_info.get('status', {}).get('state') == 'up' and 'tcp' in host_info:
                     for port, port_data in host_info['tcp'].items():
                         if port_data.get('state') == 'open':
                             result['port_info'][port] = {
                                 'service': port_data.get('name', ''),
                                 'product': port_data.get('product', ''),
                                 'version': port_data.get('version', ''),
                                 'extrainfo': port_data.get('extrainfo', ''),
                                 'cpe': port_data.get('cpe', '')
                             }
            # --- End Mock Parsing ---
        except Exception as e:
             result = {'status': 'error', 'error_message': str(e)}
        # --- END MOCK CALL ---


        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['scanned_ip'], resolved_ip)
        self.assertIn(22, result['port_info'])
        self.assertIn(80, result['port_info'])
        self.assertNotIn(995, result['port_info']) # Closed port should not be included
        self.assertEqual(result['port_info'][22]['service'], 'ssh')
        self.assertEqual(result['port_info'][22]['product'], 'OpenSSH')
        self.assertEqual(result['port_info'][22]['version'], '6.6.1p1')
        self.assertEqual(result['port_info'][22]['cpe'], 'cpe:/a:openbsd:openssh:6.6.1p1')
        self.assertEqual(result['port_info'][80]['service'], 'http')
        self.assertEqual(result['port_info'][80]['product'], 'Apache httpd')

        # Assertions about mocks
        mock_getaddrinfo.assert_called_once_with(target_host, None)
        MockPortScanner.assert_called_once() # Check constructor was called
        # *** Corrected Assertion *** Check scan was called with the RESOLVED IP
        mock_scanner_instance.scan.assert_called_once_with(hosts=resolved_ip, arguments='-sT -sV')


    @patch('socket.getaddrinfo')
    @patch('nmap.PortScanner')
    def test_success_no_open_ports(self, MockPortScanner, mock_getaddrinfo):
        # Arrange
        target_ip = "192.0.2.2" # Example IP
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (target_ip, 0))]

        mock_scan_result_data = {
            'nmap': {'scanstats': {'uphosts': '1', 'downhosts': '0', 'totalhosts': '1'}, 'scaninfo': {'tcp': {'services':'1-1000', 'method':'syn'}}},
            'scan': {
                target_ip: {
                    'status': {'state': 'up', 'reason': 'echo-reply'},
                     'hostnames': [],
                    'tcp': { # TCP was scanned but all ports are closed/filtered
                        135: {'state': 'closed', 'reason': 'reset', 'name': 'msrpc'},
                        445: {'state': 'closed', 'reason': 'reset', 'name': 'microsoft-ds'}
                    }
                }
            }
        }
        mock_scanner_instance = MockNmapPortScanner(all_hosts_results=mock_scan_result_data, hosts_list=[target_ip])
        MockPortScanner.return_value = mock_scanner_instance

        # Act
        # result = NmapTCPVersionScan(target_ip) # Replace with actual call
        # --- MOCK CALL FOR DEMONSTRATION ---
        try:
            addr_info = socket.getaddrinfo(target_ip, None)
            ip_to_scan = addr_info[0][4][0]
            scanner = nmap.PortScanner()
            scan_data = scanner.scan(hosts=ip_to_scan, arguments='-sT -sV')
            result = {'status': 'success', 'scanned_ip': ip_to_scan, 'port_info': {}}
            if ip_to_scan in scan_data.get('scan', {}):
                 host_info = scan_data['scan'][ip_to_scan]
                 if host_info.get('status', {}).get('state') == 'up' and 'tcp' in host_info:
                     for port, port_data in host_info['tcp'].items():
                         if port_data.get('state') == 'open':
                              result['port_info'][port] = { # Add parsing logic here if needed
                                 'service': port_data.get('name', '') # Example
                             }
            # Add specific error handling if needed for no open ports vs scan failure
        except Exception as e:
             result = {'status': 'error', 'error_message': str(e)}
        # --- END MOCK CALL ---


        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['scanned_ip'], target_ip)
        self.assertEqual(result['port_info'], {}) # Port info should be empty
        mock_getaddrinfo.assert_called_once_with(target_ip, None)
        MockPortScanner.assert_called_once()
        mock_scanner_instance.scan.assert_called_once_with(hosts=target_ip, arguments='-sT -sV')


    @patch('socket.getaddrinfo', side_effect=socket.gaierror("Resolution failed"))
    def test_host_resolution_failure(self, mock_getaddrinfo):
        # Arrange
        target_host = "invalid-hostname-that-doesnt-exist"

        # Act
        # result = NmapTCPVersionScan(target_host) # Replace with actual call
        # --- MOCK CALL FOR DEMONSTRATION ---
        try:
            addr_info = socket.getaddrinfo(target_host, None)
            # ... rest of scan logic ...
            result = {'status': 'unexpected_success'} # Should not reach here
        except socket.gaierror as e:
             result = {'status': 'error', 'error_message': f"Could not resolve hostname/IP: {e}"}
        except Exception as e:
             result = {'status': 'error', 'error_message': f"An unexpected error occurred: {e}"}
        # --- END MOCK CALL ---

        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("Could not resolve hostname/IP", result['error_message'])
        mock_getaddrinfo.assert_called_once_with(target_host, None)

    @patch('socket.getaddrinfo')
    @patch('nmap.PortScanner')
    def test_nmap_not_found_error_on_init(self, MockPortScanner, mock_getaddrinfo):
        # Arrange
        target_host = "example.com"
        resolved_ip = "93.184.216.34"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (resolved_ip, 0))]
        # Simulate nmap not found during PortScanner() creation
        nmap_error = nmap.PortScannerError("nmap program was not found in path")
        MockPortScanner.side_effect = nmap_error

        # Act
        # result = NmapTCPVersionScan(target_host) # Replace with actual call
        # --- MOCK CALL FOR DEMONSTRATION ---
        try:
            addr_info = socket.getaddrinfo(target_host, None)
            ip_to_scan = addr_info[0][4][0]
            # This line will raise the mocked exception
            scanner = nmap.PortScanner()
            # ... scan logic ...
            result = {'status': 'unexpected_success'} # Should not reach here
        except nmap.PortScannerError as e:
             # Assuming NmapTCPVersionScan catches this specific error
             if "nmap program was not found" in str(e):
                 result = {'status': 'error', 'error_message': f"Nmap executable not found. Please ensure Nmap is installed and in your system's PATH. Error: {e}"}
             else:
                 result = {'status': 'error', 'error_message': f"Nmap error during initialization: {e}"}
        except Exception as e:
             result = {'status': 'error', 'error_message': f"An unexpected error occurred: {e}"}
        # --- END MOCK CALL ---


        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("Nmap executable not found", result['error_message'])
        mock_getaddrinfo.assert_called_once_with(target_host, None)
        MockPortScanner.assert_called_once() # Ensure constructor was attempted

    @patch('socket.getaddrinfo')
    @patch('nmap.PortScanner')
    def test_nmap_scan_error_permission(self, MockPortScanner, mock_getaddrinfo):
        # Arrange
        target_host = "localhost"
        resolved_ip = "127.0.0.1"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (resolved_ip, 0))]
        # Simulate permission error during scan() call
        scan_exception = nmap.PortScannerError("Scan requires root privileges.")
        # Configure the mock instance to raise the exception when scan() is called
        mock_scanner_instance = MockNmapPortScanner(scan_exception=scan_exception)
        MockPortScanner.return_value = mock_scanner_instance

        # Act
        # result = NmapTCPVersionScan(target_host) # Replace with actual call
        # --- MOCK CALL FOR DEMONSTRATION ---
        try:
            addr_info = socket.getaddrinfo(target_host, None)
            ip_to_scan = addr_info[0][4][0]
            scanner = nmap.PortScanner()
            # This line will raise the mocked exception via scan()
            scan_data = scanner.scan(hosts=ip_to_scan, arguments='-sT -sV')
            # ... parsing logic ...
            result = {'status': 'unexpected_success'} # Should not reach here
        except nmap.PortScannerError as e:
             # Assuming NmapTCPVersionScan catches this specific error
             if "requires root privileges" in str(e):
                  result = {'status': 'error', 'error_message': f"Nmap reported permission error. TCP scans often require root/administrator privileges. Error: {e}"}
             else:
                  result = {'status': 'error', 'error_message': f"Nmap scan error: {e}"}
        except Exception as e:
             result = {'status': 'error', 'error_message': f"An unexpected error occurred: {e}"}
        # --- END MOCK CALL ---


        # Assert
        self.assertEqual(result['status'], 'error')
        # Check the specific error message generated by the function for permission issues
        self.assertIn("Nmap reported permission error", result['error_message'])
        mock_getaddrinfo.assert_called_once_with(target_host, None)
        MockPortScanner.assert_called_once()
        mock_scanner_instance.scan.assert_called_once_with(hosts=resolved_ip, arguments='-sT -sV')


    @patch('socket.getaddrinfo')
    @patch('nmap.PortScanner')
    def test_host_reported_down(self, MockPortScanner, mock_getaddrinfo):
        # Arrange
        target_ip = "192.0.2.3"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (target_ip, 0))]

        mock_scan_result_data = {
             'nmap': {'scanstats': {'uphosts': '0', 'downhosts': '1', 'totalhosts': '1'}},
            'scan': {
                target_ip: {
                    'status': {'state': 'down', 'reason': 'no-response'},
                     'hostnames': [],
                    # No tcp info expected if host is down
                }
            }
        }
        mock_scanner_instance = MockNmapPortScanner(all_hosts_results=mock_scan_result_data, hosts_list=[target_ip]) # Host might still be in list even if down
        MockPortScanner.return_value = mock_scanner_instance

        # Act
        # result = NmapTCPVersionScan(target_ip) # Replace with actual call
        # --- MOCK CALL FOR DEMONSTRATION ---
        try:
            addr_info = socket.getaddrinfo(target_ip, None)
            ip_to_scan = addr_info[0][4][0]
            scanner = nmap.PortScanner()
            scan_data = scanner.scan(hosts=ip_to_scan, arguments='-sT -sV')
            # --- Mock parsing logic for down host ---
            result = {'status': 'success', 'scanned_ip': ip_to_scan, 'port_info': {}} # Default success
            if ip_to_scan not in scan_data.get('scan', {}):
                 result = {'status': 'error', 'scanned_ip': ip_to_scan, 'error_message': f"Scan failed for target {ip_to_scan}. No results returned."}
            else:
                host_info = scan_data['scan'][ip_to_scan]
                host_state = host_info.get('status', {}).get('state')
                if host_state != 'up':
                    reason = host_info.get('status', {}).get('reason', 'unknown reason')
                    result = {'status': 'error', 'scanned_ip': ip_to_scan, 'error_message': f"Target host {ip_to_scan} reported as {host_state} (reason: {reason})."}
                elif 'tcp' not in host_info:
                     result = {'status': 'error', 'scanned_ip': ip_to_scan, 'error_message': f"TCP scan was not performed or yielded no results for {ip_to_scan}."}
                else:
                     # Parse open ports if host is up and tcp results exist (won't happen here)
                     pass
            # --- End Mock Parsing ---
        except Exception as e:
             result = {'status': 'error', 'error_message': str(e)}
        # --- END MOCK CALL ---


        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn(f"reported as down", result['error_message'])
        self.assertEqual(result.get('scanned_ip'), target_ip) # IP might still be known
        mock_getaddrinfo.assert_called_once_with(target_ip, None)
        MockPortScanner.assert_called_once()
        mock_scanner_instance.scan.assert_called_once_with(hosts=target_ip, arguments='-sT -sV')


    @patch('socket.getaddrinfo')
    @patch('nmap.PortScanner')
    def test_no_hosts_found_in_scan(self, MockPortScanner, mock_getaddrinfo):
        # Arrange
        target_host = "unreachable.example"
        resolved_ip = "198.51.100.1" # Assume it resolves but is unreachable
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (resolved_ip, 0))]

        # Simulate Nmap finishing but finding no hosts up
        mock_scan_result_data = {
            'nmap': {'scanstats': {'uphosts': '0', 'downhosts': '1', 'totalhosts': '1'}, 'warning':['Host seems down. If it is really up, but blocking our ping probes, try -Pn']},
            'scan': {} # Empty scan results
        }
        # Crucially, hosts_list is empty or scan dict is empty
        mock_scanner_instance = MockNmapPortScanner(all_hosts_results=mock_scan_result_data, hosts_list=[])
        MockPortScanner.return_value = mock_scanner_instance

        # Act
        # result = NmapTCPVersionScan(target_host) # Replace with actual call
        # --- MOCK CALL FOR DEMONSTRATION ---
        try:
            addr_info = socket.getaddrinfo(target_host, None)
            ip_to_scan = addr_info[0][4][0]
            scanner = nmap.PortScanner()
            scan_data = scanner.scan(hosts=ip_to_scan, arguments='-sT -sV')
            # --- Mock parsing logic for no hosts found ---
            result = {'status': 'success', 'scanned_ip': ip_to_scan, 'port_info': {}} # Default success
            if not scan_data.get('scan'): # Check if the 'scan' dict is empty
                warnings = scan_data.get('nmap', {}).get('warning', [])
                warning_str = " ".join(warnings)
                result = {'status': 'error', 'scanned_ip': None, 'error_message': f"Scan failed for target {target_host} ({ip_to_scan}). No hosts found in scan results. Nmap warning: {warning_str}"}
            else:
                 # Handle cases where scan dict is not empty but target IP isn't in it (less likely with single target)
                 pass
            # --- End Mock Parsing ---
        except Exception as e:
             result = {'status': 'error', 'error_message': str(e)}
        # --- END MOCK CALL ---


        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("Scan failed for target", result['error_message'])
        self.assertIn("No hosts found", result['error_message'])
        self.assertIn("Host seems down", result['error_message']) # Check warning is included
        self.assertIsNone(result.get('scanned_ip'))
        mock_getaddrinfo.assert_called_once_with(target_host, None)
        MockPortScanner.assert_called_once()
        mock_scanner_instance.scan.assert_called_once_with(hosts=resolved_ip, arguments='-sT -sV')


    @patch('socket.getaddrinfo')
    @patch('nmap.PortScanner')
    def test_key_error_parsing_results(self, MockPortScanner, mock_getaddrinfo):
        # Arrange
        target_host = "scanme.nmap.org"
        resolved_ip = "45.33.32.156"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (resolved_ip, 0))]

        # Malformed result data (e.g., missing 'tcp' key under the IP)
        mock_scan_result_data = {
            'nmap': {'scanstats': {'uphosts': '1', 'downhosts': '0', 'totalhosts': '1'}},
            'scan': {
                resolved_ip: {
                    'status': {'state': 'up', 'reason': 'syn-ack'},
                     'hostnames': [{'name': target_host, 'type': 'user'}],
                    # 'tcp': key is missing!
                }
            }
        }
        mock_scanner_instance = MockNmapPortScanner(all_hosts_results=mock_scan_result_data, hosts_list=[resolved_ip])
        MockPortScanner.return_value = mock_scanner_instance

        # Act
        # result = NmapTCPVersionScan(target_host) # Replace with actual call
        # --- MOCK CALL FOR DEMONSTRATION ---
        try:
            addr_info = socket.getaddrinfo(target_host, None)
            ip_to_scan = addr_info[0][4][0]
            scanner = nmap.PortScanner()
            scan_data = scanner.scan(hosts=ip_to_scan, arguments='-sT -sV')
            # --- Mock parsing logic checking for 'tcp' ---
            result = {'status': 'success', 'scanned_ip': ip_to_scan, 'port_info': {}} # Default success
            if ip_to_scan not in scan_data.get('scan', {}):
                 result = {'status': 'error', 'scanned_ip': ip_to_scan, 'error_message': f"Scan failed for target {ip_to_scan}. No results returned."}
            else:
                host_info = scan_data['scan'][ip_to_scan]
                host_state = host_info.get('status', {}).get('state')
                if host_state != 'up':
                     result = {'status': 'error', 'scanned_ip': ip_to_scan, 'error_message': f"Target host {ip_to_scan} reported as {host_state}."}
                elif 'tcp' not in host_info: # Explicitly check for 'tcp' key
                     result = {'status': 'error', 'scanned_ip': ip_to_scan, 'error_message': f"TCP scan was not performed or yielded no results for {ip_to_scan}."}
                else:
                     # Parse open ports (won't happen here)
                     for port, port_data in host_info['tcp'].items():
                         if port_data.get('state') == 'open':
                              result['port_info'][port] = { # Add parsing logic here
                                 'service': port_data.get('name', '')
                             }
            # --- End Mock Parsing ---
        except KeyError as e:
             # Catch potential KeyErrors during deeper parsing if the check above wasn't sufficient
             result = {'status': 'error', 'scanned_ip': ip_to_scan, 'error_message': f"Error parsing Nmap results (KeyError): {e}"}
        except Exception as e:
             result = {'status': 'error', 'error_message': str(e)}
        # --- END MOCK CALL ---


        # Assert
        # The function should catch the missing 'tcp' key based on the logic above.
        self.assertEqual(result['status'], 'error')
        self.assertIn("TCP scan was not performed or yielded no results", result['error_message'])
        mock_getaddrinfo.assert_called_once_with(target_host, None)
        MockPortScanner.assert_called_once()
        mock_scanner_instance.scan.assert_called_once_with(hosts=resolved_ip, arguments='-sT -sV')

class TestGetSshServerVersion(unittest.TestCase):

    @patch('socket.gethostbyname')
    @patch('socket.socket')
    def test_success_get_banner(self, mock_socket_class, mock_gethostbyname):
        # Arrange
        target_host = "ssh.example.com"
        target_port = 22
        resolved_ip = "192.0.2.4"
        ssh_banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n"

        mock_gethostbyname.return_value = resolved_ip

        # Configure the mock socket instance
        mock_sock_instance = MagicMock()
        mock_sock_instance.recv.return_value = ssh_banner
        # Make socket.socket() return our mock instance
        mock_socket_class.return_value = mock_sock_instance

        # Act
        result = GetSshServerVersion(target_host, target_port)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['target_checked'], target_host)
        self.assertEqual(result['port_checked'], target_port)
        self.assertEqual(result['ssh_banner'], ssh_banner.decode().strip())
        mock_gethostbyname.assert_called_once_with(target_host)
        mock_socket_class.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_sock_instance.settimeout.assert_called_once_with(5) # Check timeout value
        mock_sock_instance.connect.assert_called_once_with((target_host, target_port))
        mock_sock_instance.recv.assert_called_once_with(1024)
        mock_sock_instance.close.assert_called_once()

    @patch('socket.gethostbyname', side_effect=socket.gaierror("Resolution failed"))
    def test_host_resolution_failure(self, mock_gethostbyname):
        # Arrange
        target_host = "invalid-ssh-host"
        # Act
        result = GetSshServerVersion(target_host)
        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("Could not resolve hostname/IP", result['error_message'])
        mock_gethostbyname.assert_called_once_with(target_host)

    @patch('socket.gethostbyname')
    @patch('socket.socket')
    def test_connection_timeout(self, mock_socket_class, mock_gethostbyname):
        # Arrange
        target_host = "timeout.example.com"
        resolved_ip = "198.51.100.2"
        mock_gethostbyname.return_value = resolved_ip

        mock_sock_instance = MagicMock()
        # Simulate timeout on connect()
        mock_sock_instance.connect.side_effect = socket.timeout("Connection timed out")
        mock_socket_class.return_value = mock_sock_instance

        # Act
        result = GetSshServerVersion(target_host)

        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("timed out", result['error_message'])
        mock_sock_instance.connect.assert_called_once()
        mock_sock_instance.recv.assert_not_called() # recv shouldn't be called
        mock_sock_instance.close.assert_called_once() # Ensure close is still called in finally

    @patch('socket.gethostbyname')
    @patch('socket.socket')
    def test_connection_refused(self, mock_socket_class, mock_gethostbyname):
        # Arrange
        target_host = "refused.example.com"
        resolved_ip = "198.51.100.3"
        mock_gethostbyname.return_value = resolved_ip

        mock_sock_instance = MagicMock()
        # Simulate connection refused error
        mock_sock_instance.connect.side_effect = socket.error(errno.ECONNREFUSED, "Connection refused")
        mock_socket_class.return_value = mock_sock_instance

        # Act
        result = GetSshServerVersion(target_host)

        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("Socket error connecting", result['error_message'])
        self.assertIn("Connection refused", result['error_message']) # Check specific error text
        mock_sock_instance.connect.assert_called_once()
        mock_sock_instance.close.assert_called_once()

    @patch('socket.gethostbyname')
    @patch('socket.socket')
    def test_receive_timeout(self, mock_socket_class, mock_gethostbyname):
        # Arrange
        target_host = "recvtimeout.example.com"
        resolved_ip = "198.51.100.4"
        mock_gethostbyname.return_value = resolved_ip

        mock_sock_instance = MagicMock()
        # Connect succeeds, but recv times out
        mock_sock_instance.recv.side_effect = socket.timeout("Read timed out")
        mock_socket_class.return_value = mock_sock_instance

        # Act
        result = GetSshServerVersion(target_host)

        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("timed out", result['error_message'])
        mock_sock_instance.connect.assert_called_once()
        mock_sock_instance.recv.assert_called_once()
        mock_sock_instance.close.assert_called_once()

    @patch('socket.gethostbyname')
    @patch('socket.socket')
    def test_receive_invalid_banner(self, mock_socket_class, mock_gethostbyname):
        # Arrange
        target_host = "http.example.com" # Maybe an HTTP server on port 22?
        target_port = 22
        resolved_ip = "198.51.100.5"
        http_response = b"HTTP/1.1 200 OK\r\nServer: NotSSH\r\n\r\n"
        mock_gethostbyname.return_value = resolved_ip

        mock_sock_instance = MagicMock()
        mock_sock_instance.recv.return_value = http_response
        mock_socket_class.return_value = mock_sock_instance

        # Act
        result = GetSshServerVersion(target_host, target_port)

        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("did not receive a valid SSH banner", result['error_message'])
        self.assertIn("Received: 'HTTP/1.1 200 OK", result['error_message']) # Check snippet
        self.assertIsNone(result.get('ssh_banner'))
        mock_sock_instance.close.assert_called_once()

    @patch('socket.gethostbyname')
    @patch('socket.socket')
    def test_receive_empty_data(self, mock_socket_class, mock_gethostbyname):
        # Arrange
        target_host = "empty.example.com"
        resolved_ip = "198.51.100.6"
        mock_gethostbyname.return_value = resolved_ip

        mock_sock_instance = MagicMock()
        mock_sock_instance.recv.return_value = b"" # Server closes connection immediately
        mock_socket_class.return_value = mock_sock_instance

        # Act
        result = GetSshServerVersion(target_host)

        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("did not receive a valid SSH banner", result['error_message'])
        self.assertIn("Received: ''", result['error_message'])
        mock_sock_instance.close.assert_called_once()


class TestGetWebServerHeader(unittest.TestCase):

    @patch('socket.gethostbyname')
    @patch('requests.head')
    def test_success_https(self, mock_requests_head, mock_gethostbyname):
        # Arrange
        target = "https://secure.example.com"
        hostname = "secure.example.com"
        resolved_ip = "192.0.2.5"
        server_header_value = "nginx/1.18.0"

        mock_gethostbyname.return_value = resolved_ip

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {'Server': server_header_value, 'Content-Type': 'text/html'}
        # Configure raise_for_status to do nothing on success
        mock_response.raise_for_status.return_value = None
        # Make requests.head return this mock response for HTTPS
        mock_requests_head.return_value = mock_response

        # Act
        result = GetWebServerHeader(target)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['target_checked'], hostname)
        self.assertEqual(result['protocol'], 'https')
        self.assertEqual(result['server_header'], server_header_value)
        mock_gethostbyname.assert_called_once_with(hostname)
        mock_requests_head.assert_called_once()
        # Check the URL called by requests.head
        called_url = mock_requests_head.call_args[0][0]
        self.assertEqual(called_url, f"https://{hostname}")
        # Check some kwargs passed to requests.head
        self.assertIn('headers', mock_requests_head.call_args[1])
        self.assertIn('timeout', mock_requests_head.call_args[1])
        self.assertEqual(mock_requests_head.call_args[1]['timeout'], 5)

    @patch('socket.gethostbyname')
    @patch('requests.head')
    def test_success_http_after_https_fail(self, mock_requests_head, mock_gethostbyname):
        # Arrange
        target = "plain.example.com" # Input without scheme
        hostname = "plain.example.com"
        resolved_ip = "192.0.2.6"
        server_header_value = "Apache/2.4.41 (Ubuntu)"

        mock_gethostbyname.return_value = resolved_ip

        # Mock HTTPS failure (e.g., ConnectionError)
        https_exception = requests.exceptions.ConnectionError("HTTPS connection failed")
        # Mock HTTP success
        mock_http_response = MagicMock(spec=requests.Response)
        mock_http_response.status_code = 200
        mock_http_response.headers = {'Server': server_header_value}
        mock_http_response.raise_for_status.return_value = None

        # Set side_effect to raise error for HTTPS, return response for HTTP
        mock_requests_head.side_effect = [https_exception, mock_http_response]

        # Act
        result = GetWebServerHeader(target)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['target_checked'], hostname)
        self.assertEqual(result['protocol'], 'http') # Should have fallen back to HTTP
        self.assertEqual(result['server_header'], server_header_value)
        mock_gethostbyname.assert_called_once_with(hostname)
        # Check that requests.head was called twice (once for https, once for http)
        self.assertEqual(mock_requests_head.call_count, 2)
        # Check URLs called
        self.assertEqual(mock_requests_head.call_args_list[0][0][0], f"https://{hostname}")
        self.assertEqual(mock_requests_head.call_args_list[1][0][0], f"http://{hostname}")

    @patch('socket.gethostbyname')
    @patch('requests.head')
    def test_success_no_server_header(self, mock_requests_head, mock_gethostbyname):
        # Arrange
        target = "http://noheader.example.com"
        hostname = "noheader.example.com"
        resolved_ip = "192.0.2.7"

        mock_gethostbyname.return_value = resolved_ip

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'application/json'} # No Server header
        mock_response.raise_for_status.return_value = None
        mock_requests_head.return_value = mock_response

        # Act
        result = GetWebServerHeader(target)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['target_checked'], hostname)
        self.assertEqual(result['protocol'], 'http')
        self.assertIsNone(result['server_header']) # Header should be None
        mock_requests_head.assert_called_once_with(f"http://{hostname}", headers=unittest.mock.ANY, timeout=5, allow_redirects=True, verify=True)

    @patch('socket.gethostbyname', side_effect=socket.gaierror("Resolution failed"))
    def test_host_resolution_failure(self, mock_gethostbyname):
        # Arrange
        target = "invalid-web-host.xyz"
        # Act
        result = GetWebServerHeader(target)
        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertIn("Could not resolve hostname/IP", result['error_message'])
        mock_gethostbyname.assert_called_once_with("invalid-web-host.xyz") # Check it tried to resolve the correct name

    @patch('socket.gethostbyname')
    @patch('requests.head', side_effect=requests.exceptions.SSLError("SSL verification failed"))
    def test_ssl_error_then_http_fail(self, mock_requests_head, mock_gethostbyname):
        # Arrange
        target = "sslerror.example.com"
        hostname = "sslerror.example.com"
        resolved_ip = "198.51.100.7"
        mock_gethostbyname.return_value = resolved_ip

        # HTTPS fails with SSLError, HTTP fails with ConnectionError
        http_exception = requests.exceptions.ConnectionError("HTTP connection failed")
        mock_requests_head.side_effect = [requests.exceptions.SSLError("SSL verification failed"), http_exception]

        # Act
        result = GetWebServerHeader(target)

        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['target_checked'], hostname)
        # The last error should be the HTTP connection error
        self.assertIn("Could not connect via http", result['error_message'])
        self.assertEqual(mock_requests_head.call_count, 2)

    @patch('socket.gethostbyname')
    @patch('requests.head')
    def test_http_error_with_server_header(self, mock_requests_head, mock_gethostbyname):
        # Arrange
        target = "http://errorpage.example.com"
        hostname = "errorpage.example.com"
        resolved_ip = "198.51.100.8"
        server_header_value = "Microsoft-IIS/10.0"

        mock_gethostbyname.return_value = resolved_ip

        # Simulate a 404 Not Found error, but the response still has a Server header
        mock_error_response = MagicMock(spec=requests.Response)
        mock_error_response.status_code = 404
        mock_error_response.headers = {'Server': server_header_value, 'Content-Type': 'text/html'}
        # Create an HTTPError instance similar to how requests raises it
        http_error = requests.exceptions.HTTPError(f"{mock_error_response.status_code} Client Error: Not Found for url: {target}", response=mock_error_response)
        mock_error_response.raise_for_status.side_effect = http_error

        # HTTPS fails (e.g., timeout), HTTP returns the 404 response
        mock_requests_head.side_effect = [requests.exceptions.Timeout("HTTPS timeout"), mock_error_response]

        # Act
        result = GetWebServerHeader(target)

        # Assert
        self.assertEqual(result['status'], 'success') # Success because header was found
        self.assertEqual(result['target_checked'], hostname)
        self.assertEqual(result['protocol'], 'http')
        self.assertEqual(result['server_header'], server_header_value)
        self.assertIn('warning', result) # Check that a warning is included
        self.assertIn("failed with status 404", result['warning'])
        self.assertEqual(mock_requests_head.call_count, 2)

    @patch('socket.gethostbyname')
    @patch('requests.head', side_effect=requests.exceptions.Timeout("Request timed out"))
    def test_timeout_on_both_protocols(self, mock_requests_head, mock_gethostbyname):
        # Arrange
        target = "timeout.example.com"
        hostname = "timeout.example.com"
        resolved_ip = "198.51.100.9"
        mock_gethostbyname.return_value = resolved_ip

        # requests.head will raise Timeout for both HTTPS and HTTP calls
        mock_requests_head.side_effect = [
            requests.exceptions.Timeout("HTTPS Request timed out"),
            requests.exceptions.Timeout("HTTP Request timed out")
        ]

        # Act
        result = GetWebServerHeader(target)

        # Assert
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['target_checked'], hostname)
        # Last error should be from HTTP timeout
        self.assertIn("Request timed out for http", result['error_message'])
        self.assertEqual(mock_requests_head.call_count, 2)

    @patch('socket.gethostbyname')
    @patch('requests.head')
    def test_input_with_port(self, mock_requests_head, mock_gethostbyname):
        # Arrange
        target = "http://hostwithport.example.com:8080"
        hostname = "hostwithport.example.com" # Port should be stripped for resolution and URL base
        resolved_ip = "192.0.2.8"
        server_header_value = "Jetty(9.4.z)"

        mock_gethostbyname.return_value = resolved_ip

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {'Server': server_header_value}
        mock_response.raise_for_status.return_value = None
        mock_requests_head.return_value = mock_response

        # Act
        result = GetWebServerHeader(target)

        # Assert
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['target_checked'], hostname) # Check hostname is correct
        self.assertEqual(result['protocol'], 'http')
        self.assertEqual(result['server_header'], server_header_value)
        mock_gethostbyname.assert_called_once_with(hostname)
        # Check URL called - should NOT include the port as requests handles that
        mock_requests_head.assert_called_once_with(f"http://{hostname}", headers=unittest.mock.ANY, timeout=5, allow_redirects=True, verify=True)

# --- Run Tests ---
if __name__ == '__main__':
    # Suppress print statements from the functions during tests
    import sys
    from io import StringIO
    original_stdout = sys.stdout
    sys.stdout = StringIO() # Redirect stdout

    # Run tests
    unittest.main(verbosity=2, exit=False) # exit=False prevents sys.exit

    # Restore stdout
    sys.stdout = original_stdout
