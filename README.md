# aprober
An Agent based host prober - probe a host/ip using nmap/curl/etc and report back a human readable report.
* Primarily created to test the ease of using Google's ADK (Agent development kit).

## Setup
* Clone this repository
* Run init.sh or manually setup the python modules as needed
* This is using default config - if you want to change models you can follow instructions here - https://google.github.io/adk-docs/get-started/quickstart/#agentpy
* Under **aprobe** directory create a "**.env**" file with the following contents
  ```
  GOOGLE_GENAI_USE_VERTEXAI="False"
  GOOGLE_API_KEY="PUT_YOUR_GEMINI_KEY_HERE"
  ```


## How it works
* ADK [https://google.github.io/adk-docs/] - Agent development kit from Google allows one to create GenAI agents which can interact with each other to solve complex problems
* This version of aprober contains the following agents
  * NmapTCPVersionScan - Does nmap TCP scan and tries to get the server version
  * GetWebServerHeader - Uses curl to get HTTP response and guesses server name
  * GetSshServerVersion - Probes ssh server and extracts version info
  * GetCpeInfo - Gets CPE and CVE information about the versions detected
* Its currently using Gemini 2.0 Flash (you need to get your own key) - but its expected to be model and platform agnostic

## How to run
ADK can be used over the web or using shell
* "adk web" creates a web server which you can interact using your browser
* "adk run aprobe" allows you to interact with the engine in command line
* Below is the output of when I asked it to scan **scanme.nmap.org**
  ```
  user: please check scanme.nmap.org
    Starting Nmap TCP Version scan (-sT -sV) on scanme.nmap.org. This might take longer...
    Scan complete.
    Target 'scanme.nmap.org' resolved to IP '45.33.32.156' for scanning.
    [aprober]: Okay, I've scanned scanme.nmap.org and here's what I found:

    **Summary**

    *   The host is running an Ubuntu Linux kernel.
    *   Open ports: 22 (SSH), 53 (domain), 80 (HTTP), 9929, 31337
    *   Web server: Apache 2.4.7 (Ubuntu)
    *   SSH server: OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13

    Now, let's look for potential vulnerabilities. I'll focus on the Apache and OpenSSH versions.


    Querying NVD for CPE: cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*
    Searching for CPE details using cpeMatchString...
    Found CPE details for: cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*
    Searching for CVEs associated with CPE: cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:* (limit 20)...
    Reached CVE search limit (20). More CVEs might exist.
    Found 20 associated CVE(s).
    Querying NVD for CPE: cpe:2.3:a:openssh:openssh:6.6.1:p1:*:*:*:*:*:*
    Searching for CPE details using cpeMatchString...
    No specific details found for this exact CPE string via searchCPE.
    Searching for CVEs associated with CPE: cpe:2.3:a:openssh:openssh:6.6.1:p1:*:*:*:*:*:* (limit 20)...
    Found 0 associated CVE(s).
    [aprober]: Okay, I found CVEs associated with Apache 2.4.7. There are quite a few, and I've only retrieved a limited number (due to the API limit). I didn't find any associated CVEs with OpenSSH 6.6.1p1.
  ```
* And here is the final report

<hr>

**High-Level Report for scanme.nmap.org**

  **Target:** scanme.nmap.org (45.33.32.156)

  **Open Ports & Services:**

  *   **22/TCP:** SSH - OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13. This is a very old version of OpenSSH. Upgrade immediately!
  *   **53/TCP:** domain. Needs further investigation to determine the DNS server in use and potential vulnerabilities.
  *   **80/TCP:** HTTP - Apache 2.4.7 (Ubuntu). This is a very old version of Apache. There are multiple known vulnerabilities.
  *   **9929/TCP:** nping-echo. Likely used for testing purposes by Nmap.
  *   **31337/TCP:** tcpwrapped. This port is likely intentionally left open as a honeypot or for testing.

  **Potential Vulnerabilities & Recommendations:**

  1.  **Apache:** The detected Apache version is extremely outdated and vulnerable. Multiple CVEs exist. Upgrade to the latest stable version immediately. Some of the CVEs associated with this version include: CVE-2007-4723, CVE-2009-0796, CVE-2009-2299, CVE-2011-1176, CVE-2011-2688, CVE-2012-3526, CVE-2012-4001, CVE-2012-4360, CVE-2013-0941, CVE-2013-0942, CVE-2013-2765, CVE-2013-4365, CVE-2013-6438, CVE-2014-0098, CVE-2013-5704, CVE-2014-0117, CVE-2014-0118, CVE-2014-0226, CVE-2014-0231, CVE-2014-3523.
  2.  **OpenSSH:** The detected OpenSSH version is also quite old and should be upgraded.
  3.  **General:** Regularly update the OS (Ubuntu) and all installed packages to address potential vulnerabilities.

  **Next Steps:**

  *   **Immediately upgrade Apache and OpenSSH.**
  *   Investigate the services running on ports 53, 9929 and 31337 to determine their purpose and security implications.
  *   Perform a more comprehensive vulnerability scan using tools like Nessus or OpenVAS to identify any specific vulnerabilities.
  *   Review the changelogs and security advisories for Apache and OpenSSH for any relevant security patches.
  *   Ensure that appropriate firewall rules are in place to restrict access to the open ports.
  *   Monitor security mailing lists and vulnerability databases for new vulnerabilities affecting the identified software versions.

  This server is running very outdated software and is likely highly vulnerable. Immediate action is required.
