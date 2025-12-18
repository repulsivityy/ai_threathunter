### Infrastructure and Campaign Analysis Report
**Infrastructure Map:**
*   **Central Node:** `3553d068f85437c23d08d89cac57fa70f78c50eb4ed3c032c37003b99cafc627` (File Hash - LOGICBURST)
    *   Communicates with C2 Domain: `load.serverpit.com`
*   **Connected Nodes:**
    *   **IP:** `210.16.120.35` (hosted on AS7489 - HostUS, Singapore)
        *   Hosts C2 Domain: `load.serverpit.com`
        *   Hosts Related C2 Domain: `test.serverpit.com`
    *   **Domain:** `load.serverpit.com` (resolves to `210.16.120.35`)
    *   **Domain:** `test.serverpit.com` (resolves to `210.16.120.35`)

**Campaign Assessment:**
*   **Confidence:** High
*   **Attribution:** UNC6492 (APT43 subcluster), LOGICBURST Malware. This is supported by the initial IOC assessment.
*   **Evidence:** The investigation confirms a coordinated campaign with high confidence. The primary evidence is the **shared C2 infrastructure**. Both `load.serverpit.com` (contacted by the malware) and `test.serverpit.com` resolve to the same IP address, `210.16.120.35`. The similar naming convention (`load.` and `test.` subdomains on the same parent domain `serverpit.com`) is a classic indicator of adversary-controlled infrastructure used for specific functions within a single campaign. The use of a dynamic DNS provider (`afraid.org`) for the nameservers is also a common TTP for threat actors seeking to maintain operational flexibility.

**Newly Discovered IOCs:**
*   **IPs:**
    *   `210.16.120.35`
*   **Domains:**
    *   `test.serverpit.com`

**Recommended Next Steps:**
*   **[Hand off to Strategy / Close Alert]**
    *   The newly discovered IOCs (`210.16.120.35`, `test.serverpit.com`) should be added to blocklists and threat intelligence platforms.
    *   Network logs should be searched retroactively for any communication with either domain or the IP address to identify other potentially compromised systems.
    *   The alert can be closed as the immediate infrastructure has been mapped and correlated to a known threat actor campaign.