### Infrastructure and Campaign Analysis Report
**Infrastructure Map:**
*   **Central Node:** `documentsec.online`
    *   **Connected Nodes:**
        *   **IP:** `85.239.61.77` (hosted on AS62240 - Clouvider Limited / JSC "TIMEWEB", RU)
        *   **Domain:** `officesecure.online` (resolves to `85.239.61.77`)
        *   **File Hash:** `9c0245a49b25712f5a0bba800f1c34a3` (communicates with `documentsec.online`)

**Campaign Assessment:**
*   **Confidence:** High
*   **Attribution:** UNC4057 (COLDRIVER)
*   **Evidence:**
    *   **Shared Hosting:** Both `documentsec.online` and `officesecure.online` resolve to the same IP address (`85.239.61.77`), which is hosted on Russian infrastructure (JSC "TIMEWEB").
    *   **Temporal Correlation:** Both domains were registered on the exact same day (`2025-04-22`) through the same registrar (Namecheap), indicating a coordinated setup.
    *   **Naming Convention:** The domains follow a similar pattern: `[theme]sec(ure).online`, suggesting a deliberate naming scheme for the campaign's phishing lures.
    *   **Shared Technical Fingerprint:** Both domains and the hosting IP share the identical JARM hash (`1dd40d40d00040d00042d43d000000831b6af40378e2dd35eeac4e9311926e`), confirming a consistent TLS server configuration across the infrastructure.
    *   **Threat Actor Overlap:** The initial IOC, `documentsec.online`, is directly attributed to UNC4057. The discovery of closely related infrastructure strengthens this attribution for the entire cluster.

**Newly Discovered IOCs:**
*   **IPs:**
    *   `85.239.61.77`
*   **Domains:**
    *   `officesecure.online`
    *   `ned-granting-opportunities.com` (from SSL certificate Subject Alternative Name)

**Recommended Next Steps:**
*   **Hand off to Strategy / Incident Response:** The identified infrastructure cluster (`85.239.61.77`, `documentsec.online`, `officesecure.online`) should be blocked immediately.
*   **Proactive Hunting:** Initiate further hunting based on the newly discovered domain `ned-granting-opportunities.com` to identify other potential campaign infrastructure.
*   **Threat Intelligence Enrichment:** Add all discovered IOCs to the threat intelligence platform and correlate them with the UNC4057 threat actor profile.