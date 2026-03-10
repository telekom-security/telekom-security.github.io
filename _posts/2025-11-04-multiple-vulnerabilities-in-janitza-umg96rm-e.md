---
title: Multiple vulnerabilities in Janitza UMG 96RM-E
header:  Multiple vulnerabilities in Janitza UMG 96RM-E
tags: ['advisories']
cwes: ['CWE-78 (Improper Neutralization of Special Elements used in an OS Command)', 'CWE-798 (Use of Hard-coded Credentials)', 'CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)', 'CWE-732 (Incorrect Permission Assignment for Critical Resource)']
affected_product: 'Janitza UMG 96RM-E firmware versions below 3.14'
vulnerability_release_date: '2025-11-04'
---

Several vulnerabilities were discovered during testing of a Janitza UMG 96RM-E device.<!--more-->

### Details

* **Product:** UMG 96RM-E (both 24V and 230V versions)
* **Affected Version:** firmware versions below 3.14
* **Vulnerability Type:** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') (CWE-78), Use of Hard-coded Credentials (CWE-798), Use of a Broken or Risky Cryptographic Algorithm (CWE-327) and Incorrect Permission Assignment for Critical Resource (CWE-732)
* **Risk Level:** Critical
* **Vendor URL:** https://www.janitza.com/
* **Vendor acknowledged vulnerability:** Yes
* **Vendor Status:** Updated firmware available
* **CVEs:** CVE-2025-41709, CVE-2025-41710, CVE-2025-41711, CVE-2025-41712

The vulnerabilities were discovered during testing a device of type UMG 96RM-E. These vulnerabilities in combination allow an unauthenticated remote attacker to fully compromise the system including remote code execution.

It is strongly advised to update to the newest version. The vulnerabilities are fixed in version 3.14. In addition, such devices shall be operated in a closed network protected by a suitable firewall. Network access to the device should be limited to only enable necessary components to access it and protocols not necessary for the operation should be blocked.

### [CVE-2025-41709](https://www.cve.org/CVERecord?id=CVE-2025-41709): Command injection via Modbus

A high privileged remote attacker can perform a command injection via Modbus to gain read and write access on the affected device. This vulnerability has a CVSSv3.1 Base Score of [9.8](https://www.first.org/cvss/calculator/3-1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) and is rated CRITICAL.

### [CVE-2025-41710](https://www.cve.org/CVERecord?id=CVE-2025-41710): Use of Hard-coded Credentials

An unauthenticated remote attacker may use hardcoded credentials to get access to the previously activated FTP Server with limited write privileges. This vulnerability has a CVSSv3.1 Base Score of [5.3](https://www.first.org/cvss/calculator/3-1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N) and is rated MEDIUM.

### [CVE-2025-41711](https://www.cve.org/CVERecord?id=CVE-2025-41711): Use of firmware images to extract password hashes and brute force plaintext passwords

An unauthenticated remote attacker can use firmware images to extract password hashes and brute force plaintext passwords of accounts with limited access. This vulnerability has a CVSSv3.1 Base Score of [5.3](https://www.first.org/cvss/calculator/3-1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) and is rated MEDIUM.

### [CVE-2025-41712](https://www.cve.org/CVERecord?id=CVE-2025-41712): Incorrect Permission Assignment on the device

An unauthenticated remote attacker who tricks a user to upload a manipulated HTML file can get access to sensitive information on the device. This is a result of incorrect permission assignment for the web server. This vulnerability has a CVSSv3.1 Base Score of [6.5](https://www.first.org/cvss/calculator/3-1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N) and is rated MEDIUM.

### References

- [VDE-2025-079: Janitza: Multiple vulnerabilities in UMG 96RM-E](https://certvde.com/en/advisories/VDE-2025-079)
- [CVE-2025-41709](https://www.cve.org/CVERecord?id=CVE-2025-41709)
- [CVE-2025-41710](https://www.cve.org/CVERecord?id=CVE-2025-41710)
- [CVE-2025-41711](https://www.cve.org/CVERecord?id=CVE-2025-41711)
- [CVE-2025-41712](https://www.cve.org/CVERecord?id=CVE-2025-41712)
- [Vendor Security Advisory in CSAF format](https://janitza.csaf-tp.certvde.com/.well-known/csaf/white/2025/vde-2025-079.json)

### Credits

* Pascal Dengler (<pascal.dengler@telekom.de>)
* Jan Stohner (<jan.stohner@telekom.de>)