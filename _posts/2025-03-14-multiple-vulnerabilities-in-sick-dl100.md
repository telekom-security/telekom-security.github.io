---
title: Multiple critical vulnerabilities in SICK DL100-2xxxxxxx Products
header:  Multiple critical vulnerabilities in SICK DL100-2xxxxxxx Products
tags: ['advisories']
cwes: ['CWE-494 (Download of Code Without Integrity Check)', 'CWE-319 (Cleartext Transmission of Sensitive Information)', 'CWE-328 (Use of Weak Hash)']
affected_product: 'SICK DL100-2xxxxxxx all firmware versions'
vulnerability_release_date: '2025-03-14'
---

Several vulnerabilities were discovered during testing of a DL100 device.<!--more-->

### Details

* **Product:** SICK DL100-2xxxxxxx
* **Affected Version:** all firmware versions
* **Vulnerability Type:** Download of Code Without Integrity Check (CWE-494), Cleartext Transmission of Sensitive Information (CWE-319) and Use of Weak Hash (CWE-328)
* **Risk Level:** Critical
* **Vendor URL:** https://www.sick.com/de/de/
* **Vendor acknowledged vulnerability:** Yes
* **Vendor Status:** Known Affected / Workaround
* **CVEs:** CVE-2025-27593, CVE-2025-27594, CVE-2025-27595

The vulnerabilities were discovered during testing a device of type DL100.

### [CVE-2025-27593](https://www.cve.org/CVERecord?id=CVE-2025-27593): Download of Code Without Integrity Check

The product can be used to distribute malicious code using SDD Device Drivers
due to missing download verification checks leading to code execution on target systems.

### [CVE-2025-27594](https://www.cve.org/CVERecord?id=CVE-2025-27594): Cleartext Transmission of Sensitive Information

The device uses an unencrypted, proprietary protocol for communication, authentication and transmission of configuration data. An attacker can thereby intercept the authentication hash and use it to log into the device using a pass-the-hash attack.

### [CVE-2025-27595](https://www.cve.org/CVERecord?id=CVE-2025-27595): Use of Weak Hash

The device uses a weak hashing alghorithm to create the password hash. Hence, a matching password can be easily calculated by an attacker. This impacts the security and the integrity of the device.

### References

- [CVE-2025-27593](https://www.cve.org/CVERecord?id=CVE-2025-27593)
- [CVE-2025-27594](https://www.cve.org/CVERecord?id=CVE-2025-27594)
- [CVE-2025-27595](https://www.cve.org/CVERecord?id=CVE-2025-27595)
- [SICK Security Advisory](https://www.sick.com/.well-known/csaf/white/2025/sca-2025-0004.pdf)

### Timeline

* **07.01.2025:** Vulnerability reported to the vendor.
* **31.01.2025:** Vendor confirmed vulnerabilities.
* **14.03.2025:** Vendor published a Security Advisory with a workaround.
* **14.03.2025:** This blog post was published.

### Credits

* Leonard Lewedei (<leonard.lewedei@telekom.de>)