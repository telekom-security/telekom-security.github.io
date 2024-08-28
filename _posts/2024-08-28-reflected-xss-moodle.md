---
title: Moodle - Reflected XSS Vulnerability via H5P error message
header: Moodle - Reflected XSS Vulnerability via H5P error message
tags: ['advisories']
cwes: ['Cross-site Scripting (CWE-79)']
affected_product: 'Moodle'
vulnerability_release_date: '2024-08-19'
---

A reflected cross-site scripting (XSS) vulnerability (CVE-2024-43439) has been identified in Moodle, allowing an attacker to execute arbitrary JavaScript within the context of a Moodle website when a victim visits a specially crafted link.<!--more-->

### Details

* **Product:** Moodle
* **Affected Version:** 4.4 to 4.4.1, 4.3 to 4.3.5, 4.2 to 4.2.8, 4.1 to 4.1.11, and earlier unsupported versions
* **Vulnerability Type:** Cross-site Scripting (CWE-79)
* **Risk Level:** High
* **Vendor URL:** https://moodle.org/
* **Vendor acknowledged vulnerability:** Yes
* **Vendor Status:** Fixed
* **CVE:** CVE-2024-43439

The vulnerability was discovered during a penetration test of a Moodle-based website. The attack is possible when a teacher, who could also be the victim, uploads an H5P file to a course. While the H5P file itself does not contain malicious content, an attacker (such as a malicious student) can obtain and modify the link associated with this file. By replacing part of the link with double URL-encoded JavaScript code, the attacker can create a link that, when viewed by the victim, triggers execution of the embedded JavaScript code. This is possible because an error message related to H5P files is not properly sanitized before it is displayed.

### Impact

An attacker could execute arbitrary JavaScript code within the victim's Moodle session, which could lead to actions such as session hijacking or unauthorized data access.

### Remediation

It is recommended to upgrade to the latest version of Moodle to fix this vulnerability.

### References
- [Moodle Advisory](https://moodle.org/mod/forum/discuss.php?d=461209#p1851881)
- [CVE-2024-43439](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43439)

### Timeline

* **2024-07-03:** Vulnerability reported to the vendor.
* **2024-08-19:** Vendor has reported that the vulnerability has been fixed.
* **2024-08-28:** This blog post was published.

### Credits

* Holger Fuhrmannek (<holger.fuhrmannek@telekom.de>)