---
title: Apple's macOS Quick Look Vulnerability - Buffer Overflow
header: Apple's macOS Quick Look Vulnerability - Buffer Overflow
tags: ['advisories']
cwes: ['Buffer Copy without Checking Size of Input (CWE-120)']
affected_product: 'Apple iOS/iPadOS, macOS and more'
vulnerability_release_date: '2023-06-23'
---

A  vulnerability has been identified in Apple's Quick Look feature that affects Apple's macOS. The vulnerability, classified as a classic buffer overflow, was addressed with improved bounds checking. <!--more-->Users are strongly encouraged to update their devices to the latest version to protect their data.

### Details

* **Product:** macOS
* **Affected Version:** macOS < 12.6.6, macOS < 11.7.7, macOS < 13.4
* **Vulnerability Type:** Buffer Copy without Checking Size of Input (CWE-120)
* **Risk Level:** High
* **Vendor URL:** https://www.apple.com
* **Vendor acknowledged vulnerability:** Yes
* **Vendor Status:** Fixed
* **CVE:** CVE-2023-32401

The vulnerability exists due to improper bounds checking when parsing an office document in Quick Look.

### Exploitation

The vulnerability can be exploited by crafting a malicious office document that triggers the buffer overflow when parsed by the Quick Look component. This could allow an attacker to execute arbitrary code on the affected device, leading to a potential compromise of the system.

### Impact

Exploitation of this vulnerability by an attacker could have serious security implications. Arbitrary code execution could allow the attacker to take control of the affected system, access sensitive information, and perform unauthorized actions.

### References

- [https://support.apple.com/en-us/HT213758](https://support.apple.com/en-us/HT213758)
- [NVD - CVE-2023-32401](https://nvd.nist.gov/vuln/detail/CVE-2023-32401)
- [https://developer.apple.com/documentation/quicklook](https://developer.apple.com/documentation/quicklook)

### Timeline

* **2022**:  Vulnerability reported to the vendor.
* **2023-05-18:** Vendor has fixed the vulnerability.
* **2023-12-21:** Vendor has reported that the vulnerability has been fixed.
* **2024-06-26:** This blog post was published.

### Credits

* Holger Fuhrmannek ([holger.fuhrmannek@telekom.de](mailto:holger.fuhrmannek@telekom.de))