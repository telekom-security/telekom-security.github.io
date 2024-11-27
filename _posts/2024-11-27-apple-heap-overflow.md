---
title: Security Content for iOS, iPadOS, and macOS  
header: Apple ARKit Vulnerability - Heap Overflow
tags: ['advisories']  
cwes: ['Out-of-bounds Write (CWE-787)']  
affected_product: 'Apple iOS/iPadOS, macOS and more'  
vulnerability_release_date: '2024-09-16'  
---

A heap corruption vulnerability (CVE-2024-44126) has been identified in several Apple products that use the ARKit component. This vulnerability could compromise the security of devices when processing a specially crafted file. <!--more-->

### Details

* **Product:** Apple Software
* **Affected Version:** macOS Ventura < 13.7.1, iOS < 17.7, iPadOS < 17.7, macOS Sonoma < 14.7
* **Vulnerability Type:** Out-of-bounds Write (CWE-787)
* **Risk Level:** High
* **Vendor URL:** https://support.apple.com
* **Vendor acknowledged vulnerability:** Yes
* **Vendor Status:** Fixed
* **CVE:** CVE-2024-44126

This vulnerability has the potential to lead to data exfiltration and system instability, posing a risk to users of iOS and macOS devices. It is recommended that users ensure they have the latest software versions installed to mitigate this vulnerability.

### References
- [CVE-2024-44126](https://nvd.nist.gov/vuln/detail/CVE-2024-44126)
- [Apple Support - Update 1](https://support.apple.com/en-us/121238)
- [Apple Support - Update 2](https://support.apple.com/en-us/121246)
- [Apple Support - Update 3](https://support.apple.com/en-us/121247)
- [Apple Support - Update 4](https://support.apple.com/en-us/121249)
- [Apple Support - Update 5](https://support.apple.com/en-us/121250)
- [Apple Support - Update 6](https://support.apple.com/en-us/121568)

### Timeline

* **2024-09-16:** Vendor has fixed the vulnerability.
* **2024-10-28:** Vendor has reported that the vulnerability has been fixed.
* **2024-11-27:** This blog post was published.

### Credits

* Holger Fuhrmannek (<holger.fuhrmannek@telekom.de>)