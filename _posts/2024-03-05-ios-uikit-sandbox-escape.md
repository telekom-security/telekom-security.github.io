---
title: Apple's UIKit Vulnerability - Sandbox Escape
header: Apple's UIKit Vulnerability - Sandbox Escape
tags: ['advisories']
cwes: ['Improper Input Validation (CWE-20)']
affected_product: 'Apple iOS/iPadOS, macOS and more'
vulnerability_release_date: '2024-03-05'
---

A vulnerability has been identified in various Apple devices, including iPhones, posing a significant risk. The vulnerability affects the UIKit component. <!--more-->Users are strongly encouraged to update their devices to the latest version to protect their data.

### Details

* **Product:** Various Apple Systems
* **Affected Version:** iOS/iPadOS < 17.4, iOS/iPadOS < 16.7.6, macOS Sonoma < 14.4, visionOS < 1.1, watchOS < 10.4, tvOS < 17.4
* **Vulnerability Type:** Improper Input Validation (CWE-20)
* **Risk Level:** Medium
* **Vendor URL:** https://www.apple.com
* **Vendor acknowledged vulnerability:** Yes
* **Vendor Status:** Fixed
* **CVE:** CVE-2024-23246

The vulnerability exists because the UIKit component contains code that, if exploited, can allow an application to escape its sandbox.

### Impact

Exploitation of this vulnerability by an attacker could have serious security implications. Breaking out of the sandbox could allow a malicious app to access sensitive data and potentially control other parts of the system, compromising the overall security of the device.

### References

- [https://support.apple.com/en-us/HT214081](https://support.apple.com/en-us/HT214081)
- [NVD - CVE-2024-23246](https://nvd.nist.gov/vuln/detail/CVE-2024-23246)

### Credits

* Holger Fuhrmannek ([holger.fuhrmannek@telekom.de](mailto:holger.fuhrmannek@telekom.de))