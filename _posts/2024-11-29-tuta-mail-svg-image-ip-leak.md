---
title: Tuta Mail Vulnerability - Client Information Leak
header: Tuta Mail Vulnerability - Client Information Leak
tags: ['advisories']  
cwes: ['Server-Side Request Forgery (SSRF) (CWE-918)']  
affected_product: 'Tuta Mail'  
vulnerability_release_date: '2024-01-22' 
---

An client information leak vulnerability (CVE-2024-23330) has been identified in Tuta Mail. This vulnerability could leak client information by loading external resources in the mail even if disabled.<!--more-->

### Details

* **Product:** Tuta Mail
* **Affected Version:** Tuta Mail < 3.119.10
* **Vulnerability Type:** Server-Side Request Forgery (SSRF) (CWE-918)
* **Risk Level:** Medium
* **Vendor URL:** https://tuta.com/
* **Vendor acknowledged vulnerability:** Yes
* **Vendor Status:** Fixed
* **CVE:** CVE-2024-23330

The vulnerability was discovered during testing of Tutanota for iOS. By sending a html email with an embeded svg image, an attacker could receive the information when the email was read, which device is used and the user's ip address.

### References
- [CVE-2024-23330](https://nvd.nist.gov/vuln/detail/CVE-2024-23330)
- [Tuta Mail Advisory](https://github.com/tutao/tutanota/security/advisories/GHSA-32w8-v5fc-vpp7)

### Timeline

* **2024-01-22:** Vendor has reported that the vulnerability has been fixed.
* **2024-11-29:** This blog post was published.

### Credits

* Tom Peine (<Tom.Peine@telekom.de>)