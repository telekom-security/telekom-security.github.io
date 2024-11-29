---
title: Tuta Mail Vulnerability - DoS  
header: Tuta Mail Vulnerability - DoS
tags: ['advisories']  
cwes: ['Improper Input Validation (CWE-20)']  
affected_product: 'Tuta Mail'  
vulnerability_release_date: '2024-01-25'  
---

A denial of service vulnerability (CVE-2024-23655) has been identified in Tuta Mail. This vulnerability could prevent users from accessing and reading received mails when an attacker sends a manipulated mail.<!--more-->

### Details

* **Product:** Tuta Mail
* **Affected Version:** Tuta Mail >=3.118.12, < 3.119.10
* **Vulnerability Type:** Improper Input Validation (CWE-20)
* **Risk Level:** High
* **Vendor URL:** https://tuta.com/
* **Vendor acknowledged vulnerability:** Yes
* **Vendor Status:** Fixed
* **CVE:** CVE-2024-23655

The vulnerability was discovered during testing of Tutanota for iOS. By sending a manipulated email, an attacker could put the app into an unusable state. In this case, a user can no longer access received e-mails. Since the vulnerability affects not only the app, but also the web application, a user in this case has no way to access received emails.

### References
- [CVE-2024-23655](https://nvd.nist.gov/vuln/detail/CVE-2024-23655)
- [Tuta Mail Advisory](https://github.com/tutao/tutanota/security/advisories/GHSA-5h47-g927-629g)

### Timeline

* **2024-01-25:** Vendor has reported that the vulnerability has been fixed.
* **2024-11-29:** This blog post was published.

### Credits

* Tom Peine (<Tom.Peine@telekom.de>)