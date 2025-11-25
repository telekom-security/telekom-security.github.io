---
title: Security Content for REDAXO
header: REDAXO Mediapool Reflected Cross-Site Scripting
tags: ['advisories']
cwes: ['Improper Neutralization of Input During Web Page Generation (CWE-79)']
affected_product: 'REDAXO CMS'
vulnerability_release_date: '2025-11-25'
---

A reflected Cross-Site Scripting vulnerability (CVE-2025-66026) has been identified in the REDAXO Mediapool component. The issue allows arbitrary JavaScript execution in the backend when a user visits a specially crafted link while authenticated. <!--more-->

### Details

* **Product:** REDAXO CMS
* **Affected Version:** <= 5.20.0
* **Fixed Version:** 5.20.1
* **Vulnerability Type:** Reflected Cross-Site Scripting (CWE-79)
* **Risk Level:** Moderate
* **Vendor URL:** https://redaxo.org/
* **Vendor acknowledged vulnerability:** Yes
* **Vendor Status:** Fixed
* **CVE:** CVE-2025-66026

### Technical Summary

In the Mediapool view, the request parameter `args[types]` is injected into an information banner without proper HTML escaping.

### Impact

This vulnerability enables JavaScript execution in the backend context of an authenticated user, potentially allowing session hijacking and unauthorized administrative actions.

### References
- [Github Advisory](https://github.com/redaxo/redaxo/security/advisories/GHSA-x6vr-q3vf-vqgq)

### Timeline

* **2025-11-11:** Vulnerability reported to the vendor via GitHub.
* **2025-11-25:** The vendor has published the GitHub advisory and released the fixed version.
* **2025-11-25:** This blog post was published.

### Credits

* Holger Fuhrmannek (<holger.fuhrmannek@telekom.de>)