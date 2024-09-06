---
title: Collabora Office for Android - JavaScript Injection via Links
header: Collabora Office for Android - JavaScript Injection via Links
tags: ['advisories']
cwes: ['Improper Neutralization of Encoded URI Schemes in a Web Page (CWE-84)']
affected_product: 'Collabora Office for Android'
vulnerability_release_date: '2024-08-29'
---

A JavaScript Injection vulnerability (CVE-2024-45045) has been identified in Collabora Office for Android, allowing an attacker to execute arbitrary JavaScript within the context of the Android App when a victim opens a specially crafted document.<!--more-->

### Details

* **Product:** Collabora Office for Android
* **Affected Version:** < 24.04.6.2
* **Vulnerability Type:** Improper Neutralization of Encoded URI Schemes in a Web Page (CWE-84)
* **Risk Level:** Medium
* **Vendor URL:** https://www.collaboraonline.com/collabora-office-android-ios/
* **Vendor acknowledged vulnerability:** Yes
* **Vendor Status:** Fixed
* **CVE:** CVE-2024-45045

The vulnerability was discovered during testing of Collabora Office for Android. In affected versions of the app, it is possible to inject JavaScript via a document with a specially crafted link using URL-encoded values. For instance, a link with the target `"http://www.google.de/%22%27%2b%61%6c%65%72%74%28%31%29%2b%27"` triggers the execution of the JavaScript code `"alert(1)"` when the link is activated. Since it is possible for a link to be automatically activated when a document is opened, the vulnerability could be triggered after a victim opens a document without any further user interaction.

### Impact

Since the Android JavaScript interface allows access to internal functions, the likelihood that the app could be compromised via this vulnerability is considered high.

### Remediation

It is recommended to upgrade to the latest version of Collabora Office for Android to fix this vulnerability.

### References
- [Collabora Advisory](https://github.com/CollaboraOnline/online/security/advisories/GHSA-78cg-rg4q-26qv)
- [Collabora Office - Play Store](https://play.google.com/store/apps/details?id=com.collabora.libreoffice)

### Timeline

* **2024-03-18:** Vulnerability reported to the vendor.
* **2024-08-29:** Vendor has reported that the vulnerability has been fixed.
* **2024-09-06:** This blog post was published.

### Credits

* Holger Fuhrmannek (<holger.fuhrmannek@telekom.de>)