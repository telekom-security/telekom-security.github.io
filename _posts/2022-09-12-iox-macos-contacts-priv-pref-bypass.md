---
title: Apple's iOS & macOS Contacts Vulnerability - Privacy Preferences Bypass
header: Apple's iOS & macOS Contacts Vulnerability - Privacy Preferences Bypass
tags: ['advisories']
cwes: ['Improper Input Validation (CWE-20)']
affected_product: 'Apple iOS/iPadOS, macOS'
vulnerability_release_date: '2022-09-12'
---

A vulnerability has been identified in iOS/iPadOS < 15.7 / < 16.0 and macOS Big Sur < 11.7 that allows an app to bypass Privacy preferences, posing a significant risk. The vulnerability, classified as Improper Input Validation affects the Contacts component. <!--more-->Users are strongly encouraged to update their devices to the latest version to protect their data.

### Details

* **Product:** Apple iOS/iPadOS, macOS
* **Affected Version:**  iOS/iPadOS < 15.7 / < 16.0, macOS Big Sur < 11.7
* **Vulnerability Type:** Improper Input Validation (CWE-20)
* **Risk Level:** Medium
* **Vendor URL:** https://www.apple.com
* **Vendor acknowledged vulnerability:** Yes
* **Vendor Status:** Fixed
* **CVE:** CVE-2022-32854

The vulnerability exists because the `CNContactPickerViewController` class allows the selection of contacts without prompting the user for access permissions. By exploiting a specific predicate (`predicateForEnablingContact`) with a custom selector, it is possible to inject Objective-C method calls into a internal service component. This can lead to serious breaches, such as a malicious app accessing sensitive data without user consent.

### Exploitation

The vulnerability was demonstrated using two exploits:

1. **Control Program Flow**:
    - By calling `indexOfObjectPassingTest:` on an NSArray object with an NSData object as a parameter, a type confusion occurs. The NSData object is used as a block, where its content is treated as a function pointer. This exploit can access various data such as Calendar, Contacts, Photos, and Camera.

2. **Send Conditional HTTP Requests**:
    - By calling `initWithContentsOfURL:` on an NSData object, the app can send HTTP requests. This can extract contact data from a local app using HTTP requests as a feedback mechanism.

### Impact

Exploitation of this vulnerability by an attacker could have serious privacy implications. Accessing Calendar, Contacts, Photos, and Camera data without user consent can lead to data leakage and unauthorized data manipulation.

### References

- [https://support.apple.com/en-us/102838](https://support.apple.com/en-us/102838)
- [NVD - CVE-2022-32854](https://nvd.nist.gov/vuln/detail/CVE-2022-32854)
- [https://developer.apple.com/documentation/contactsui/cncontactpickerviewcontroller](https://developer.apple.com/documentation/contactsui/cncontactpickerviewcontroller)

### Timeline

* **Mid 2022:** Vulnerability reported to the vendor.
* **2022-09-12:** Vendor has fixed the vulnerability.
* **2024-06-26:** This blog post was published.

### Credits

* Holger Fuhrmannek ([holger.fuhrmannek@telekom.de](mailto:holger.fuhrmannek@telekom.de))