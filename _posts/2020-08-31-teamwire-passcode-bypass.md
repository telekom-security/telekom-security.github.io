---
title: Teamwire Pass Code Bypass
description: Advisory for Teamwire (Android) < version 5.4.3
header: Teamwire Pass Code Bypass
tags: ['advisories']
cwes: ['Missing Authentication for Critical Function (CWE-306)']
affected_product: 'Teamwire (Android)'
vulnerability_release_date: '2020-06-10'
---
A pass code bypass in the mobile application of Teamwire for Android allows an attacker with physical access to the phone to use the app without entering the valid pass code. 
<!--more-->

[View the full advisory](/assets/advisories/20200831_Teamwire_Pass_Code_Bypass.txt)
~~~
                                           Telekom Security
                                         security.telekom.com

                                   Advisory: Teamwire Pass Code Bypass
                               Release Date: 2020/08/31
                                     Author: Bastian Recktenwald (Bastian.Recktenwald@telekom.de)
                                        CVE: CVE-2020-12621

                                Application: Teamwire (Android App)
                                       Risk: Medium 

Overview:

  Teamwire is a secure messenger for companies, authorities and healtcare. The complete description 
  of the app could be found in the official app store: 
  https://play.google.com/store/apps/details?id=com.teamwire.messenger 
  During a penetration test of the mobile application Teamwire for Android, a vulnerability 
  could be identified. To exploit the vulnerability in a sensible way, an attack must have physical 
  access to the mobile phone. The vulnerability was fixed with version 5.4.3.

Details:

  The App can be additionally protected with a pass code to improve the access security of the app. 
  The found vulnerability allows an attacker to bypass the pass code protection mechanism. In order to 
  exploit the vulnerability, an attacker can bypass the pass code by starting the exposed 
  activity “LoadingActivity“. Afterwards the app could be used without any restrictions.
  For example, new messages could be written or existing messages could be read. 

Disclosure Timeline:

  30. April  2020 - Notified vendor
  11. Mai    2020 - Vulnerability was fixed
  10. Juni   2020 - Release of version 5.4.3


About Telekom Security:

  Telekom Security is the security provider for Deutsche Telekom and Deutsche Telekom customers.
    https://security.telekom.com
    https://telekomsecurity.github.io
    https://www.sicherheitstacho.eu
~~~
