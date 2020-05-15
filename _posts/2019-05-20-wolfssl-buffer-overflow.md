---
title: wolfSSL TLSv1.3 Remote Buffer Overflow
description: Advisory for wolfSSL TLSv1.3 PSK extension parsing buffer overflow
header: wolfSSL TLSv1.3 Remote Buffer Overflow
---
A new critical remote buffer overflow vulnerability (CVE-2019-11873) was discovered in the wolfSSL library (version 4.0.0-stable, http://www.wolfssl.com) by Security Evaluators of Telekom Security with modern fuzzing methods. The vulnerability allows an attacker to overwrite a large part of the RAM of a wolfSSL server with hisdata over the network.

[View the full advisory](/assets/advisories/20190520_remote-buffer-overflow-wolfssl_CVE-2019-11873.pdf)
