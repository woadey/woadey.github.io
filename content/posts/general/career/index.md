---
title: "Offensive Security: Interview Prep"
slug: "interviews"
date: 2024-04-12T19:05:07-04:00
draft: false
summary: "Red Team & Pentest Job Interview Preparation"
description: "Red Team & Pentest Job Interview Preparation"
categories: ["general"]
tags: []
keywords: []
---

_I have been exploring transitioning to a more technical and hands on role in the Offensive Security field (broad, I know). This naturally requires some interviews. Rather than keeping this to my self, I figured I would publish my review and document my efforts._

_Some of this is a review of basic concepts that I am already familiar with, but there are also areas within the fundamentals that I have missed or just haven't learned about to the full depth._

**Note: this is more for me than anything else - a majority of this content is catering towards Red Team and Pentesting roles that I have been looking at, but obviously certain topics can be applied to other jobs you maybe looking for.**

## Major Topics

### Hacker Types (Hats)

- Black: malicious
- White: ethical
- Grey: not malicious, not ethical
- Green: new, unskilled
- Blue: vengeful
- Red: vigilante

### (A Few) Hacker Roles

#### Pentetration tester

- Goal: find vulnerabilities in specified time and subset of assests
- Scope: scoped to system or applications
- Timeline: a few days to a few weeks
- Types:
  - Internal: Identify vulnerabilities in an organization's systems
  - External: Identify vulnerabilities that could be exploited from the outside
- Cost: generally cheaper than red team due to less time spent

#### Red teamer

- Goal: test the effectiveness of an organizations defensive strategies
- Scope: specific objective (exfiltrate financial information)
- Timeline: 3-4 weeks or longer
- Types:
  - Internal: focus on the internal network and systems
  - External: focus on the exteral attack surface
  - Hybrid: A combination of the two
- Cost: generally pricey in comparison to pentest due to time

### [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)

- [A01:2021-Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) moves up from the fifth position; 94% of applications were tested for some form of broken access control. The 34 Common Weakness Enumerations (CWEs) mapped to Broken Access Control had more occurrences in applications than any other category.
- [A02:2021-Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) shifts up one position to #2, previously known as Sensitive Data Exposure, which was broad symptom rather than a root cause. The renewed focus here is on failures related to cryptography which often leads to sensitive data exposure or system compromise.
- [A03:2021-Injection](https://owasp.org/Top10/A03_2021-Injection/) slides down to the third position. 94% of the applications were tested for some form of injection, and the 33 CWEs mapped into this category have the second most occurrences in applications. Cross-site Scripting is now part of this category in this edition.
- [A04:2021-Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/) is a new category for 2021, with a focus on risks related to design flaws. If we genuinely want to “move left” as an industry, it calls for more use of threat modeling, secure design patterns and principles, and reference architectures.
- [A05:2021-Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) moves up from #6 in the previous edition; 90% of applications were tested for some form of misconfiguration. With more shifts into highly configurable software, it’s not surprising to see this category move up. The former category for XML External Entities (XXE) is now part of this category.
- [A06:2021-Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) was previously titled Using Components with Known Vulnerabilities and is #2 in the Top 10 community survey, but also had enough data to make the Top 10 via data analysis. This category moves up from #9 in 2017 and is a known issue that we struggle to test and assess risk. It is the only category not to have any Common Vulnerability and Exposures (CVEs) mapped to the included CWEs, so a default exploit and impact weights of 5.0 are factored into their scores.
- [A07:2021-Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) was previously Broken Authentication and is sliding down from the second position, and now includes CWEs that are more related to identification failures. This category is still an integral part of the Top 10, but the increased availability of standardized frameworks seems to be helping.
- [A08:2021-Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) is a new category for 2021, focusing on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. One of the highest weighted impacts from Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) data mapped to the 10 CWEs in this category. Insecure Deserialization from 2017 is now a part of this larger category.
- [A09:2021-Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) was previously Insufficient Logging & Monitoring and is added from the industry survey (#3), moving up from #10 previously. This category is expanded to include more types of failures, is challenging to test for, and isn’t well represented in the CVE/CVSS data. However, failures in this category can directly impact visibility, incident alerting, and forensics.
- [A10:2021-Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) is added from the Top 10 community survey (#1). The data shows a relatively low incidence rate with above average testing coverage, along with above-average ratings for Exploit and Impact potential. This category represents the scenario where the security community members are telling us this is important, even though it’s not illustrated in the data at this time.

### OSI Model

- Application
- Presentation
- Session
- Transport
- Network
- Data Link
- Physical

### TCP/IP Model

- Application
  - OSI Equivalent: Application + Presentation + Sesssion
- Transport
  - OSI Equivalent: Transport
- Network
  - OSI Equivalent: Network
- Network Interface
  - OSI Equivalent: Data Link + Physical

### Application Layer

### Presentation Layer

### Session Layer

### Transport Layer

#### Transmission Control Protocol (TCP)

- Connection oriented protocol: establishes a connection between sender and receiver befre transfer
  - 3-way handshake: SYN, SYN-ACK, ACK stays in effect until timeout or reset by client or server
- Data is sent from source to destination
- Data integrity is ensured using ackowledgements and retransmissions
- Data is transfered in an order
- Checksums are used to verify the integrity of data transmitted
- Flow control: ensures data is sent at the most efficient rate from sender to receiver
- Congestion control: uses mechanisms and algorithms to achieve a high flow rate of data and avoid congestion

![TCP Header](images/tcp-header.i.jpg#center "[[_image source_](https://www.lifewire.com/tcp-headers-and-udp-headers-explained-817970) ]")

#### User Datagram Protocol (UDP)

- Connectionlesss communication protocol
- Only cares about sending the segments

### Network Layer

### Data Link Layer

### Physical Layer

---

## Common Questions

### Random

**What is Kerberoasting?**

- Targets Service Principal Name accounts, specifically the NTLM hash which is used to encrypt TGS-REP
- All thats needed is cleartext password or NTLM hash of user, shell in context of domain user account, or SYSTEM level access on a domain-joined host

### YT:Hacksplained "[Pentest Interview Questions](https://www.youtube.com/watch?v=cR-Dj6eueiY)"

#### General Questions

**What is the last pentest tool you used, improved, suite?**

**Where do you find new vulnerability research?**

**Who is your hacking idol?**

**What is your latest writeup?**

**Where do you have room to improve in?**

#### Junior Level

**What is XSS?**

**What is SQL Injection?**
When an attacker is able to insert a malicious SQL payload within a website field in order to interact with the SQL database. This is due to improper (or lack there of) sanatization of client-side input. Often times this involves having a query that will always be true, such as `1=1 --`. [HackTricks](https://book.hacktricks.xyz/pentesting-web/sql-injection) has quite a few paylaods and descriptions to help.

**What is an Open Redirect (Vulnerability)?**
Open redirects are when a web application allows users to redirect/forward to another URL. Open redirect vulnerabilites can lead to phishing attacks, XSS attacks, SSRF attacks, CSP bypassing, etc.

**Which cookie security flags exist?**

**Difference between Pentest / Vulnerability test?**

**Difference between Black/White/Gray box?**

**What pentest types/techniques exist?**

**Which file upload restrictions are common in web applications?**

#### Senior Level

**Content of a good pentest report?**

**How do you detect a CSRF attack?**

**How does XXE payload work?**

**What is a boolean blind SQLi?**

**Explain different HTTP methods, what they are used for, and how to be exploited?**

**What is a salt?**
**Difference between attack web app and api?**

**Last found business logic vulnerability?**

#### Principal Level

**What is a threat model and how can this be useful?**

**Benefits of bug bounty vs pentest?**

**How to measure pentest results?**

**Explain details of HTTP DSync attack**

**How does deserialization work?**

**What are common auth standards and how can you attack them?**

**Can SSTI lead to RCE?**

**What was your last RCE vulnerability?**
