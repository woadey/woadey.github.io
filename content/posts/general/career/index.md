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
- Data is sent from source to destination
- Data integrity is ensured using ackowledgements and retransmissions
- Data is transfered in an order
- Checksums are used to verify the integrity of data transmitted
- Flow control: ensures the sender is not overwhelming the receiver

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

**What is an Open Redirect (Vulnerability)?**

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
