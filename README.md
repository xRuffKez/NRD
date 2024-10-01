
# NRD Lists

## Block New Threats Before They Emerge

This repository provides **Newly Registered Domains (NRD)** lists tailored for various ad-blocking and DNS filtering solutions. These lists aim to enhance privacy and security by blocking newly registered domains often used for ads, tracking, and other unwanted activities. NRDs are also a common choice for malicious actors, making these lists an effective tool for threat mitigation.

---

# Next update in

![Countdown](https://img.shields.io/badge/dynamic/json?url=https://your-api.com/countdown&label=Next%20update&query=next_update)

---

## Table of Contents

- [Overview](#overview)
- [Why Use NRD Lists?](#why-use-nrd-lists)
- [How NRDs Are Harvested](#how-nrds-are-harvested)
- [Available Lists](#available-lists)
  - [14-Day List](#14-day-list)
  - [30-Day List](#30-day-list)
- [List Formats](#list-formats)
  - [Adblock Format](#adblock-format)
  - [Plain Domain Format](#plain-domain-format)
  - [Asterisk Format](#asterisk-format)
- [Usage Instructions](#usage-instructions)
  - [Pi-hole](#pi-hole)
  - [AdGuard Home](#adguard-home)
  - [Other Adblockers](#other-adblockers)
  - [DNS Filtering Solutions](#dns-filtering-solutions)
- [False Positives](#false-positives)
- [Recommended Blocklists](#recommended-blocklists)
- [Repository Files](#repository-files)
- [License](#license)

---

## Overview

NRD lists are useful for blocking recently registered domains, many of which are associated with malicious behavior, advertisements, or unwanted tracking. By leveraging these lists, users can enhance their browsing experience and strengthen their security posture.

This repository offers NRD lists in multiple formats to support different adblockers and DNS filtering tools. The lists are updated regularly to ensure comprehensive coverage.

---

## Why Use NRD Lists?

**1. Early Threat Mitigation:**  
Newly registered domains (NRDs) are commonly used by cybercriminals for phishing, malware, and other fraudulent activities. Blocking NRDs helps prevent access to potential threats before they become widespread.

**2. Improved Privacy:**  
NRDs are often used for aggressive tracking and advertising practices. By blocking NRDs, you can reduce exposure to data-harvesting services and improve online privacy.

**3. Reducing Unwanted Traffic:**  
Many ad networks use NRDs to bypass existing blocking lists. Including NRD lists helps to enhance adblocking effectiveness, preventing the display of intrusive ads that originate from newly created domains.

**4. Prevention Against Emerging Risks:**  
Black hats and other threat actors favor NRDs because they are not well-known or blacklisted in traditional security systems. Blocking these domains helps prevent exposure to emerging and unknown threats.

**5. Broad Compatibility:**  
These lists are available in various formats to suit different adblockers and DNS filtering solutions, ensuring that they can be easily integrated into your existing security setup.

---

## How NRDs Are Harvested

The NRD lists are compiled by continuously monitoring domain registration databases, focusing on identifying new domains as they are registered. Here's how the process works:

1. **Domain Registration Tracking:**  
   I gather data from publicly available sources such as WHOIS services and other domain registries. These sources provide information on recently registered domains across various top-level domains (TLDs).

2. **Filtering & Processing:**  
   The raw data is filtered to remove common legitimate domains (such as those used by major tech companies or services), leaving a list of potentially suspicious NRDs.

3. **List Compilation:**  
   After filtering, the domains are categorized into lists based on the registration time period (e.g., 14-day, 30-day) and then converted into formats compatible with popular adblockers and DNS filtering solutions.

4. **Frequent Updates:**  
   The lists are updated regularly to ensure that they remain effective, reflecting newly registered domains that could pose risks.

By leveraging this continuous monitoring and updating process, the lists provide a proactive layer of security against new and emerging threats.

---

## Available Lists

### 14-Day List
- Domains registered within the past **14 days**.
- Available in the following formats:
  - **Adblock format**: Supports Pi-hole, ~~AdGuard~~ (too large), AdGuard Home, uBlock, AdBlock, AdBlock Plus, Opera, Vivaldi, Brave, AdNauseam, eBlocker.
  - **Plain domain format**: For DNSCloak, DNSCrypt, TechnitiumDNS, PersonalDNSfilter, InviZible Pro.
  - **Asterisk format**: For Blocky (v0.23+), Nebulo, NetDuma, OPNsense, YogaDNS.

### 30-Day List
- Domains registered within the past **30 days** (split into two parts for easier handling).
- Available in the following formats:
  - **Adblock format**: Supports Pi-hole, ~~AdGuard~~ (too large), AdGuard Home, uBlock, AdBlock, AdBlock Plus, Opera, Vivaldi, Brave, AdNauseam, eBlocker.
  - **Plain domain format**: For DNSCloak, DNSCrypt, TechnitiumDNS, PersonalDNSfilter, InviZible Pro.
  - **Asterisk format**: For Blocky (v0.23+), Nebulo, NetDuma, OPNsense, YogaDNS.

---

## List Formats

### Adblock Format
**Compatible with:**
- Pi-hole
- ~~AdGuard~~ (too large)
- AdGuard Home
- uBlock
- AdBlock, AdBlock Plus
- Opera
- Vivaldi
- Brave
- AdNauseam
- eBlocker

### Plain Domain Format
**Compatible with:**
- DNSCloak
- DNSCrypt
- TechnitiumDNS
- PersonalDNSfilter
- InviZible Pro

### Asterisk Format
**Compatible with:**
- Blocky (v0.23+)
- Nebulo
- NetDuma
- OPNsense
- YogaDNS

---

## Usage Instructions

### Pi-hole
1. Access the Pi-hole admin panel.
2. Navigate to **Group Management > Adlists**.
3. Add the URL of the desired NRD list.

### AdGuard Home
1. Open the AdGuard Home admin interface.
2. Navigate to **Filters > DNS blocklists**.
3. Add the URL of the desired NRD list.

### Other Adblockers
For **uBlock**, **AdBlock**, **AdBlock Plus**, **Opera**, **Vivaldi**, **Brave**, **AdNauseam**, and **eBlocker**:
1. Open the settings or extensions page.
2. Add the URL of the desired NRD list under custom filters.

### DNS Filtering Solutions
For **DNSCloak**, **DNSCrypt**, **TechnitiumDNS**, **PersonalDNSfilter**, and **InviZible Pro**:
1. Open the application settings.
2. Import the **plain domain format** list.

For **Blocky (v0.23+)**, **Nebulo**, **NetDuma**, **OPNsense**, and **YogaDNS**:
1. Open the application settings.
2. Import the **asterisk format** list.

---

## False Positives

Please note that these lists are **comprehensive NRD lists**, meaning no domains are whitelisted. While this offers broad protection, it may result in false positives. Regular review and customization are recommended based on your specific needs.

---

## Recommended Blocklists

For enhanced protection, I recommend using additional blocklists provided by **Hagezi**. These lists cover a wider range of threats, including ads, trackers, and malware.

Explore Hagezi's blocklists here: [Hagezi DNS Blocklists](https://github.com/Hagezi).

---

## Repository Files

  
- **NRD Lists:**
  - **14-Day NRD Lists:**
    - `nrd-14day.txt`
    - `nrd-14day_adblock.txt`
    - `nrd-14day_wildcard.txt`
  - **30-Day NRD Lists (Split):**
    - `nrd-30day_part1.txt`
    - `nrd-30day_part2.txt`
    - `nrd-30day_adblock_part1.txt`
    - `nrd-30day_adblock_part2.txt`
    - `nrd-30day_wildcard_part1.txt`
    - `nrd-30day_wildcard_part2.txt`
  - **Phishing-Specific NRD Lists:**
    - `nrd-phishing-14day.txt`
    - `nrd-phishing-14day_adblock.txt`
    - `nrd-phishing-14day_wildcard.txt`
    - `nrd-phishing-30day_part1.txt`
    - `nrd-phishing-30day_part2.txt`
    - `nrd-phishing-30day_adblock_part1.txt`
    - `nrd-phishing-30day_adblock_part2.txt`
    - `nrd-phishing-30day_wildcard_part1.txt`
    - `nrd-phishing-30day_wildcard_part2.txt`

---

## License

This project is licensed under the **MIT License**.  
For more information, see the [LICENSE](LICENSE) file.

---
