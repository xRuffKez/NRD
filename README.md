# NRD Lists

This repository contains NRD (Newly Registered Domains) lists for various adblockers and DNS filtering solutions. The lists are provided in multiple formats to support different tools and applications. These lists help enhance privacy and reduce unwanted traffic by blocking newly registered domains that are often associated with advertisements, trackers, and other unwanted content.
It also prevents new threats, because NRD are favored by black hats.
Learn more [here](https://unit42.paloaltonetworks.com/newly-registered-domains-malicious-abuse-by-bad-actors/)

## Available Lists

### 14-Day List
- Contains domains registered over the past 14 days.
- Available in the following formats:
  - Adblock format: Pi-hole, ~AdGuard~ (too big!), AdGuard Home, eBlocker, uBlock, AdBlock, AdBlock Plus, Opera, Vivaldi, Brave, AdNauseam.
  - Plain domain format: DNSCloak, DNSCrypt, TechnitiumDNS, PersonalDNSfilter, InviZible Pro.
  - Asterisk format: Blocky (v0.23 or newer), Nebulo, NetDuma, OPNsense, YogaDNS.

### 30-Day List
- Contains domains registered over the past 30 days, split into two parts for easier handling.
- Available in the following formats:
  - Adblock format: Pi-hole, ~AdGuard~ (too big!), AdGuard Home, eBlocker, uBlock, AdBlock, AdBlock Plus, Opera, Vivaldi, Brave, AdNauseam.
  - Plain domain format: DNSCloak, DNSCrypt, TechnitiumDNS, PersonalDNSfilter, InviZible Pro.
  - Asterisk format: Blocky (v0.23 or newer), Nebulo, NetDuma, OPNsense, YogaDNS.

## List Formats

### Adblock Format
Suitable for:
- Pi-hole
- ~AdGuard~ (too big!)
- AdGuard Home
- eBlocker
- uBlock
- AdBlock
- AdBlock Plus
- Opera
- Vivaldi
- Brave
- AdNauseam

### Plain Domain Format
Suitable for:
- DNSCloak
- DNSCrypt
- TechnitiumDNS
- PersonalDNSfilter
- InviZible Pro

### Asterisk Format
Suitable for:
- Blocky (v0.23 or newer)
- Nebulo
- NetDuma
- OPNsense
- YogaDNS

## Usage Instructions

### Pi-hole
1. Go to your Pi-hole admin panel.
2. Navigate to **Group Management** > **Adlists**.
3. Add the URL of the desired list.

### AdGuard Home
1. Open the AdGuard Home admin interface.
2. Go to **Filters** > **DNS blocklists**.
3. Add the URL of the desired list.

### eBlocker, uBlock, AdBlock, AdBlock Plus, Opera, Vivaldi, Brave, AdNauseam
1. Open the settings or extensions page.
2. Add the URL of the desired list to the custom filters section.

### DNSCloak, DNSCrypt, TechnitiumDNS, PersonalDNSfilter, InviZible Pro
1. Open the settings.
2. Import the plain domain format list.

### Blocky (v0.23 or newer), Nebulo, NetDuma, OPNsense, YogaDNS
1. Open the settings.
2. Import the asterisk format list.

## Reminder
Please note that false positives may occur. These lists are purely complete NRD lists, and no domains will be whitelisted.

## Recommended Additional Blocklists

For enhanced blocking capabilities, consider using the following DNS blocklists from Hagezi:
- Hagezi DNS blocklists provide comprehensive protection against various threats, including ads, trackers, and malware.
- [Hagezi DNS Blocklists](https://github.com/hagezi/dns-blocklists)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE.md) file for details.
