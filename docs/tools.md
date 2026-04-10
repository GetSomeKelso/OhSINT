# OhSINT Tool Reference

All 43 tools integrated into OhSINT, organized by category. Each entry includes the tool description, source repository, install method, API key requirements, and whether it runs passively or requires authorization.

---

## Tier 1 — CLI-Native, Actively Maintained

| # | Tool | Type | API Key |
|---|------|------|---------|
| 1 | [theHarvester](#theharvester) | Passive | Optional |
| 2 | [SpiderFoot](#spiderfoot) | Active | Optional |
| 3 | [recon-ng](#recon-ng) | Active | Optional |
| 4 | [Metagoofil](#metagoofil) | Passive | None |
| 5 | [Shodan](#shodan) | Passive | **Required** |
| 6 | [ExifTool](#exiftool) | Passive | None |
| 7 | [github-dorks](#github-dorks) | Passive | **Required** |

## LinkedIn / People Recon

| # | Tool | Type | API Key |
|---|------|------|---------|
| 8 | [CrossLinked](#crosslinked) | Passive | None |
| 9 | [InSpy](#inspy) | Passive | Optional |
| 10 | [linkedin2username](#linkedin2username) | Active | **Required** |
| 11 | [Sherlock](#sherlock) | Passive | None |
| 12 | [Maigret](#maigret) | Passive | None |
| 13 | [Holehe](#holehe) | Passive | None |
| 14 | [LinkedInt](#linkedint) | Active | **Required** |

## Passive Infrastructure

| # | Tool | Type | API Key |
|---|------|------|---------|
| 15 | [Subfinder](#subfinder) | Passive | Optional |
| 16 | [crt.sh](#crtsh) | Passive | None |
| 17 | [WHOIS](#whois) | Passive | None |

## Threat Intel & Breach Data

| # | Tool | Type | API Key |
|---|------|------|---------|
| 18 | [VirusTotal](#virustotal) | Passive | **Required** |
| 19 | [h8mail](#h8mail) | Passive | Optional |
| 20 | [waymore](#waymore) | Passive | None |

## Tier 2 — CLI-Compatible

| # | Tool | Type | API Key |
|---|------|------|---------|
| 21 | [Brave Search](#brave-search) | Passive | **Required** |
| 22 | [XRay](#xray) | Active | **Required** |
| 23 | [GooDork](#goodork) | Passive | None |
| 24 | [dork-cli](#dork-cli) | Passive | None |
| 25 | [DataSploit](#datasploit) | Passive | Optional |
| 26 | [Snitch](#snitch) | Passive | None |
| 27 | [VcsMap](#vcsmap) | Passive | None |
| 28 | [Creepy](#creepy) | Passive | None |

## Phone & Identity — Tier 1 (Open API)

| # | Tool | Type | API Key |
|---|------|------|---------|
| 29 | [NumVerify](#numverify) | Passive | **Required** |
| 30 | [Twilio Lookup](#twilio-lookup) | Passive | **Required** |
| 31 | [Censys](#censys) | Passive | **Required** |

## Phone & Identity — Tier 2 (Threat Intel)

| # | Tool | Type | API Key |
|---|------|------|---------|
| 32 | [Intelligence X](#intelligence-x) | Passive | **Required** |
| 33 | [Hudson Rock](#hudson-rock) | Passive | None (free basic) |
| 34 | [SpyCloud](#spycloud) | Passive | **Required** (enterprise) |

## Phone & Identity — Tier 3 (Commercial, FCRA-Gated)

| # | Tool | Type | API Key |
|---|------|------|---------|
| 35 | [Consumer Identity Reference](#consumer-identity-reference) | Passive | None |
| 36 | [Whitepages Pro](#whitepages-pro) | **FCRA** | **Required** |
| 37 | [BeenVerified](#beenverified) | **FCRA** | **Required** |
| 38 | [LexisNexis](#lexisnexis) | **FCRA stub** | Contract |
| 39 | [TLO](#tlo) | **FCRA stub** | Contract |
| 40 | [CLEAR](#clear) | **FCRA stub** | Contract |
| 41 | [Tracers](#tracers) | **FCRA stub** | Contract |
| 42 | [IDI](#idi) | **FCRA stub** | Contract |
| 43 | [SmartMove](#smartmove) | **FCRA stub** | Contract |

---

## Tool Details

### theHarvester

Harvest emails, subdomains, IPs, and employee names from search engines and public data sources.

- **Repo:** [github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)
- **Install:** `sudo apt install theharvester` (Kali)
- **API Keys:** Optional — GitHub, Hunter, IntelX, SecurityTrails improve results
- **Type:** Passive
- **CLI:** `theHarvester -d <domain> -b all -l 500`
- **OhSINT wrapper:** `src/tools/theharvester.py`
- **MCP tool:** `osint_theharvester`
- **Profiles:** passive, infrastructure, people, full

---

### SpiderFoot

Multi-source OSINT automation with 200+ data collection modules.

- **Repo:** [github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot)
- **Install:** `sudo apt install spiderfoot` (Kali)
- **API Keys:** Optional — VirusTotal, Censys, Hunter, IPinfo improve results
- **Type:** Active (some modules probe target infrastructure; use `passive` use_case to restrict)
- **CLI:** `spiderfoot -s <target> -t <types> -u all -o json`
- **OhSINT wrapper:** `src/tools/spiderfoot.py`
- **MCP tool:** `osint_spiderfoot`
- **Profiles:** passive (passive mode), active (all modules), full

---

### recon-ng

Modular web reconnaissance framework (Metasploit-style interface).

- **Repo:** [github.com/lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng)
- **Install:** `sudo apt install recon-ng` (Kali)
- **API Keys:** Optional — Shodan, BuiltWith, GitHub, Google
- **Type:** Active (some modules interact with target)
- **CLI:** Scripted via `recon-ng -r <script.rc>`
- **OhSINT wrapper:** `src/tools/recon_ng.py`
- **MCP tool:** `osint_recon_ng`
- **Profiles:** active, full

---

### Metagoofil

Document metadata harvester — finds and downloads PDF, DOC, XLS files from a domain via search engines, then extracts metadata.

- **Repo:** [github.com/opsdisk/metagoofil](https://github.com/opsdisk/metagoofil)
- **Install:** `git clone https://github.com/opsdisk/metagoofil.git && pip install -r requirements.txt`
- **API Keys:** None
- **Type:** Passive
- **CLI:** `metagoofil -d <domain> -t pdf,doc,xls -l 50 -o <dir>`
- **OhSINT wrapper:** `src/tools/metagoofil.py`
- **MCP tool:** `osint_metagoofil`
- **Profiles:** passive, metadata, full

---

### Shodan

Internet-connected device search engine — queries indexed device data (banners, ports, services, certificates) without touching the target.

- **Repo:** [github.com/achillean/shodan-python](https://github.com/achillean/shodan-python)
- **Docs:** [shodan.io](https://www.shodan.io/)
- **Install:** `pip install shodan`
- **API Keys:** **Required** — `shodan.api_key` ($49 one-time membership)
- **Type:** Passive (queries Shodan's index, not the target)
- **CLI:** `shodan search <query>` / Python API
- **OhSINT wrapper:** `src/tools/shodan_tool.py`
- **MCP tool:** `osint_shodan`
- **Profiles:** passive, infrastructure, threat-intel, full

---

### ExifTool

File metadata extraction — reads EXIF, GPS, author, software, timestamps from 200+ file types.

- **Repo:** [github.com/exiftool/exiftool](https://github.com/exiftool/exiftool)
- **Install:** `sudo apt install libimage-exiftool-perl`
- **API Keys:** None
- **Type:** Passive (analyzes already-downloaded files)
- **CLI:** `exiftool -r <dir>`
- **OhSINT wrapper:** `src/tools/exiftool.py`
- **MCP tool:** `osint_exiftool`
- **Profiles:** passive, metadata, full

---

### github-dorks

Scan GitHub repositories and organizations for sensitive information leaks using configurable dork patterns.

- **Repo:** [github.com/techgaun/github-dorks](https://github.com/techgaun/github-dorks)
- **Install:** `git clone https://github.com/techgaun/github-dorks.git && pip install -r requirements.txt`
- **API Keys:** **Required** — `github_dorks.github_token`
- **Type:** Passive
- **CLI:** `python github-dork.py -u <org>`
- **OhSINT wrapper:** `src/tools/github_dorks.py`
- **MCP tool:** `osint_github_dorks`
- **Profiles:** passive, full

---

### CrossLinked

LinkedIn employee enumeration via Google/Bing search engine scraping. No LinkedIn account or API key needed — fully passive.

- **Repo:** [github.com/m8sec/CrossLinked](https://github.com/m8sec/CrossLinked)
- **Install:** `pip install crosslinked`
- **API Keys:** None
- **Type:** Passive
- **CLI:** `crosslinked -f '{first}.{last}@domain.com' "Company Name"`
- **OhSINT wrapper:** `src/tools/crosslinked.py`
- **MCP tool:** `osint_crosslinked`
- **Profiles:** passive, social, people, full

---

### InSpy

Two modes: **EmpSpy** (employee enumeration by title/department) and **TechSpy** (technology stack fingerprinting from LinkedIn job listings).

- **Repo:** [github.com/jobroche/InSpy](https://github.com/jobroche/InSpy)
- **Install:** `git clone https://github.com/jobroche/InSpy.git && pip install -r requirements.txt`
- **API Keys:** Optional — Hunter.io improves email verification
- **Type:** Passive
- **CLI:** `python InSpy.py "Company" --empspy --titles wordlists/title-list-large.txt`
- **OhSINT wrapper:** `src/tools/inspy.py`
- **MCP tool:** `osint_inspy`
- **Profiles:** passive, social, people, metadata (techspy), full

---

### linkedin2username

Authenticated LinkedIn scraping via Selenium. Logs into LinkedIn and scrapes the full employee directory, generating multiple username format files.

- **Repo:** [github.com/initstring/linkedin2username](https://github.com/initstring/linkedin2username)
- **Install:** `git clone https://github.com/initstring/linkedin2username.git && pip install -r requirements.txt`
- **API Keys:** **Required** — `linkedin.email`, `linkedin.password` (use a dedicated research account)
- **Type:** Active (authenticates to LinkedIn)
- **CLI:** `python linkedin2username.py -c company-name -n domain.com -d 5 -s 3`
- **OhSINT wrapper:** `src/tools/linkedin2username.py`
- **MCP tool:** `osint_linkedin2username`
- **Profiles:** active, full

---

### Sherlock

Cross-platform username search across 400+ social media sites.

- **Repo:** [github.com/sherlock-project/sherlock](https://github.com/sherlock-project/sherlock)
- **Install:** `pip install sherlock-project`
- **API Keys:** None
- **Type:** Passive
- **CLI:** `sherlock <username1> <username2> --csv --print-found`
- **OhSINT wrapper:** `src/tools/sherlock_tool.py`
- **MCP tool:** `osint_sherlock`
- **Profiles:** social, people, full

---

### Maigret

Username search across 3,000+ sites with profile data extraction (names, bios, links) and better false-positive filtering than Sherlock.

- **Repo:** [github.com/soxoj/maigret](https://github.com/soxoj/maigret)
- **Install:** `pip install maigret`
- **API Keys:** None
- **Type:** Passive
- **CLI:** `maigret <username> --json ndjson -C --no-color`
- **OhSINT wrapper:** `src/tools/maigret_tool.py`
- **MCP tool:** `osint_maigret`
- **Profiles:** social, people, full

---

### Holehe

Email-to-platform registration check. Checks 120+ platforms via password reset endpoints to determine where an email is registered.

- **Repo:** [github.com/megadose/holehe](https://github.com/megadose/holehe)
- **Install:** `pip install holehe`
- **API Keys:** None
- **Type:** Passive (checks public registration endpoints, does not alert the target)
- **CLI:** `holehe user@example.com --no-color --no-clear`
- **OhSINT wrapper:** `src/tools/holehe_tool.py`
- **MCP tool:** `osint_holehe`
- **Profiles:** social, people, full

---

### LinkedInt

LinkedIn profile deep-scraping. Archived and may not work with current LinkedIn.

- **Repo:** [github.com/mdsecactivebreach/LinkedInt](https://github.com/mdsecactivebreach/LinkedInt)
- **Install:** `git clone https://github.com/mdsecactivebreach/LinkedInt.git`
- **API Keys:** **Required** — `linkedin.email`, `linkedin.password`
- **Type:** Active (authenticates to LinkedIn)
- **Status:** Archived, non-functional. Use CrossLinked or linkedin2username instead.
- **OhSINT wrapper:** `src/tools/linkedint.py`
- **MCP tool:** N/A (returns early with non-functional warning)
- **Profiles:** full

---

### Subfinder

Fast passive subdomain enumeration using 40+ public APIs (crt.sh, SecurityTrails, VirusTotal, Censys, Shodan, etc.). Zero target interaction.

- **Repo:** [github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder)
- **Install:** `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- **API Keys:** Optional — SecurityTrails, Censys, VirusTotal keys improve coverage
- **Type:** Passive
- **CLI:** `subfinder -d <domain> -all -silent -json`
- **OhSINT wrapper:** `src/tools/subfinder.py`
- **MCP tool:** `osint_subfinder`
- **Profiles:** passive, infrastructure, full

---

### crt.sh

Certificate Transparency log search. Discovers subdomains and certificates from public CT logs — every SSL/TLS certificate ever issued for a domain is publicly logged.

- **Website:** [crt.sh](https://crt.sh)
- **Install:** API-based (uses httpx, no binary needed)
- **API Keys:** None (free public API)
- **Type:** Passive
- **API:** `GET https://crt.sh/?q=%25.<domain>&output=json`
- **OhSINT wrapper:** `src/tools/crtsh.py`
- **MCP tool:** `osint_crtsh`
- **Profiles:** passive, infrastructure, full

---

### WHOIS

Domain registration and ownership lookup — registrant info, creation/expiration dates, name servers, registrar.

- **Install:** `sudo apt install whois` (pre-installed on Kali)
- **API Keys:** None
- **Type:** Passive
- **CLI:** `whois <domain>`
- **OhSINT wrapper:** `src/tools/whois_tool.py`
- **MCP tool:** `osint_whois`
- **Profiles:** passive, infrastructure, full

---

### VirusTotal

Domain and IP threat reputation — checks against 70+ antivirus/security vendors. Returns malicious scores, DNS records, categories, ASN info, and subdomains.

- **Website:** [virustotal.com](https://www.virustotal.com)
- **Install:** API-based (uses httpx, no binary needed)
- **API Keys:** **Required** — `virustotal.api_key` (free tier: 4 req/min, 500/day)
- **Type:** Passive (queries VirusTotal's index)
- **API:** `GET https://www.virustotal.com/api/v3/domains/{domain}`
- **OhSINT wrapper:** `src/tools/virustotal.py`
- **MCP tool:** `osint_virustotal`
- **Profiles:** passive, threat-intel, full

---

### h8mail

Email breach hunting — queries HIBP, Snusbase, LeakLookup, Dehashed, Intelligence X for exposed credentials and breach data.

- **Repo:** [github.com/khast3x/h8mail](https://github.com/khast3x/h8mail)
- **Install:** `pip install h8mail`
- **API Keys:** Optional — HIBP, Snusbase, LeakLookup, Dehashed keys improve results
- **Type:** Passive (queries breach databases)
- **CLI:** `h8mail -t <email> -j output.json`
- **OhSINT wrapper:** `src/tools/h8mail.py`
- **MCP tool:** `osint_h8mail`
- **Profiles:** passive, threat-intel, full

---

### waymore

Web archive URL extraction — queries Wayback Machine, Common Crawl (106 index collections), AlienVault OTX, URLScan, and VirusTotal for all known URLs associated with a domain.

- **Repo:** [github.com/xnl-h4ck3r/waymore](https://github.com/xnl-h4ck3r/waymore)
- **Install:** `pip install waymore`
- **API Keys:** None
- **Type:** Passive (queries web archives, not the target)
- **CLI:** `waymore -i <domain> -mode U`
- **OhSINT wrapper:** `src/tools/waymore.py`
- **MCP tool:** `osint_waymore`
- **Profiles:** passive, threat-intel, full

---

### Brave Search

Web search API for OSINT reconnaissance. Runs OSINT-focused dork queries (subdomains, documents, login pages, exposed files, directory listings, config exposure, error pages, API endpoints).

- **Website:** [brave.com/search/api](https://brave.com/search/api/)
- **Install:** API-based (uses httpx, no binary needed)
- **API Keys:** **Required** — `brave.api_key` (free tier: 2,000 queries/month)
- **Type:** Passive
- **OhSINT wrapper:** `src/tools/brave_search.py`
- **MCP tool:** `osint_brave_search`
- **Profiles:** passive, infrastructure, full

---

### XRay

Network reconnaissance and OSINT from public networks. Archived — the author recommends [legba](https://github.com/evilsocket/legba) as the Rust-based successor.

- **Repo:** [github.com/evilsocket/xray](https://github.com/evilsocket/xray) (archived)
- **Install:** `git clone && go build -o xray ./cmd/xray/ && sudo cp xray /usr/local/bin/`
- **API Keys:** **Required** — `shodan.api_key`
- **Type:** Active (direct network interaction)
- **CLI:** `xray -target <domain> -shodan-key <key>`
- **OhSINT wrapper:** `src/tools/xray.py`
- **MCP tool:** `osint_xray`
- **Profiles:** active, full

---

### GooDork

Google dorking from the command line. Despite the name, this is a Python tool (not Go).

- **Repo:** [github.com/k3170makan/GooDork](https://github.com/k3170makan/GooDork)
- **Install:** `git clone https://github.com/k3170makan/GooDork.git && pip install beautifulsoup4`
- **API Keys:** None
- **Type:** Passive
- **CLI:** `python GooDork.py -q "site:<domain>" -p 3`
- **OhSINT wrapper:** `src/tools/goodork.py`
- **MCP tool:** `osint_goodork`
- **Profiles:** full

---

### dork-cli

Google dork query runner with built-in rate limiting and dork library (GHDB passive, filetype, login, sensitive, directory dorks).

- **Repo:** [github.com/jgor/dork-cli](https://github.com/jgor/dork-cli)
- **Install:** `git clone https://github.com/jgor/dork-cli.git`
- **API Keys:** None
- **Type:** Passive
- **CLI:** `python dork-cli.py -q "site:<domain> filetype:pdf"`
- **OhSINT wrapper:** `src/tools/dork_cli.py`
- **MCP tool:** `osint_google_dorks`
- **Profiles:** passive, metadata, full

---

### DataSploit

OSINT visualizer aggregating data from Shodan, Censys, Clearbit, and other sources.

- **Repo:** [github.com/upgoingstar/datasploit](https://github.com/upgoingstar/datasploit)
- **Install:** `git clone https://github.com/upgoingstar/datasploit.git`
- **API Keys:** Optional — Shodan API key
- **Type:** Passive
- **OhSINT wrapper:** `src/tools/datasploit.py`
- **MCP tool:** `osint_datasploit`
- **Profiles:** full

---

### Snitch

Information gathering via Google dork queries.

- **Repo:** [github.com/Smaash/snitch](https://github.com/Smaash/snitch)
- **Install:** `git clone https://github.com/Smaash/snitch.git`
- **API Keys:** None
- **Type:** Passive
- **OhSINT wrapper:** `src/tools/snitch.py`
- **MCP tool:** `osint_snitch`
- **Profiles:** full

---

### VcsMap

Scan public version control systems (GitHub, GitLab, Bitbucket) for sensitive information.

- **Repo:** [github.com/melvinsh/vcsmap](https://github.com/melvinsh/vcsmap)
- **Install:** `gem install vcsmap`
- **API Keys:** None
- **Type:** Passive
- **CLI:** `vcsmap -t <target> --all`
- **OhSINT wrapper:** `src/tools/vcsmap.py`
- **MCP tool:** `osint_vcsmap`
- **Profiles:** full

---

### Creepy

Geolocation OSINT — extracts location data from social media profiles and posts.

- **Repo:** [github.com/ilektrojohn/creepy](https://github.com/ilektrojohn/creepy)
- **Install:** `git clone https://github.com/ilektrojohn/creepy.git`
- **API Keys:** None
- **Type:** Passive
- **OhSINT wrapper:** `src/tools/creepy.py`
- **MCP tool:** `osint_creepy`
- **Profiles:** social, full

---

### NumVerify

Phone number validation — carrier, line type, location, country via NumVerify API.

- **Website:** [numverify.com](https://numverify.com/)
- **Install:** API-based (uses httpx)
- **API Keys:** **Required** — `numverify.api_key` (free: 100 req/month)
- **Type:** Passive
- **OhSINT wrapper:** `src/tools/numverify.py`
- **MCP tool:** `osint_numverify`
- **Profiles:** phone, identity

---

### Twilio Lookup

Phone carrier, CNAM (caller ID name), and line type intelligence via Twilio Lookup API v2.

- **Website:** [twilio.com](https://www.twilio.com/docs/lookup)
- **Install:** API-based (uses httpx)
- **API Keys:** **Required** — `twilio.account_sid`, `twilio.auth_token` (~$0.005/lookup)
- **Type:** Passive
- **Cost:** ~$0.005 per lookup. Logged to audit trail.
- **OhSINT wrapper:** `src/tools/twilio_lookup.py`
- **MCP tool:** `osint_twilio_lookup`
- **Profiles:** phone, identity

---

### Censys

Internet device and certificate search — hosts, services, TLS certs. Also searches for SIP/VoIP infrastructure associated with phone numbers.

- **Website:** [search.censys.io](https://search.censys.io/)
- **Install:** API-based (uses httpx)
- **API Keys:** **Required** — `censys.api_id`, `censys.api_secret` (free: 250 req/month)
- **Type:** Passive
- **OhSINT wrapper:** `src/tools/censys.py`
- **MCP tool:** `osint_censys`
- **Profiles:** phone, infrastructure

---

### Intelligence X

Search leaked data, dark web, paste sites, and breach archives for phone numbers, emails, or domains.

- **Website:** [intelx.io](https://intelx.io/)
- **Install:** API-based (uses httpx)
- **API Keys:** **Required** — `intelx.api_key` (free: ~10 searches/day)
- **Type:** Passive
- **Rate limit:** Free tier is heavily limited. 429 errors handled gracefully.
- **OhSINT wrapper:** `src/tools/intelx.py`
- **MCP tool:** `osint_intelx`
- **Profiles:** phone, identity, threat-intel

---

### Hudson Rock

Infostealer credential lookup — maps phones/emails to compromised machines from Raccoon, Redline, Vidar, and similar infostealer families.

- **Website:** [hudsonrock.com](https://www.hudsonrock.com/)
- **Install:** API-based (uses httpx)
- **API Keys:** None for basic tier; optional `hudson_rock.api_key` for Pro
- **Type:** Passive
- **OhSINT wrapper:** `src/tools/hudson_rock.py`
- **MCP tool:** `osint_hudson_rock`
- **Profiles:** phone, identity, threat-intel

---

### SpyCloud

Enterprise botnet log and recaptured credential search. Requires security firm verification for access.

- **Website:** [spycloud.com](https://spycloud.com/)
- **Install:** API-based (uses httpx)
- **API Keys:** **Required** — `spycloud.api_key` (enterprise only). Must also set `spycloud.enabled: true`
- **Type:** Passive (gated behind config flag)
- **OhSINT wrapper:** `src/tools/spycloud.py`
- **MCP tool:** N/A (disabled by default)
- **Profiles:** identity (when enabled)

---

### Consumer Identity Reference

Generates lookup URLs for manual investigation on consumer identity portals (Spokeo, BeenVerified, Whitepages, TruePeopleSearch, etc.). No API calls, no scraping — just builds URLs.

- **Install:** No install needed
- **API Keys:** None
- **Type:** Passive
- **OhSINT wrapper:** `src/tools/consumer_identity_reference.py`
- **MCP tool:** `osint_consumer_identity_links`
- **Profiles:** phone, identity

---

### Whitepages Pro

Reverse phone and identity lookup — owner, address, carrier data via Whitepages Pro API. **FCRA-gated.**

- **Website:** [pro.whitepages.com](https://pro.whitepages.com/)
- **Install:** API-based (uses httpx)
- **API Keys:** **Required** — `whitepages_pro.api_key` (subscription required)
- **Type:** **FCRA-gated** — requires `--authorization` AND `--fcra-permissible-purpose`
- **Cost:** ~$0.10/lookup
- **OhSINT wrapper:** `src/tools/whitepages_pro.py`
- **MCP tool:** `osint_whitepages_pro`
- **Profiles:** commercial_identity

---

### BeenVerified

Identity resolution — phone/email/name lookup via BeenVerified Business API. **FCRA-gated.**

- **Website:** [beenverified.com/business](https://www.beenverified.com/business/)
- **Install:** API-based (uses httpx)
- **API Keys:** **Required** — `beenverified.api_key` (business subscription required)
- **Type:** **FCRA-gated** — requires `--authorization` AND `--fcra-permissible-purpose`
- **Cost:** ~$0.15/lookup
- **OhSINT wrapper:** `src/tools/beenverified.py`
- **MCP tool:** N/A (use via commercial_identity profile)
- **Profiles:** commercial_identity

---

### LexisNexis

LexisNexis Accurint identity resolution. **Placeholder stub** — requires PI license or law enforcement credentials.

- **Website:** [risk.lexisnexis.com/products/accurint](https://risk.lexisnexis.com/products/accurint)
- **API Keys:** Contract-specific — `lexisnexis.api_key`, `lexisnexis.api_endpoint`
- **Type:** **FCRA-gated stub** — disabled by default
- **OhSINT wrapper:** `src/tools/lexisnexis.py`

---

### TLO

TLO/TransUnion investigative data. **Placeholder stub** — requires security firm verification.

- **Website:** [tlo.com](https://www.tlo.com/)
- **API Keys:** Contract-specific — `tlo.api_key`, `tlo.api_endpoint`
- **Type:** **FCRA-gated stub** — disabled by default
- **OhSINT wrapper:** `src/tools/tlo.py`

---

### CLEAR

Thomson Reuters CLEAR investigative platform. **Placeholder stub** — requires LE or licensed investigator credentials.

- **Website:** [legal.thomsonreuters.com](https://legal.thomsonreuters.com/en/products/clear-investigation-software)
- **API Keys:** Contract-specific — `clear.api_key`, `clear.api_endpoint`
- **Type:** **FCRA-gated stub** — disabled by default
- **OhSINT wrapper:** `src/tools/clear_tool.py`

---

### Tracers

Tracers investigative data platform. **Placeholder stub** — requires licensed investigator credentials.

- **Website:** [tracers.com](https://www.tracers.com/)
- **API Keys:** Contract-specific — `tracers.api_key`
- **Type:** **FCRA-gated stub** — disabled by default
- **OhSINT wrapper:** `src/tools/tracers.py`

---

### IDI

IDI/idiCORE identity resolution platform. **Placeholder stub** — requires credentialed access.

- **Website:** [ididata.com](https://www.ididata.com/)
- **API Keys:** Contract-specific — `idi.api_key`
- **Type:** **FCRA-gated stub** — disabled by default
- **OhSINT wrapper:** `src/tools/idi.py`

---

### SmartMove

TransUnion SmartMove identity/background reports. **Placeholder stub** — FCRA-gated, ~$25-45 per report.

- **Website:** [mysmartmove.com](https://www.mysmartmove.com/)
- **API Keys:** Contract-specific — `smartmove.api_key`
- **Type:** **FCRA-gated stub** — disabled by default
- **Cost:** ~$25-45 per report
- **OhSINT wrapper:** `src/tools/smartmove.py`
