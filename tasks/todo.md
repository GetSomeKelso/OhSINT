# OhSINT Build Checklist

## Phase 1 — Foundation ✅
- [x] Project scaffolding (pyproject.toml, src/, tests/)
- [x] BaseTool abstract class with subprocess execution, timeout, error handling
- [x] ToolResult and IntelFinding Pydantic models
- [x] config.py with YAML-based API key management
- [x] CLI skeleton with Click (global flags, authorization gate)
- [x] install-check command that verifies every tool binary + API keys
- [x] Docker environment that installs all tools

## Phase 2 — Tier 1 Tool Wrappers ✅
- [x] theharvester.py — parse emails, subdomains, IPs from output
- [x] spiderfoot.py — wrap CLI + JSON output parsing
- [x] recon_ng.py — generate .rc scripts, execute, parse workspace DB
- [x] metagoofil.py — download docs + trigger exiftool post-processing
- [x] shodan_tool.py — Python API wrapper (search, host, domain)
- [x] exiftool.py — recursive metadata extraction + field filtering
- [x] github_dorks.py — org/user scanning with configurable dork lists

## Phase 3 — Tier 2 Tool Wrappers ✅
- [x] xray.py — Go binary wrapper
- [x] goodork.py — Go binary wrapper
- [x] dork_cli.py — Google dork execution with rate limiting
- [x] datasploit.py — wrapper with dependency management
- [x] snitch.py — dork-based gathering wrapper
- [x] vcsmap.py — Ruby gem wrapper
- [x] creepy.py — geolocation wrapper

## Phase 4 — Orchestration & Reporting ✅
- [x] Scan profiles (passive, active, metadata, social, full)
- [x] Parallel execution engine with per-tool timeouts
- [x] ReconReport model with deduplication + confidence merging
- [x] Markdown report generator
- [x] HTML report generator (styled dark theme, finding tables, summary cards)
- [x] JSON export for downstream tool consumption

## Phase 5 — MCP Server ✅
- [x] MCP server with tool definitions for every wrapper (14 MCP tools)
- [x] Input validation per MCP tool
- [ ] Streaming output for long-running scans
- [ ] Integration testing with Claude Desktop

## Phase 2.5 — LinkedIn / People Recon ✅
- [x] crosslinked.py — LinkedIn employee enum via search engine scraping (passive)
- [x] inspy.py — EmpSpy (employees) + TechSpy (tech stack from job listings)
- [x] linkedin2username.py — authenticated LinkedIn scraping via Selenium
- [x] sherlock_tool.py — username search across 400+ social media sites
- [x] linkedint.py — LinkedIn deep-scraping (Tier 2, archived, stubbed)
- [x] USERNAME added to IntelType enum
- [x] People scan profile added to scan_profiles.yaml
- [x] Pipeline chaining: CrossLinked/InSpy → linkedin2username → Sherlock
- [x] MCP tools: osint_crosslinked, osint_inspy, osint_linkedin2username, osint_sherlock, osint_people_recon
- [x] Dockerfile updated with crosslinked, sherlock-project, InSpy, linkedin2username, LinkedInt, chromium
- [x] api_keys.yaml.example updated with linkedin + hunter_io sections

## Phase 7 — Subdomain Takeover Detection ✅
- [x] SUBDOMAIN_TAKEOVER added to IntelType enum
- [x] configs/takeover_providers.yaml — 17 provider fingerprint patterns
- [x] Config.get_takeover_providers() method
- [x] dnsx_cname.py — DNS CNAME resolution wrapper
- [x] subzy.py — subdomain takeover fingerprinting wrapper
- [x] nuclei_takeovers.py — nuclei takeover templates wrapper
- [x] TakeoverPipeline — 5-stage sequential pipeline with parallel enumeration/fingerprinting
- [x] scope_parser.py — HackerOne/Bugcrowd scope file parser with interactive selection
- [x] Multi-target support: -t repeat, --targets-file, --scope-file
- [x] Combined + per-domain report modes (--per-domain flag)
- [x] --re-scan flag for delta detection against previous results
- [x] Takeover-specific report rendering (markdown + HTML) with impact assessment
- [x] CLI: ohsint takeover command with --dry-run support
- [x] MCP: osint_subdomain_takeover, osint_dnsx_cname, osint_subzy, osint_nuclei_takeovers
- [x] subdomain_takeover scan profile added to scan_profiles.yaml
- [x] docs/tools.md updated with 3 new tools (46 total)
- [x] CLAUDE.md updated with takeover pipeline docs
- [ ] Install dnsx, subzy, nuclei on Kali VM
- [ ] Integration test against known-safe target

## Phase 8 — Pipeline A: Historical URL Harvesting ✅
- [x] _url_classify.py — shared URL classification module (extracted from waymore)
- [x] waymore.py refactored to use shared module
- [x] gau.py — URL harvester (Go binary wrapper)
- [x] waybackurls.py — Wayback URL collector
- [x] gf_patterns.py — gf pattern matcher (stdin-based, auto-copies patterns)
- [x] configs/gf_patterns/ — 5 pattern files (redirect, aws-keys, s3-buckets, secrets, interestingparams)
- [x] UrlHarvestPipeline — 5-stage: enumerate → merge → gf match → JS extract → robots.txt history
- [x] CLI: ohsint url-harvest command
- [x] MCP: osint_url_harvest, osint_gau, osint_waybackurls
- [x] url_harvest scan profile
- [ ] Install gau, waybackurls, gf, waymore on Kali VM
- [ ] Integration test

## Phase 9 — Pipeline B: Secret Surface Discovery ✅
- [x] github_code_search.py — GitHub Search API for secret-focused queries
- [x] trufflehog_github.py — TruffleHog GitHub org scanner
- [x] trufflehog_docker.py — TruffleHog Docker image scanner
- [x] trufflehog_postman.py — TruffleHog Postman workspace scanner
- [x] gitleaks.py — Gitleaks regex-based secret scanner
- [x] docker_hub_search.py — Docker Hub public image discovery
- [x] postman_workspace_search.py — Postman public workspace discovery
- [x] SecretSurfacePipeline — 6-stage: discover → TruffleHog verify → Gitleaks → cross-validate
- [x] LEAKED_SECRET IntelType + secret report rendering (markdown + HTML)
- [x] CLI: ohsint secret-surface command
- [x] MCP: osint_secret_surface, osint_github_code_search, osint_trufflehog_github, etc.
- [x] secret_surface scan profile
- [ ] Install trufflehog, gitleaks on Kali VM
- [ ] Integration test

## Phase 10 — Pipeline C: JavaScript File Analysis ✅
- [x] subjs.py — JS URL crawler (stdin-based)
- [x] getjs.py — JS URL collector for SPAs
- [x] linkfinder_tool.py — JS endpoint extractor
- [x] secretfinder_tool.py — JS secret extractor
- [x] JsAnalysisPipeline — 7-stage: collect → download → beautify → sourcemaps → analyze → TruffleHog → Swagger
- [x] JS_ENDPOINT + EXPOSED_API_DOC IntelTypes
- [x] CLI: ohsint js-analysis command
- [x] MCP: osint_js_analysis, osint_linkfinder
- [x] js_analysis scan profile
- [ ] Install subjs, getjs, js-beautify, linkfinder, SecretFinder on Kali VM
- [ ] Integration test

## Phase 11 — Full Passive Pipeline ✅
- [x] PassiveFullPipeline — chains takeover + url_harvest + secret_surface + js_analysis
- [x] Parallel phase 1 (takeover + url_harvest + secret_surface), sequential phase 2 (js_analysis)
- [x] Report merging + deduplication across pipelines
- [x] CLI: ohsint passive-full command (with --skip-takeover)
- [x] MCP: osint_passive_full
- [x] osint_passive_full scan profile
- [x] configs/pipeline_defaults.yaml — pipeline configuration
- [x] 60 total tools registered, 5 pipelines
- [ ] Full integration test on Kali VM

## Phase 12 — OPSEC / Analyst Protection Layer ✅
- [x] configs/opsec.yaml — UA pool, rate limits, proxy config, session isolation
- [x] src/http_client.py — OhSINTHTTPClient with UA rotation, rate limiting, proxy, cookie suppression
- [x] Config.get_opsec_config() method
- [x] Refactored all 14 HTTP tools + pipelines to use OhSINTHTTPClient (zero bare httpx.Client remaining)
- [x] base.py modified — _build_proxy_env() injects proxy env vars into subprocess.run()
- [x] github_dorks, trufflehog_github, trufflehog_postman updated to use _build_proxy_env()
- [x] CLI: ohsint opsec-check command (UA status, proxy test, session config)
- [x] Session isolation: random suffix on output directories
- [x] docs/kasm-deployment.md — Kasm Workspaces deployment guide
- [ ] Tor connectivity test on Kali VM

## Kali VM — Batch Install (all outstanding)
- [ ] Takeover: dnsx, subzy, nuclei, nuclei-templates
- [ ] Pipeline A: gau, waybackurls, gf, waymore
- [ ] Pipeline B: trufflehog, gitleaks
- [ ] Pipeline C: subjs, getjs, js-beautify, linkfinder, SecretFinder
- [ ] Tor: sudo apt install tor
- [ ] Run ohsint install-check — verify all 60 tools
- [ ] Run ohsint opsec-check — verify OPSEC config
- [ ] Integration test all 5 pipelines against test domain

## Phase 6 — Polish ✅
- [x] Rich CLI output (tables, progress bars, spinners)
- [x] --dry-run flag
- [ ] Scan result caching
- [ ] API key health check
- [x] Unit tests for every parser (24/24 passing)
- [ ] Integration tests against known-safe targets
