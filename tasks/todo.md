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

## Phase 6 — Polish ✅
- [x] Rich CLI output (tables, progress bars, spinners)
- [x] --dry-run flag
- [ ] Scan result caching
- [ ] API key health check
- [x] Unit tests for every parser (24/24 passing)
- [ ] Integration tests against known-safe targets
