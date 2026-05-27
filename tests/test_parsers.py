"""Unit tests for all OSINT tool output parsers."""

import pytest
from src.config import Config
from src.models import IntelType

# Use a dummy config for all tests
config = Config()


# ---------------------------------------------------------------------------
# theHarvester
# ---------------------------------------------------------------------------
class TestTheHarvester:
    def setup_method(self):
        from src.tools.theharvester import TheHarvester
        self.tool = TheHarvester(config=config)

    def test_parse_emails(self):
        output = """
[*] Emails found:
admin@example.com
info@example.com
[*] Hosts found:
mail.example.com:93.184.216.34
www.example.com:93.184.216.34
[*] IPs found:
93.184.216.34
"""
        result = self.tool.parse_output(output, "example.com")
        data = result.structured_data
        assert "admin@example.com" in data["emails"]
        assert "info@example.com" in data["emails"]
        assert "mail.example.com" in data["subdomains"]
        assert "93.184.216.34" in data["ips"]
        assert len(data["findings"]) >= 4

    def test_parse_people(self):
        output = """
[*] People found:
John Smith
Jane Doe
"""
        result = self.tool.parse_output(output, "example.com")
        assert "John Smith" in result.structured_data["people"]
        assert "Jane Doe" in result.structured_data["people"]

    def test_empty_output(self):
        result = self.tool.parse_output("", "example.com")
        assert result.tool_name == "theharvester"
        assert result.structured_data["emails"] == []

    def test_regex_fallback(self):
        output = "Some random text with hidden@example.org embedded"
        result = self.tool.parse_output(output, "example.com")
        assert "hidden@example.org" in result.structured_data["emails"]


# ---------------------------------------------------------------------------
# SpiderFoot
# ---------------------------------------------------------------------------
class TestSpiderFoot:
    def setup_method(self):
        from src.tools.spiderfoot import SpiderFoot
        self.tool = SpiderFoot(config=config)

    def test_parse_json_events(self):
        import json
        events = [
            {"type": "EMAILADDR", "data": "admin@example.com"},
            {"type": "IP_ADDRESS", "data": "93.184.216.34"},
            {"type": "INTERNET_NAME", "data": "www.example.com"},
        ]
        output = json.dumps(events)
        result = self.tool.parse_output(output, "example.com")
        findings = result.structured_data["findings"]
        types = [f["type"] for f in findings]
        assert IntelType.EMAIL in types
        assert IntelType.IP_ADDRESS in types
        assert IntelType.SUBDOMAIN in types

    def test_parse_tabular(self):
        output = "2024-01-01\tEMAILADDR\tmodule\tsrc\ttest@example.com"
        result = self.tool.parse_output(output, "example.com")
        findings = result.structured_data["findings"]
        assert len(findings) == 1
        assert findings[0]["type"] == IntelType.EMAIL

    def test_empty_output(self):
        result = self.tool.parse_output("", "example.com")
        assert result.structured_data["findings"] == []


# ---------------------------------------------------------------------------
# recon-ng
# ---------------------------------------------------------------------------
class TestReconNg:
    def setup_method(self):
        from src.tools.recon_ng import ReconNg
        self.tool = ReconNg(config=config)

    def test_parse_hosts(self):
        output = """
[*] www.example.com (93.184.216.34)
[*] mail.example.com (93.184.216.35)
"""
        result = self.tool.parse_output(output, "example.com")
        data = result.structured_data
        assert len(data["hosts"]) == 2
        hostnames = [h["hostname"] for h in data["hosts"]]
        assert "www.example.com" in hostnames

    def test_parse_contacts(self):
        output = "admin@example.com | John Smith | Registrant"
        result = self.tool.parse_output(output, "example.com")
        assert "admin@example.com" in result.structured_data["contacts"]


# ---------------------------------------------------------------------------
# metagoofil
# ---------------------------------------------------------------------------
class TestMetagoofil:
    def setup_method(self):
        from src.tools.metagoofil import Metagoofil
        self.tool = Metagoofil(config=config)

    def test_parse_users_and_software(self):
        output = """
[*] Users found:
John Smith
Jane Doe
[*] Software found:
Microsoft Office Word
Adobe Acrobat 11
[*] Emails found:
jsmith@example.com
"""
        result = self.tool.parse_output(output, "example.com")
        data = result.structured_data
        assert "John Smith" in data["users"]
        assert "Microsoft Office Word" in data["software"]
        assert "jsmith@example.com" in data["emails"]


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------
class TestShodan:
    def setup_method(self):
        from src.tools.shodan_tool import ShodanTool
        self.tool = ShodanTool(config=config)

    def test_parse_cli_output(self):
        output = "93.184.216.34\t80\texample.org\tApache"
        result = self.tool.parse_output(output, "example.com")
        findings = result.structured_data["findings"]
        assert len(findings) == 2  # IP + port

    def test_parse_host_data(self):
        host = {
            "ip_str": "93.184.216.34",
            "hostnames": ["example.com"],
            "data": [
                {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.19", "vulns": ["CVE-2021-1234"]},
            ],
            "org": "Example Inc",
            "asn": "AS15133",
        }
        findings = self.tool._parse_host(host)
        types = [f["type"] for f in findings]
        assert IntelType.IP_ADDRESS in types
        assert IntelType.SUBDOMAIN in types
        assert IntelType.PORT_SERVICE in types
        assert IntelType.VULNERABILITY in types
        assert IntelType.ASN in types


# ---------------------------------------------------------------------------
# exiftool
# ---------------------------------------------------------------------------
class TestExifTool:
    def setup_method(self):
        from src.tools.exiftool import ExifTool
        self.tool = ExifTool(config=config)

    def test_parse_json_output(self):
        import json
        records = [{
            "SourceFile": "doc.pdf",
            "Author": "John Smith",
            "Creator": "Microsoft Word",
            "Producer": "Adobe PDF Library",
            "GPSLatitude": "40.7128",
            "GPSLongitude": "-74.0060",
        }]
        output = json.dumps(records)
        result = self.tool.parse_output(output, "/tmp/docs")
        data = result.structured_data
        assert "John Smith" in data["users"]
        assert "Microsoft Word" in data["software"] or "Adobe PDF Library" in data["software"]
        assert len(data["geolocations"]) == 1

    def test_parse_text_output(self):
        output = """
======== doc.pdf
Author                          : Jane Doe
Creator                         : LibreOffice 7.4
"""
        result = self.tool.parse_output(output, "/tmp/docs")
        assert "JaneDoe" in result.structured_data["users"] or "Jane Doe" in str(result.structured_data)


# ---------------------------------------------------------------------------
# github-dorks
# ---------------------------------------------------------------------------
class TestGithubDorks:
    def setup_method(self):
        from src.tools.github_dorks import GithubDorks
        self.tool = GithubDorks(config=config)

    def test_parse_sensitive_files(self):
        output = """
https://github.com/example/repo/blob/main/.env
https://github.com/example/repo/blob/main/config/database.yml
"""
        result = self.tool.parse_output(output, "example")
        data = result.structured_data
        assert len(data["sensitive_files"]) == 2
        assert data["sensitive_files"][0]["repo"] == "example/repo"

    def test_parse_credentials(self):
        output = "Found: AWS_ACCESS_KEY_ID=AKIA... in repo/file.txt"
        result = self.tool.parse_output(output, "example")
        assert len(result.structured_data["potential_credentials"]) == 1


# ---------------------------------------------------------------------------
# XRay
# ---------------------------------------------------------------------------
class TestXRay:
    def setup_method(self):
        from src.tools.xray import XRay
        self.tool = XRay(config=config)

    def test_parse_ip_port(self):
        output = "Found: 192.168.1.1:443 — nginx\nFound: 192.168.1.1:80 — Apache"
        result = self.tool.parse_output(output, "192.168.1.0/24")
        data = result.structured_data
        assert "192.168.1.1" in data["hosts"]
        assert len(data["ports"]) == 2


# ---------------------------------------------------------------------------
# DorkCli
# ---------------------------------------------------------------------------
class TestDorkCli:
    def setup_method(self):
        from src.tools.dork_cli import DorkCli, DORK_CATEGORIES
        self.tool = DorkCli(config=config)
        self.categories = DORK_CATEGORIES

    def test_dork_categories_exist(self):
        assert "ghdb_passive" in self.categories
        assert "filetype_dorks" in self.categories
        assert "sensitive_dorks" in self.categories
        assert len(self.categories["ghdb_passive"]) > 0

    def test_parse_urls(self):
        output = "https://example.com/admin/login.php\nhttps://example.com/backup.sql"
        result = self.tool.parse_output(output, "example.com")
        findings = result.structured_data["findings"]
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Creepy
# ---------------------------------------------------------------------------
class TestCreepy:
    def setup_method(self):
        from src.tools.creepy import Creepy
        self.tool = Creepy(config=config)

    def test_parse_gps(self):
        output = "Location found: 40.7128, -74.0060 from Twitter post"
        result = self.tool.parse_output(output, "johndoe")
        findings = result.structured_data["findings"]
        geo = [f for f in findings if f["type"] == IntelType.GEOLOCATION]
        assert len(geo) == 1

    def test_parse_social_profiles(self):
        output = "Profile: https://twitter.com/johndoe"
        result = self.tool.parse_output(output, "johndoe")
        findings = result.structured_data["findings"]
        social = [f for f in findings if f["type"] == IntelType.SOCIAL_PROFILE]
        assert len(social) == 1


# ---------------------------------------------------------------------------
# dnsx_cname
# ---------------------------------------------------------------------------
class TestDnsxCname:
    def setup_method(self):
        from src.tools.dnsx_cname import DnsxCname
        self.tool = DnsxCname(config=config)

    def test_parse_json_cname(self):
        output = '{"host":"blog.example.com","cname":["example.github.io"]}\n{"host":"app.example.com","cname":["app-example.herokuapp.com"]}\n'
        result = self.tool.parse_output(output, "example.com")
        cmap = result.structured_data["cname_map"]
        assert "blog.example.com" in cmap
        assert "example.github.io" in cmap["blog.example.com"]
        assert result.structured_data["total_resolved"] == 2
        findings = result.structured_data["findings"]
        assert len(findings) == 2
        assert all(f["type"] == IntelType.DNS_RECORD for f in findings)

    def test_parse_empty_output(self):
        result = self.tool.parse_output("", "example.com")
        assert result.structured_data["total_resolved"] == 0
        assert result.structured_data["findings"] == []

    def test_build_command_standalone(self):
        cmd = self.tool.build_command("example.com")
        assert "dnsx" in cmd
        assert "-d" in cmd
        assert "example.com" in cmd
        assert "-cname" in cmd

    def test_build_command_with_input_file(self):
        cmd = self.tool.build_command("example.com", input_file="/tmp/subs.txt")
        assert "-l" in cmd
        assert "/tmp/subs.txt" in cmd
        assert "-d" not in cmd


# ---------------------------------------------------------------------------
# subzy
# ---------------------------------------------------------------------------
class TestSubzy:
    def setup_method(self):
        from src.tools.subzy import SubzyTool
        self.tool = SubzyTool(config=config)

    def test_parse_json_vulnerable(self):
        output = '{"subdomain":"blog.example.com","cname":"example.github.io","service":"GitHub Pages","vulnerable":true}\n'
        result = self.tool.parse_output(output, "example.com")
        assert result.structured_data["total_vulnerable"] == 1
        findings = result.structured_data["findings"]
        assert len(findings) == 1
        assert findings[0]["type"] == IntelType.SUBDOMAIN_TAKEOVER
        assert findings[0]["confidence"] == 0.7

    def test_parse_text_vulnerable(self):
        output = "[VULNERABLE] blog.example.com - Service: GitHub Pages\n[NOT VULNERABLE] www.example.com\n"
        result = self.tool.parse_output(output, "example.com")
        assert result.structured_data["total_vulnerable"] == 1
        assert result.structured_data["findings"][0]["value"] == "blog.example.com"

    def test_parse_empty(self):
        result = self.tool.parse_output("", "example.com")
        assert result.structured_data["total_vulnerable"] == 0

    def test_standalone_returns_error(self):
        result = self.tool.run("example.com")
        assert result.errors
        assert "input-file" in result.errors[0]


# ---------------------------------------------------------------------------
# nuclei_takeovers
# ---------------------------------------------------------------------------
class TestNucleiTakeovers:
    def setup_method(self):
        from src.tools.nuclei_takeovers import NucleiTakeovers
        self.tool = NucleiTakeovers(config=config)

    def test_parse_json_takeover(self):
        output = '{"host":"https://blog.example.com","template-id":"github-takeover","matcher-name":"github","info":{"name":"GitHub Takeover","severity":"high"}}\n'
        result = self.tool.parse_output(output, "example.com")
        assert result.structured_data["total_found"] == 1
        findings = result.structured_data["findings"]
        assert len(findings) == 1
        assert findings[0]["type"] == IntelType.SUBDOMAIN_TAKEOVER
        assert findings[0]["value"] == "blog.example.com"  # protocol stripped
        assert findings[0]["raw_data"]["severity"] == "high"

    def test_parse_empty(self):
        result = self.tool.parse_output("", "example.com")
        assert result.structured_data["total_found"] == 0

    def test_build_command_with_input_file(self):
        cmd = self.tool.build_command("example.com", input_file="/tmp/cands.txt")
        assert "-l" in cmd
        assert "/tmp/cands.txt" in cmd
        assert "-t" in cmd
        assert "http/takeovers/" in cmd

    def test_build_command_standalone(self):
        cmd = self.tool.build_command("example.com")
        assert "-u" in cmd
        assert "example.com" in cmd


# ---------------------------------------------------------------------------
# Takeover report rendering
# ---------------------------------------------------------------------------
class TestTakeoverReport:
    def test_markdown_takeover_section(self):
        from src.models import IntelFinding, ReconReport
        from datetime import datetime, timezone

        report = ReconReport(
            target="example.com",
            scan_profile="subdomain_takeover",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            tools_executed=["subzy", "nuclei_takeovers"],
            findings=[
                IntelFinding(
                    type=IntelType.SUBDOMAIN_TAKEOVER,
                    value="blog.example.com",
                    source_tool="subzy,nuclei",
                    confidence=0.95,
                    tags=["takeover", "confirmed", "github-pages"],
                    raw_data={
                        "cname_target": "test.github.io",
                        "provider_name": "GitHub Pages",
                        "severity": "high",
                        "poc_approach": "Create GitHub repo",
                    },
                ),
            ],
            summary={"subdomain_takeover": 1},
        )
        md = report.to_markdown()
        assert "Subdomain Takeover Assessment" in md
        assert "blog.example.com" in md
        assert "GitHub Pages" in md
        assert "Impact Assessment" in md
        assert "Proof of Concept" in md

    def test_html_takeover_section(self):
        from src.models import IntelFinding, ReconReport
        from datetime import datetime, timezone

        report = ReconReport(
            target="example.com",
            scan_profile="subdomain_takeover",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            tools_executed=["subzy"],
            findings=[
                IntelFinding(
                    type=IntelType.SUBDOMAIN_TAKEOVER,
                    value="app.example.com",
                    source_tool="subzy",
                    confidence=0.65,
                    tags=["takeover", "unconfirmed", "heroku"],
                    raw_data={
                        "cname_target": "app.herokuapp.com",
                        "provider_name": "Heroku",
                        "severity": "high",
                        "poc_approach": "Create Heroku app",
                    },
                ),
            ],
            summary={"subdomain_takeover": 1},
        )
        html = report.to_html()
        assert "Subdomain Takeover Assessment" in html
        assert "app.example.com" in html
        assert "Heroku" in html


# ---------------------------------------------------------------------------
# Scope parser
# ---------------------------------------------------------------------------
class TestScopeParser:
    def test_parse_targets_file(self, tmp_path):
        from src.pipelines.scope_parser import parse_targets_file
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n# comment\nhilton.io\n\nhilton.com\n")
        domains = parse_targets_file(f)
        assert domains == ["example.com", "hilton.com", "hilton.io"]

    def test_parse_scope_eligible(self, tmp_path):
        from src.pipelines.scope_parser import parse_scope_file, extract_domains_from_scope
        f = tmp_path / "scope.txt"
        f.write_text(
            "hilton.com\tDomain\tCritical\tEligible\n"
            "*.hilton.io\tWildcard\tCritical\tEligible\n"
            "82.196.42.196/28\tCIDR\tCritical\tEligible\n"
            "pim.hilton.com\tDomain\tNone\tIneligible\n"
        )
        assets = parse_scope_file(f)
        domains = extract_domains_from_scope(assets, include_ineligible=False)
        domain_names = [d["domain"] for d in domains]
        assert "hilton.com" in domain_names
        assert "hilton.io" in domain_names
        assert "pim.hilton.com" not in domain_names


# ---------------------------------------------------------------------------
# Models — deduplication and reporting
# ---------------------------------------------------------------------------
class TestModels:
    def test_deduplication(self):
        from src.models import IntelFinding, ReconReport
        from datetime import datetime, timezone

        f1 = IntelFinding(
            type=IntelType.EMAIL, value="admin@example.com",
            source_tool="theharvester", confidence=0.8,
        )
        f2 = IntelFinding(
            type=IntelType.EMAIL, value="admin@example.com",
            source_tool="spiderfoot", confidence=0.7,
        )
        f3 = IntelFinding(
            type=IntelType.IP_ADDRESS, value="93.184.216.34",
            source_tool="shodan", confidence=0.9,
        )
        report = ReconReport(
            target="example.com",
            scan_profile="passive",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            authorization_confirmed=True,
            findings=[f1, f2, f3],
        )
        deduped = report.deduplicate()
        assert len(deduped.findings) == 2  # email deduped
        email_finding = [f for f in deduped.findings if f.type == IntelType.EMAIL][0]
        assert email_finding.confidence == 0.8  # kept higher
        assert "theharvester" in email_finding.source_tool
        assert "spiderfoot" in email_finding.source_tool

    def test_markdown_report(self):
        from src.models import IntelFinding, ReconReport
        from datetime import datetime, timezone

        report = ReconReport(
            target="example.com",
            scan_profile="passive",
            start_time=datetime(2024, 1, 1),
            end_time=datetime(2024, 1, 1, 0, 30),
            authorization_confirmed=True,
            tools_executed=["theharvester"],
            findings=[
                IntelFinding(
                    type=IntelType.EMAIL, value="test@example.com",
                    source_tool="theharvester", confidence=0.8,
                ),
            ],
            summary={"email": 1},
        )
        md = report.to_markdown()
        assert "example.com" in md
        assert "test@example.com" in md
        assert "theharvester" in md

    def test_html_report(self):
        from src.models import IntelFinding, ReconReport
        from datetime import datetime, timezone

        report = ReconReport(
            target="example.com",
            scan_profile="passive",
            start_time=datetime(2024, 1, 1),
            end_time=datetime(2024, 1, 1, 0, 30),
            authorization_confirmed=True,
            tools_executed=["shodan"],
            findings=[
                IntelFinding(
                    type=IntelType.IP_ADDRESS, value="93.184.216.34",
                    source_tool="shodan", confidence=0.9,
                ),
            ],
            summary={"ip_address": 1},
        )
        html = report.to_html()
        assert "<!DOCTYPE html>" in html
        assert "93.184.216.34" in html
        assert "OhSINT" in html
