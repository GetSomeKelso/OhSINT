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
