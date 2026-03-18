"""Tests for smart target resolution system."""

import pytest
from src.target import TargetType, TargetResolver, ResolvedTarget, _detect


class TestDetection:
    """Test the detection/classification of raw target strings."""

    def test_detect_domain(self):
        tt, conf = _detect("walmart.com")
        assert tt == TargetType.DOMAIN
        assert conf >= 0.8

    def test_detect_subdomain(self):
        tt, conf = _detect("shop.walmart.com")
        assert tt == TargetType.DOMAIN

    def test_detect_ipv4(self):
        tt, conf = _detect("192.168.1.1")
        assert tt == TargetType.IP
        assert conf >= 0.9

    def test_detect_cidr(self):
        tt, conf = _detect("10.0.0.0/24")
        assert tt == TargetType.CIDR
        assert conf >= 0.9

    def test_detect_email(self):
        tt, conf = _detect("admin@walmart.com")
        assert tt == TargetType.EMAIL
        assert conf >= 0.9

    def test_detect_url(self):
        tt, conf = _detect("https://walmart.com")
        assert tt == TargetType.URL
        assert conf >= 0.9

    def test_detect_github_url(self):
        tt, conf = _detect("https://github.com/walmartlabs")
        assert tt == TargetType.GITHUB_HANDLE
        assert conf >= 0.8

    def test_detect_github_prefix(self):
        tt, conf = _detect("gh:walmartlabs")
        assert tt == TargetType.GITHUB_HANDLE

    def test_detect_filepath_unix(self):
        tt, conf = _detect("/tmp/docs/metadata")
        assert tt == TargetType.FILEPATH

    def test_detect_filepath_windows(self):
        tt, conf = _detect("C:\\Users\\docs")
        assert tt == TargetType.FILEPATH

    def test_detect_filepath_relative(self):
        tt, conf = _detect("./results/scan1")
        assert tt == TargetType.FILEPATH

    def test_detect_username(self):
        tt, conf = _detect("@johndoe")
        assert tt == TargetType.USERNAME

    def test_detect_org_name_single_word(self):
        tt, conf = _detect("Walmart")
        assert tt == TargetType.ORG_NAME

    def test_detect_org_name_with_suffix(self):
        tt, conf = _detect("Walmart Inc")
        assert tt == TargetType.ORG_NAME

    def test_detect_person_name(self):
        tt, conf = _detect("John Smith")
        assert tt == TargetType.PERSON_NAME

    def test_detect_invalid_ip(self):
        """256.1.1.1 is not a valid IP, should fall through to domain or org."""
        tt, conf = _detect("256.1.1.1")
        assert tt != TargetType.IP


class TestResolver:
    """Test the full resolve pipeline including derivation."""

    def setup_method(self):
        self.resolver = TargetResolver()

    def test_resolve_org_derives_domain(self):
        r = self.resolver.resolve("Walmart")
        assert r.detected_type == TargetType.ORG_NAME
        assert r.domain == "walmart.com"
        assert r.github_handle == "walmartlabs"  # from override table
        assert r.org_name == "Walmart"

    def test_resolve_org_derives_domain_no_override(self):
        r = self.resolver.resolve("Acme")
        assert r.domain == "acme.com"
        assert r.github_handle == "acme"

    def test_resolve_domain_derives_org(self):
        r = self.resolver.resolve("tesla.com")
        assert r.detected_type == TargetType.DOMAIN
        assert r.domain == "tesla.com"
        assert r.org_name == "Tesla"
        assert r.github_handle == "teslamotors"  # from override table

    def test_resolve_domain_derives_url(self):
        r = self.resolver.resolve("example.com")
        assert r.url == "https://example.com"

    def test_resolve_email_derives_domain(self):
        r = self.resolver.resolve("hr@walmart.com")
        assert r.detected_type == TargetType.EMAIL
        assert r.email == "hr@walmart.com"
        assert r.domain == "walmart.com"
        assert r.org_name == "Walmart"

    def test_resolve_github_url_strips_prefix(self):
        r = self.resolver.resolve("https://github.com/walmartlabs")
        assert r.detected_type == TargetType.GITHUB_HANDLE
        assert r.github_handle == "walmartlabs"

    def test_resolve_github_prefix_strips(self):
        r = self.resolver.resolve("gh:shopify")
        assert r.github_handle == "shopify"

    def test_resolve_ip_leaves_domain_none(self):
        r = self.resolver.resolve("93.184.216.34")
        assert r.detected_type == TargetType.IP
        assert r.ip == "93.184.216.34"
        assert r.domain is None  # can't derive from IP without DNS

    def test_resolve_cidr(self):
        r = self.resolver.resolve("10.0.0.0/24")
        assert r.detected_type == TargetType.CIDR
        assert r.cidr == "10.0.0.0/24"

    def test_resolve_filepath(self):
        r = self.resolver.resolve("/tmp/downloads")
        assert r.detected_type == TargetType.FILEPATH
        assert r.filepath == "/tmp/downloads"

    def test_resolve_person_derives_username(self):
        r = self.resolver.resolve("John Smith")
        assert r.detected_type == TargetType.PERSON_NAME
        assert r.person_name == "John Smith"
        assert r.username == "johnsmith"

    def test_resolve_username(self):
        r = self.resolver.resolve("@elonmusk")
        assert r.detected_type == TargetType.USERNAME
        assert r.username == "elonmusk"  # @ stripped

    def test_resolve_url_derives_domain(self):
        r = self.resolver.resolve("https://shop.walmart.com/deals")
        assert r.detected_type == TargetType.URL
        assert r.domain == "shop.walmart.com"

    def test_resolve_known_override_meta(self):
        """Meta -> meta.com (override) not 'meta.com' by default."""
        r = self.resolver.resolve("Meta")
        assert r.domain == "meta.com"
        assert r.github_handle == "facebook"  # from override

    def test_resolve_known_override_alphabet(self):
        r = self.resolver.resolve("Alphabet")
        assert r.domain == "abc.xyz"


class TestGetFor:
    """Test ResolvedTarget.get_for() priority selection."""

    def setup_method(self):
        self.resolver = TargetResolver()

    def test_domain_tool_gets_domain(self):
        r = self.resolver.resolve("Walmart")
        assert r.get_for((TargetType.DOMAIN,)) == "walmart.com"

    def test_github_tool_gets_handle(self):
        r = self.resolver.resolve("Walmart")
        assert r.get_for((TargetType.GITHUB_HANDLE,)) == "walmartlabs"

    def test_person_tool_gets_org_name_fallback(self):
        """If person_name is None but org_name exists, and tool accepts both."""
        r = self.resolver.resolve("Walmart")
        # Walmart is detected as org, so person_name is None
        result = r.get_for((TargetType.PERSON_NAME, TargetType.ORG_NAME))
        assert result == "Walmart"

    def test_falls_back_to_raw(self):
        r = self.resolver.resolve("192.168.1.1")
        # IP target asked for FILEPATH — should fall back to raw
        assert r.get_for((TargetType.FILEPATH,)) == "192.168.1.1"

    def test_priority_order_matters(self):
        r = self.resolver.resolve("admin@walmart.com")
        # Email tool prefers email, but if we ask for domain first...
        assert r.get_for((TargetType.DOMAIN, TargetType.EMAIL)) == "walmart.com"
        assert r.get_for((TargetType.EMAIL, TargetType.DOMAIN)) == "admin@walmart.com"


class TestSummaryDict:
    def test_summary_includes_resolved_fields(self):
        r = TargetResolver().resolve("Tesla")
        d = r.summary_dict()
        assert d["raw"] == "Tesla"
        assert d["detected_type"] == "org_name"
        assert "domain" in d
        assert "github_handle" in d


class TestEdgeCases:
    def setup_method(self):
        self.resolver = TargetResolver()

    def test_whitespace_stripped(self):
        r = self.resolver.resolve("  Walmart  ")
        assert r.raw == "Walmart"
        assert r.org_name == "Walmart"

    def test_org_with_special_chars(self):
        r = self.resolver.resolve("Johnson & Johnson")
        # & is technically in our disallowed set for target validation,
        # but the resolver itself handles it gracefully
        assert r.raw == "Johnson & Johnson"

    def test_complex_domain(self):
        r = self.resolver.resolve("my-company.co.uk")
        assert r.detected_type == TargetType.DOMAIN
        assert r.domain == "my-company.co.uk"

    def test_single_letter_not_crash(self):
        r = self.resolver.resolve("X")
        assert r.detected_type == TargetType.ORG_NAME
        assert r.domain == "x.com"
        assert r.github_handle == "twitter"  # from override
