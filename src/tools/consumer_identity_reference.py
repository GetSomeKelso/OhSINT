"""Consumer Identity Reference — generates lookup URLs for manual investigation."""

from __future__ import annotations

import re
from typing import List
from urllib.parse import quote_plus

from src.models import IntelType, ToolResult
from src.registry import register_tool
from src.target import TargetType
from src.tools.base import BaseTool

# Consumer identity lookup portals
_PHONE_PORTALS = {
    "TruePeopleSearch": "https://www.truepeoplesearch.com/results?phoneno={phone}",
    "FastPeopleSearch": "https://www.fastpeoplesearch.com/{phone}",
    "USPhoneBook": "https://www.usphonebook.com/{phone}",
    "NumLookup": "https://www.numlookup.com/lookup/{phone}",
    "WhitePages": "https://www.whitepages.com/phone/{phone}",
    "Spokeo": "https://www.spokeo.com/phone/{phone}",
    "BeenVerified": "https://www.beenverified.com/phone/{phone}/",
    "ThatsThem": "https://thatsthem.com/phone/{phone}",
}

_EMAIL_PORTALS = {
    "TruePeopleSearch": "https://www.truepeoplesearch.com/results?email={email}",
    "Spokeo": "https://www.spokeo.com/email-search/search?q={email}",
    "BeenVerified": "https://www.beenverified.com/email/{email}/",
    "ThatsThem": "https://thatsthem.com/email/{email}",
    "Epieos": "https://epieos.com/?q={email}",
}

_NAME_PORTALS = {
    "TruePeopleSearch": "https://www.truepeoplesearch.com/results?name={name}",
    "FastPeopleSearch": "https://www.fastpeoplesearch.com/name/{name}",
    "WhitePages": "https://www.whitepages.com/name/{name}",
    "Spokeo": "https://www.spokeo.com/{name}",
    "BeenVerified": "https://www.beenverified.com/people/{name}/",
}


@register_tool
class ConsumerIdentityReference(BaseTool):
    name = "consumer_identity_reference"
    description = "Generate lookup URLs for manual investigation on consumer identity portals (no API, no scraping)"
    binary_name = "consumer_identity_reference"
    install_cmd = "No install needed — generates URLs only"
    accepted_target_types = (TargetType.PHONE, TargetType.EMAIL, TargetType.PERSON_NAME)
    requires_api_keys = ()

    def is_installed(self) -> bool:
        return True  # no binary needed

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["consumer_identity_reference", "--target", target]

    def run(self, target: str, timeout: int = 300, **kwargs) -> ToolResult:
        import time as _time
        start = _time.time()
        findings = []

        # Detect target type
        is_email = bool(re.match(r'^[\w.+-]+@[\w-]+\.[\w.-]+$', target))
        is_phone = bool(re.match(r'^\+?\d[\d\s.()-]{6,18}\d$', target))

        if is_phone:
            phone = re.sub(r'[\s().+-]', '', target)
            portals = _PHONE_PORTALS
            fmt_key = "phone"
            fmt_val = phone
        elif is_email:
            portals = _EMAIL_PORTALS
            fmt_key = "email"
            fmt_val = quote_plus(target)
        else:
            portals = _NAME_PORTALS
            fmt_key = "name"
            fmt_val = quote_plus(target.lower().replace(" ", "-"))

        for portal_name, url_template in portals.items():
            url = url_template.replace(f"{{{fmt_key}}}", fmt_val)
            findings.append({
                "type": IntelType.METADATA,
                "value": f"{portal_name}: {url}",
                "source_tool": self.name,
                "confidence": 0.5,
                "tags": ["consumer-identity", "reference-url", portal_name.lower()],
                "raw_data": {"portal": portal_name, "url": url, "target_type": fmt_key},
            })

        elapsed = _time.time() - start
        return ToolResult(
            tool_name=self.name, target=target,
            raw_output=f"Generated {len(findings)} lookup URLs for manual investigation",
            structured_data={"portals": len(findings), "findings": findings},
            execution_time_seconds=elapsed,
        )

    def parse_output(self, raw_output: str, target: str) -> ToolResult:
        return ToolResult(tool_name=self.name, target=target, raw_output=raw_output, structured_data={})
