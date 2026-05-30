"""OSINT tool wrappers — importing this module registers all tools."""

# Tier 1 — CLI-Native, Actively Maintained
from src.tools.theharvester import TheHarvester
from src.tools.spiderfoot import SpiderFoot
from src.tools.recon_ng import ReconNg
from src.tools.metagoofil import Metagoofil
from src.tools.shodan_tool import ShodanTool
from src.tools.exiftool import ExifTool
from src.tools.github_dorks import GithubDorks

# API-based tools
from src.tools.brave_search import BraveSearch
from src.tools.crtsh import CrtSh

# Passive infrastructure
from src.tools.subfinder import Subfinder
from src.tools.whois_tool import WhoisTool

# Subdomain takeover detection
from src.tools.dnsx_cname import DnsxCname
from src.tools.subzy import SubzyTool
from src.tools.nuclei_takeovers import NucleiTakeovers
from src.tools.nuclei_scan import NucleiScan

# Threat intel & breach data
from src.tools.virustotal import VirusTotalTool
from src.tools.h8mail import H8mail
from src.tools.waymore import Waymore

# Expanded identity OSINT
from src.tools.maigret_tool import MaigretTool
from src.tools.holehe_tool import HoleheTool

# Phone & Identity — Tier 1 (Open API)
from src.tools.numverify import NumVerifyTool
from src.tools.twilio_lookup import TwilioLookupTool
from src.tools.censys import CensysTool

# Phone & Identity — Tier 2 (Threat Intel)
from src.tools.intelx import IntelXTool
from src.tools.hudson_rock import HudsonRockTool
from src.tools.spycloud import SpyCloudTool

# Phone & Identity — Tier 3 (Commercial, FCRA-gated)
from src.tools.consumer_identity_reference import ConsumerIdentityReference
from src.tools.whitepages_pro import WhitepagesProTool
from src.tools.beenverified import BeenVerifiedTool
from src.tools.lexisnexis import LexisNexisTool
from src.tools.tlo import TloTool
from src.tools.clear_tool import ClearTool
from src.tools.tracers import TracersTool
from src.tools.idi import IdiTool
from src.tools.smartmove import SmartMoveTool

# LinkedIn / People Recon
from src.tools.crosslinked import CrossLinked
from src.tools.inspy import InSpy
from src.tools.linkedin2username import LinkedIn2Username
from src.tools.sherlock_tool import SherlockTool
from src.tools.linkedint import LinkedInt

# Pipeline A — Historical URL Harvesting
from src.tools.gau import Gau
from src.tools.waybackurls import Waybackurls
from src.tools.gf_patterns import GfPatterns

# Pipeline B — Secret Surface Discovery
from src.tools.github_code_search import GithubCodeSearch
from src.tools.trufflehog_github import TrufflehogGithub
from src.tools.trufflehog_docker import TrufflehogDocker
from src.tools.trufflehog_postman import TrufflehogPostman
from src.tools.gitleaks import Gitleaks
from src.tools.docker_hub_search import DockerHubSearch
from src.tools.postman_workspace_search import PostmanWorkspaceSearch

# Pipeline C — JavaScript File Analysis
from src.tools.subjs import Subjs
from src.tools.getjs import GetJs
from src.tools.linkfinder_tool import LinkFinderTool
from src.tools.secretfinder_tool import SecretFinderTool

# ProjectDiscovery — Passive
from src.tools.katana_tool import KatanaTool
from src.tools.uncover_tool import UncoverTool
from src.tools.tlsx_tool import TlsxTool
from src.tools.asnmap_tool import AsnmapTool
from src.tools.cdncheck_tool import CdncheckTool
from src.tools.urlfinder_tool import UrlfinderTool
from src.tools.cvemap_tool import CvemapTool
from src.tools.alterx_tool import AlterxTool
from src.tools.notify_tool import NotifyTool

# ProjectDiscovery — Active
from src.tools.httpx_tool import HttpxTool
from src.tools.naabu_tool import NaabuTool
from src.tools.shuffledns_tool import ShufflednsTool
from src.tools.interactsh_tool import InteractshTool

# Tier 2 — CLI-Compatible, May Need Wrapper Logic
from src.tools.xray import XRay
from src.tools.goodork import GooDork
from src.tools.dork_cli import DorkCli
from src.tools.datasploit import DataSploit
from src.tools.snitch import Snitch
from src.tools.vcsmap import VcsMap
from src.tools.creepy import Creepy

__all__ = [
    # Tier 1
    "TheHarvester",
    "SpiderFoot",
    "ReconNg",
    "Metagoofil",
    "ShodanTool",
    "ExifTool",
    "GithubDorks",
    # API-based
    "BraveSearch",
    "CrtSh",
    # Passive infrastructure
    "Subfinder",
    "WhoisTool",
    # Subdomain takeover detection
    "DnsxCname",
    "SubzyTool",
    "NucleiTakeovers",
    "NucleiScan",
    # Threat intel & breach data
    "VirusTotalTool",
    "H8mail",
    "Waymore",
    # Expanded identity OSINT
    "MaigretTool",
    "HoleheTool",
    # Phone & Identity — Tier 1
    "NumVerifyTool",
    "TwilioLookupTool",
    "CensysTool",
    # Phone & Identity — Tier 2
    "IntelXTool",
    "HudsonRockTool",
    "SpyCloudTool",
    # Phone & Identity — Tier 3 (FCRA-gated)
    "ConsumerIdentityReference",
    "WhitepagesProTool",
    "BeenVerifiedTool",
    "LexisNexisTool",
    "TloTool",
    "ClearTool",
    "TracersTool",
    "IdiTool",
    "SmartMoveTool",
    "SpyCloudTool",
    "LexisNexisTool",
    "TloTool",
    "ClearTool",
    "TracersTool",
    "IdiTool",
    "SmartMoveTool",
    # Pipeline A — URL Harvesting
    "Gau",
    "Waybackurls",
    "GfPatterns",
    # Pipeline B — Secret Surface
    "GithubCodeSearch",
    "TrufflehogGithub",
    "TrufflehogDocker",
    "TrufflehogPostman",
    "Gitleaks",
    "DockerHubSearch",
    "PostmanWorkspaceSearch",
    # Pipeline C — JS Analysis
    "Subjs",
    "GetJs",
    "LinkFinderTool",
    "SecretFinderTool",
    # ProjectDiscovery — Passive
    "KatanaTool",
    "UncoverTool",
    "TlsxTool",
    "AsnmapTool",
    "CdncheckTool",
    "UrlfinderTool",
    "CvemapTool",
    "AlterxTool",
    "NotifyTool",
    # ProjectDiscovery — Active
    "HttpxTool",
    "NaabuTool",
    "ShufflednsTool",
    "InteractshTool",
    # LinkedIn / People Recon
    "CrossLinked",
    "InSpy",
    "LinkedIn2Username",
    "SherlockTool",
    "LinkedInt",
    # Tier 2
    "XRay",
    "GooDork",
    "DorkCli",
    "DataSploit",
    "Snitch",
    "VcsMap",
    "Creepy",
]
