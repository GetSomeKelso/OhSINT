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
