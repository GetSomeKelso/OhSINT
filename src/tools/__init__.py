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
