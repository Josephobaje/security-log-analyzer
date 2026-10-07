"""Detection rules. Each detector takes parsed events and returns findings."""

from seclog.detectors.bruteforce import detect_ssh_attacks, detect_web_login_bruteforce
from seclog.detectors.config import Thresholds
from seclog.detectors.scanning import detect_404_bursts, detect_scanner_agents
from seclog.detectors.web_attacks import WEB_SIGNATURES, classify_request, detect_web_attacks

__all__ = [
    "WEB_SIGNATURES",
    "Thresholds",
    "classify_request",
    "detect_404_bursts",
    "detect_scanner_agents",
    "detect_ssh_attacks",
    "detect_web_attacks",
    "detect_web_login_bruteforce",
]
