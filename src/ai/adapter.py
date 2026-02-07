#!/usr/bin/env python3
"""
Honeyclaw AI Adaptive Deception Adapter

Adjusts honeypot interaction level based on attacker sophistication classification.

Interaction levels:
  AUTOMATED:     Low-interaction, fast responses, collect IoCs
  SCRIPT_KIDDIE: Medium-interaction, appear vulnerable
  SKILLED:       High-interaction, AI conversation, fake data breadcrumbs
  ADVANCED/APT:  Maximum engagement, realistic environment, alert SOC immediately

Environment variables:
  AI_ADAPTIVE_ENABLED   - Enable adaptive behavior (default: true)
  AI_ALERT_ON_ADVANCED  - Alert SOC on ADVANCED+ classification (default: true)
"""

import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .classifier import (
    Classification,
    SophisticationClassifier,
    SophisticationLevel,
)


@dataclass
class InteractionProfile:
    """Defines how the honeypot interacts at a given level."""
    level: SophisticationLevel
    interaction_depth: str  # "low", "medium", "high", "maximum"
    use_ai_responses: bool = False
    personality: str = "naive_intern"
    response_delay_multiplier: float = 1.0
    breadcrumb_level: int = 0  # 0=none, 1=basic, 2=interesting, 3=high-value
    alert_soc: bool = False
    description: str = ""


# Default interaction profiles per sophistication level
DEFAULT_PROFILES: Dict[SophisticationLevel, InteractionProfile] = {
    SophisticationLevel.AUTOMATED: InteractionProfile(
        level=SophisticationLevel.AUTOMATED,
        interaction_depth="low",
        use_ai_responses=False,
        personality="naive_intern",
        response_delay_multiplier=0.5,  # Fast responses for bots
        breadcrumb_level=0,
        alert_soc=False,
        description="Low-interaction: collect IoCs, minimal engagement",
    ),
    SophisticationLevel.SCRIPT_KIDDIE: InteractionProfile(
        level=SophisticationLevel.SCRIPT_KIDDIE,
        interaction_depth="medium",
        use_ai_responses=False,
        personality="helpful_clueless",
        response_delay_multiplier=1.0,
        breadcrumb_level=1,
        alert_soc=False,
        description="Medium-interaction: appear vulnerable, basic breadcrumbs",
    ),
    SophisticationLevel.SKILLED: InteractionProfile(
        level=SophisticationLevel.SKILLED,
        interaction_depth="high",
        use_ai_responses=True,
        personality="naive_intern",
        response_delay_multiplier=1.2,
        breadcrumb_level=2,
        alert_soc=False,
        description="High-interaction: AI conversation, interesting breadcrumbs",
    ),
    SophisticationLevel.ADVANCED: InteractionProfile(
        level=SophisticationLevel.ADVANCED,
        interaction_depth="maximum",
        use_ai_responses=True,
        personality="paranoid_admin",
        response_delay_multiplier=1.5,
        breadcrumb_level=3,
        alert_soc=True,
        description="Maximum engagement: realistic environment, high-value breadcrumbs, SOC alert",
    ),
    SophisticationLevel.APT: InteractionProfile(
        level=SophisticationLevel.APT,
        interaction_depth="maximum",
        use_ai_responses=True,
        personality="security_honeypot",
        response_delay_multiplier=1.5,
        breadcrumb_level=3,
        alert_soc=True,
        description="Maximum engagement: full deception suite, immediate SOC alert",
    ),
}

# Breadcrumbs by level - planted data to extend engagement
BREADCRUMBS = {
    1: [
        # Basic: obvious fake data that script kiddies will grab
        {"type": "credential", "data": "admin:password123"},
        {"type": "credential", "data": "root:toor"},
    ],
    2: [
        # Interesting: looks more real, attracts skilled attackers
        {"type": "database_url", "data": "postgresql://app_user:Spr1ng2024!@10.0.0.5:5432/prod"},
        {"type": "api_key", "data": "api_canary_4eC39HqLyjWDarjtT1zdp7dc"},
        {"type": "ssh_key_path", "data": "/opt/backups/keys/deploy_rsa"},
    ],
    3: [
        # High-value: looks like a jackpot to advanced attackers
        {"type": "aws_credentials", "data": "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
        {"type": "vpn_config", "data": "/etc/openvpn/corp-vpn.ovpn"},
        {"type": "kubernetes_config", "data": "/home/admin/.kube/config"},
        {"type": "database_backup", "data": "/opt/backups/prod-db-20260201.sql.gz"},
        {"type": "internal_wiki", "data": "https://wiki.internal.corp/pages/infrastructure"},
    ],
}


class AdaptiveDeceptionAdapter:
    """
    Adapts honeypot behavior based on attacker sophistication.

    Integrates with the SophisticationClassifier to dynamically adjust
    interaction depth, AI personality, breadcrumb planting, and SOC alerting.
    """

    def __init__(
        self,
        enabled: Optional[bool] = None,
        classifier: Optional[SophisticationClassifier] = None,
        profiles: Optional[Dict[SophisticationLevel, InteractionProfile]] = None,
        on_soc_alert: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        on_level_change: Optional[Callable[[SophisticationLevel, SophisticationLevel], None]] = None,
    ):
        if enabled is not None:
            self.enabled = enabled
        else:
            self.enabled = os.environ.get("AI_ADAPTIVE_ENABLED", "true").lower() == "true"

        self.classifier = classifier or SophisticationClassifier()
        self.profiles = profiles or dict(DEFAULT_PROFILES)
        self.on_soc_alert = on_soc_alert
        self.on_level_change = on_level_change

        self._current_level: Optional[SophisticationLevel] = None
        self._soc_alerted = False
        self._breadcrumbs_planted: List[Dict[str, str]] = []
        self._session_start = time.time()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_command(self, command: str, client_ip: str = "") -> InteractionProfile:
        """
        Process a command and return the appropriate interaction profile.

        Args:
            command: The attacker's command
            client_ip: Source IP for alerting

        Returns:
            InteractionProfile for current sophistication level
        """
        if not self.enabled:
            return self.profiles[SophisticationLevel.SKILLED]

        # Update classification
        classification = self.classifier.add_command(command)
        new_level = classification.level

        # Check for level change
        if self._current_level is not None and new_level != self._current_level:
            if self.on_level_change:
                try:
                    self.on_level_change(self._current_level, new_level)
                except Exception:
                    pass

        self._current_level = new_level

        # Get profile
        profile = self.profiles.get(new_level, self.profiles[SophisticationLevel.SKILLED])

        # SOC alert for advanced+ attackers
        if profile.alert_soc and not self._soc_alerted:
            self._alert_soc(classification, client_ip)
            self._soc_alerted = True

        return profile

    def get_classification(self) -> Classification:
        """Get the current attacker classification."""
        return self.classifier.get_classification()

    def get_current_profile(self) -> InteractionProfile:
        """Get the current interaction profile."""
        if self._current_level is None:
            return self.profiles[SophisticationLevel.AUTOMATED]
        return self.profiles.get(self._current_level, self.profiles[SophisticationLevel.SKILLED])

    def get_breadcrumbs(self) -> List[Dict[str, str]]:
        """Get breadcrumbs appropriate for the current sophistication level."""
        profile = self.get_current_profile()
        level = profile.breadcrumb_level

        available = []
        for l in range(1, level + 1):
            available.extend(BREADCRUMBS.get(l, []))

        # Don't repeat breadcrumbs
        new_crumbs = [
            b for b in available
            if b not in self._breadcrumbs_planted
        ]

        return new_crumbs

    def plant_breadcrumb(self, breadcrumb: Dict[str, str]):
        """Record that a breadcrumb has been planted."""
        self._breadcrumbs_planted.append(breadcrumb)

    def get_session_summary(self) -> Dict[str, Any]:
        """Get a summary of the adaptive deception session."""
        classification = self.get_classification()
        return {
            "duration_seconds": round(time.time() - self._session_start, 1),
            "classification": classification.to_dict(),
            "current_profile": self.get_current_profile().description,
            "breadcrumbs_planted": len(self._breadcrumbs_planted),
            "soc_alerted": self._soc_alerted,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _alert_soc(self, classification: Classification, client_ip: str):
        """Send an alert to the SOC team."""
        alert_on_advanced = os.environ.get("AI_ALERT_ON_ADVANCED", "true").lower() == "true"
        if not alert_on_advanced:
            return

        if self.on_soc_alert:
            try:
                self.on_soc_alert(
                    "advanced_attacker_detected",
                    {
                        "client_ip": client_ip,
                        "classification": classification.to_dict(),
                        "session_duration": round(time.time() - self._session_start, 1),
                        "message": (
                            f"Advanced attacker detected (level={classification.level.value}, "
                            f"score={classification.score:.2f}). "
                            f"Engaging with maximum deception."
                        ),
                    },
                )
            except Exception:
                pass
