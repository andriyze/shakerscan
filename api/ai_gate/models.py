from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProbeTurnTemplate:
    message: str
    role: str = "attacker"


@dataclass(frozen=True)
class Probe:
    id: str
    family: str
    title: str
    prompt: str
    owasp: str | None = None
    minimum_profile: str = "smoke"
    technique: str | None = None
    source_name: str | None = None
    source_reference: str | None = None
    tactics: tuple[str, ...] = field(default_factory=tuple)
    expected_safe_behavior: str | None = None
    expected_attack_success: str | None = None
    severity_if_success: str | None = None
    turns: tuple[ProbeTurnTemplate, ...] = field(default_factory=tuple)
    max_turns: int = 1
    requires_state: bool = False
    requires_fresh_session: bool = False
    safe_for_production: bool = True

    def with_default_turns(self) -> "Probe":
        if self.turns:
            return self
        return Probe(
            id=self.id,
            family=self.family,
            title=self.title,
            prompt=self.prompt,
            owasp=self.owasp,
            minimum_profile=self.minimum_profile,
            technique=self.technique,
            source_name=self.source_name,
            source_reference=self.source_reference,
            tactics=self.tactics,
            expected_safe_behavior=self.expected_safe_behavior,
            expected_attack_success=self.expected_attack_success,
            severity_if_success=self.severity_if_success,
            turns=(ProbeTurnTemplate(message=self.prompt),),
            max_turns=self.max_turns,
            requires_state=self.requires_state,
            requires_fresh_session=self.requires_fresh_session,
            safe_for_production=self.safe_for_production,
        )

    @property
    def conversation_turns(self) -> tuple[ProbeTurnTemplate, ...]:
        return self.with_default_turns().turns

    def to_legacy_dict(self) -> dict[str, str]:
        payload = {
            "id": self.id,
            "family": self.family,
            "title": self.title,
            "prompt": self.prompt,
        }
        if self.owasp:
            payload["owasp"] = self.owasp
        if self.technique:
            payload["technique"] = self.technique
        if self.source_name:
            payload["source_name"] = self.source_name
        return payload
