# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
LLMLayer: couche interprétative optionnelle.

Le LLM intervient uniquement pour :
1. Désambiguïser un SemanticDiff au verdict AMBIGUOUS
2. Proposer des hypothèses complémentaires
3. Interpréter du JavaScript obfusqué
4. Générer les remediation_hints contextuels
5. Générer le résumé exécutif du rapport

Activation : variable d'environnement ANTHROPIC_API_KEY.
Sans clé API, create_llm_layer() retourne None silencieusement.

Contrainte (ADR-002) : toute sortie LLM est taguée source="llm" et
n'est jamais utilisée comme preuve exclusive dans un Finding.
Le LLM ne peut PAS retourner CONFIRMED — seulement AMBIGUOUS ou REFUTED.
"""
from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import structlog

from hdwp.core.oracle.violation_oracle import ViolationAssessment, ViolationVerdict

if TYPE_CHECKING:
    from hdwp.core.context.config_schema import LLMConfig
    from hdwp.core.model.schemas import ApplicationModelData, Finding, SemanticDiff

log = structlog.get_logger()


class LLMLayerProtocol(ABC):
    """Interface abstraite pour la couche LLM."""

    @abstractmethod
    async def disambiguate_diff(
        self,
        diff: SemanticDiff,
        mutation_type: str,
        baseline_body: object,
        experiment_body: object,
    ) -> ViolationAssessment | None:
        """
        Analyse sémantiquement un diff AMBIGUOUS.

        Retourne None si le LLM ne peut pas conclure.
        Ne retourne JAMAIS ViolationVerdict.CONFIRMED — seulement AMBIGUOUS ou REFUTED.
        """
        ...

    @abstractmethod
    async def generate_remediation_hint(self, finding: Finding) -> str:
        """
        Génère un conseil de remédiation contextuel pour un finding.
        Retourne le hint existant en cas d'erreur (fallback).
        """
        ...

    @abstractmethod
    async def generate_executive_summary(
        self, findings: list[Finding], target: str
    ) -> str:
        """
        Génère le résumé exécutif du rapport (3-4 phrases, ton professionnel).
        Retourne un résumé statistique en cas d'erreur (fallback).
        """
        ...

    @abstractmethod
    async def interpret_js(self, source: str) -> list[str]:
        """
        Extrait les endpoints/routes depuis du JavaScript obfusqué ou minifié.
        Retourne une liste de chemins URL détectés. Retourne [] en cas d'erreur.
        """
        ...

    @abstractmethod
    async def propose_hypotheses(
        self, model: ApplicationModelData, existing_count: int
    ) -> list[str]:
        """
        Propose des hypothèses complémentaires depuis le modèle.
        Retourne une liste d'énoncés falsifiables (pas de Hypothesis directement).
        Retourne [] en cas d'erreur.
        """
        ...

    @abstractmethod
    async def generate_exploit_context(self, finding: Finding) -> dict:
        """
        Analyse contextuelle de la vulnérabilité. ADR-002 : informatif uniquement.
        Retourne {explanation: str, alternative_payloads: list[str]}.
        Le résultat n'est JAMAIS utilisé comme preuve ou verdict.
        """
        ...

    @abstractmethod
    async def propose_invariants(
        self,
        model: ApplicationModelData,
        response_corpus: dict[str, dict[str, list[dict]]],
    ) -> list[str]:
        """
        V3: Propose des invariants candidats depuis le modèle et le corpus de réponses.
        Les propositions sont soumises à InvariantStore pour validation déterministe (ADR-002).
        Retourne une liste d'énoncés formels. Retourne [] en cas d'erreur.
        """
        ...


class AnthropicLLMLayer(LLMLayerProtocol):
    """Implémentation Anthropic de la couche LLM."""

    MODEL = "claude-sonnet-4-6"

    def __init__(self, api_key: str, model: str = MODEL) -> None:
        import anthropic
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    async def disambiguate_diff(
        self,
        diff: SemanticDiff,
        mutation_type: str,
        baseline_body: object,
        experiment_body: object,
    ) -> ViolationAssessment | None:
        prompt = _build_disambiguation_prompt(diff, mutation_type, baseline_body, experiment_body)
        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text.strip().lower()
            result = _parse_llm_verdict(text)
            log.debug("llm.disambiguation_result", verdict=result.verdict.value, text=text[:50])
            return result
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.disambiguation_failed", error=str(exc))
            return None

    async def generate_remediation_hint(self, finding: Finding) -> str:
        endpoint = finding.affected_endpoints[0] if finding.affected_endpoints else "inconnu"
        steps = finding.proof.get("reproduction_steps", [""])
        first_step = steps[0] if steps else ""
        prompt = (
            "Tu es un expert en sécurité applicative.\n"
            "Génère un conseil de remédiation concis (2-3 phrases) pour cette vulnérabilité :\n\n"
            f"Type : {finding.owasp_category} / {finding.cwe_id}\n"
            f"Sévérité : {finding.severity}\n"
            f"Endpoint : {endpoint}\n"
            f"Description : {first_step}\n\n"
            "Conseil technique précis, orienté développeur. Pas de généralités."
        )
        try:
            resp = await self._client.messages.create(
                model=self._model,
                max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text.strip()
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.remediation_hint_failed", error=str(exc))
            return finding.remediation_hint

    async def generate_executive_summary(
        self, findings: list[Finding], target: str
    ) -> str:
        if not findings:
            return f"L'analyse de {target} n'a révélé aucun finding confirmé."

        by_severity: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        findings_text = "\n".join(
            f"- [{f.severity}] {f.owasp_category}/{f.cwe_id} sur "
            f"{f.affected_endpoints[0] if f.affected_endpoints else 'inconnu'}"
            for f in findings[:10]
        )
        prompt = (
            "Tu es un consultant en sécurité rédigeant un résumé exécutif.\n"
            f"Cible : {target}\n"
            f"Findings :\n{findings_text}\n"
            f"Compteurs : {by_severity}\n\n"
            "Résumé exécutif en 3-4 phrases, ton professionnel, orienté business.\n"
            "Commence par le constat général, puis le risque principal, puis la recommandation prioritaire.\n"
            "Pas de jargon technique excessif — ce résumé est pour un RSSI ou un directeur technique."
        )
        try:
            resp = await self._client.messages.create(
                model=self._model,
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text.strip()
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.executive_summary_failed", error=str(exc))
            by_str = ", ".join(f"{k}: {v}" for k, v in sorted(by_severity.items()))
            return f"L'analyse de {target} a révélé {len(findings)} finding(s) : {by_str}."

    async def interpret_js(self, source: str) -> list[str]:
        truncated = source[:3000]
        prompt = (
            "Analyse ce code JavaScript et extrais uniquement les chemins d'URL d'API (format /api/...).\n"
            'Retourne une liste JSON de strings, rien d\'autre. Exemple : ["/api/users", "/api/orders/{id}"]\n\n'
            f"JavaScript :\n{truncated}\n\n"
            "Réponds UNIQUEMENT avec un tableau JSON valide. Si aucun endpoint trouvé, réponds []."
        )
        try:
            resp = await self._client.messages.create(
                model=self._model,
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}],
            )
            import json
            text = resp.content[0].text.strip()
            match = re.search(r"\[.*\]", text, re.DOTALL)
            if match:
                return json.loads(match.group())
            return []
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.interpret_js_failed", error=str(exc))
            return []

    async def propose_hypotheses(
        self, model: ApplicationModelData, existing_count: int
    ) -> list[str]:
        endpoints_summary = [
            f"{ep.path} [{', '.join(ep.methods)}]" for ep in model.endpoints[:10]
        ]
        params_summary = [
            f"{p.name} ({p.location}, {p.type_inferred})" for p in model.parameters[:10]
        ]
        prompt = (
            "Tu es un expert en sécurité applicative analysant un modèle d'application web.\n\n"
            f"Endpoints observés : {endpoints_summary}\n"
            f"Paramètres observés : {params_summary}\n"
            f"Rôles : {[r.name for r in model.roles]}\n"
            f"Nombre d'hypothèses déjà générées : {existing_count}\n\n"
            "Propose 3 hypothèses de sécurité complémentaires non encore couvertes.\n"
            "Format : une hypothèse par ligne, commençant par 'Il est possible que...'\n"
            "Ne répète pas les hypothèses BOLA/AuthZ standard si déjà couvertes.\n"
            "Focus sur les patterns business logic et les interactions inter-paramètres."
        )
        try:
            resp = await self._client.messages.create(
                model=self._model,
                max_tokens=400,
                messages=[{"role": "user", "content": prompt}],
            )
            lines = resp.content[0].text.strip().split("\n")
            return [
                line.strip()
                for line in lines
                if line.strip().startswith("Il est possible")
            ][:3]
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.propose_hypotheses_failed", error=str(exc))
            return []

    async def generate_exploit_context(self, finding: Finding) -> dict:
        endpoint = finding.affected_endpoints[0] if finding.affected_endpoints else "inconnu"
        prompt = (
            "You are a security researcher providing INFORMATIONAL analysis only. "
            "This output will NOT be used as security evidence (ADR-002).\n\n"
            f"Vulnerability: {finding.cwe_id} — {finding.owasp_category}\n"
            f"Severity: {finding.severity}\n"
            f"Affected: {endpoint}\n"
            f"Remediation hint: {finding.remediation_hint}\n\n"
            "Provide: 1) A 2-sentence explanation of this vulnerability class. "
            "2) 2-3 alternative payload variations for testing (informational only). "
            'Format as JSON: {"explanation": "...", "alternative_payloads": [...]}'
        )
        try:
            import json as _json
            resp = await self._client.messages.create(
                model=self._model,
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = resp.content[0].text.strip()
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return _json.loads(raw[start:end])
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.exploit_context_failed", error=str(exc))
        return {"explanation": finding.remediation_hint, "alternative_payloads": []}

    async def propose_invariants(
        self,
        model: ApplicationModelData,
        response_corpus: dict[str, dict[str, list[dict]]],
    ) -> list[str]:
        endpoints_summary = [f"{ep.path} [{', '.join(ep.methods)}] roles={ep.roles_observed}" for ep in model.endpoints[:8]]
        corpus_sample = {k: list(v.keys()) for k, v in list(response_corpus.items())[:5]}
        prompt = (
            "Tu es un expert en sécurité applicative. "
            "Analyse le modèle et propose des invariants de sécurité.\n\n"
            f"Endpoints : {endpoints_summary}\n"
            f"Rôles : {[r.name for r in model.roles]}\n"
            f"Corpus de réponses (endpoint → rôles) : {corpus_sample}\n\n"
            "Propose 3-5 invariants formels, un par ligne. Format :\n"
            "- owner_id in response == authenticated_user_id for /api/resource/{id}\n"
            "- status_code == 403 for anonymous on /api/admin/*\n"
            "- field 'balance' absent for role 'user' on /api/accounts/{id}\n\n"
            "Uniquement des invariants vérifiables automatiquement. "
            "ADR-002 : ces propositions seront validées par un oracle déterministe."
        )
        try:
            resp = await self._client.messages.create(
                model=self._model,
                max_tokens=400,
                messages=[{"role": "user", "content": prompt}],
            )
            lines = resp.content[0].text.strip().split("\n")
            return [ln.lstrip("- ").strip() for ln in lines if ln.strip() and not ln.startswith("#")][:5]
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.propose_invariants_failed", error=str(exc))
            return []


class OpenAICompatibleLLMLayer(LLMLayerProtocol):
    """
    Provider compatible API OpenAI : OpenAI, Ollama, LM Studio, vLLM, Together, Groq.

    Pour Ollama local, passer base_url="http://localhost:11434/v1".
    La clé API est optionnelle pour les providers locaux.
    """

    def __init__(self, api_key: str, model: str, base_url: str | None = None) -> None:
        try:
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=api_key or "none", base_url=base_url)
        except ImportError as exc:
            raise RuntimeError(
                "openai package requis : pip install hdwp[llm]"
            ) from exc
        self._model = model

    async def disambiguate_diff(
        self,
        diff: SemanticDiff,
        mutation_type: str,
        baseline_body: object,
        experiment_body: object,
    ) -> ViolationAssessment | None:
        prompt = _build_disambiguation_prompt(diff, mutation_type, baseline_body, experiment_body)
        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            text = (response.choices[0].message.content or "").strip().lower()
            result = _parse_llm_verdict(text)
            log.debug("llm.disambiguation_result", verdict=result.verdict.value, text=text[:50])
            return result
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.disambiguation_failed", error=str(exc))
            return None

    async def generate_remediation_hint(self, finding: Finding) -> str:
        endpoint = finding.affected_endpoints[0] if finding.affected_endpoints else "inconnu"
        steps = finding.proof.get("reproduction_steps", [""])
        first_step = steps[0] if steps else ""
        prompt = (
            "Tu es un expert en sécurité applicative.\n"
            "Génère un conseil de remédiation concis (2-3 phrases) pour cette vulnérabilité :\n\n"
            f"Type : {finding.owasp_category} / {finding.cwe_id}\n"
            f"Sévérité : {finding.severity}\nEndpoint : {endpoint}\nDescription : {first_step}\n\n"
            "Conseil technique précis, orienté développeur. Pas de généralités."
        )
        try:
            resp = await self._client.chat.completions.create(
                model=self._model, max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
            )
            return (resp.choices[0].message.content or "").strip()
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.remediation_hint_failed", error=str(exc))
            return finding.remediation_hint

    async def generate_executive_summary(self, findings: list[Finding], target: str) -> str:
        if not findings:
            return f"L'analyse de {target} n'a révélé aucun finding confirmé."
        by_severity: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        findings_text = "\n".join(
            f"- [{f.severity}] {f.owasp_category}/{f.cwe_id} sur "
            f"{f.affected_endpoints[0] if f.affected_endpoints else 'inconnu'}"
            for f in findings[:10]
        )
        prompt = (
            f"Cible : {target}\nFindings :\n{findings_text}\nCompteurs : {by_severity}\n\n"
            "Résumé exécutif 3-4 phrases, ton professionnel, orienté business. "
            "Constat général, risque principal, recommandation prioritaire."
        )
        try:
            resp = await self._client.chat.completions.create(
                model=self._model, max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            return (resp.choices[0].message.content or "").strip()
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.executive_summary_failed", error=str(exc))
            by_str = ", ".join(f"{k}: {v}" for k, v in sorted(by_severity.items()))
            return f"L'analyse de {target} a révélé {len(findings)} finding(s) : {by_str}."

    async def interpret_js(self, source: str) -> list[str]:
        prompt = (
            "Extrais les chemins d'URL d'API depuis ce JavaScript.\n"
            'Retourne UNIQUEMENT un tableau JSON. Exemple : ["/api/users"]\n\n'
            f"JavaScript :\n{source[:3000]}\n\nRéponds [] si aucun endpoint."
        )
        try:
            resp = await self._client.chat.completions.create(
                model=self._model, max_tokens=500,
                messages=[{"role": "user", "content": prompt}],
            )
            import json
            text = (resp.choices[0].message.content or "").strip()
            match = re.search(r"\[.*\]", text, re.DOTALL)
            if match:
                return json.loads(match.group())
            return []
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.interpret_js_failed", error=str(exc))
            return []

    async def propose_hypotheses(
        self, model: ApplicationModelData, existing_count: int
    ) -> list[str]:
        endpoints_summary = [f"{ep.path} [{', '.join(ep.methods)}]" for ep in model.endpoints[:10]]
        params_summary = [f"{p.name} ({p.location}, {p.type_inferred})" for p in model.parameters[:10]]
        prompt = (
            f"Endpoints : {endpoints_summary}\nParamètres : {params_summary}\n"
            f"Rôles : {[r.name for r in model.roles]}\nHypothèses existantes : {existing_count}\n\n"
            "Propose 3 hypothèses complémentaires, une par ligne, "
            "commençant par 'Il est possible que...'"
        )
        try:
            resp = await self._client.chat.completions.create(
                model=self._model, max_tokens=400,
                messages=[{"role": "user", "content": prompt}],
            )
            lines = (resp.choices[0].message.content or "").strip().split("\n")
            return [ln.strip() for ln in lines if ln.strip().startswith("Il est possible")][:3]
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.propose_hypotheses_failed", error=str(exc))
            return []

    async def generate_exploit_context(self, finding: Finding) -> dict:
        endpoint = finding.affected_endpoints[0] if finding.affected_endpoints else "inconnu"
        prompt = (
            "You are a security researcher providing INFORMATIONAL analysis only. "
            "This output will NOT be used as security evidence (ADR-002).\n\n"
            f"Vulnerability: {finding.cwe_id} — {finding.owasp_category}\n"
            f"Severity: {finding.severity}\nAffected: {endpoint}\n"
            f"Remediation hint: {finding.remediation_hint}\n\n"
            "Provide: 1) A 2-sentence explanation. 2) 2-3 alternative payload variations. "
            'Format: {"explanation": "...", "alternative_payloads": [...]}'
        )
        try:
            import json as _json
            resp = await self._client.chat.completions.create(
                model=self._model, max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = (resp.choices[0].message.content or "").strip()
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return _json.loads(raw[start:end])
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.exploit_context_failed", error=str(exc))
        return {"explanation": finding.remediation_hint, "alternative_payloads": []}

    async def propose_invariants(
        self,
        model: ApplicationModelData,
        response_corpus: dict[str, dict[str, list[dict]]],
    ) -> list[str]:
        endpoints_summary = [f"{ep.path} [{', '.join(ep.methods)}] roles={ep.roles_observed}" for ep in model.endpoints[:8]]
        corpus_sample = {k: list(v.keys()) for k, v in list(response_corpus.items())[:5]}
        prompt = (
            "Analyse le modèle et propose des invariants de sécurité.\n\n"
            f"Endpoints : {endpoints_summary}\n"
            f"Rôles : {[r.name for r in model.roles]}\n"
            f"Corpus : {corpus_sample}\n\n"
            "Propose 3-5 invariants formels, un par ligne (format: condition for context). "
            "ADR-002 : propositions validées par oracle déterministe."
        )
        try:
            resp = await self._client.chat.completions.create(
                model=self._model, max_tokens=400,
                messages=[{"role": "user", "content": prompt}],
            )
            lines = (resp.choices[0].message.content or "").strip().split("\n")
            return [ln.lstrip("- ").strip() for ln in lines if ln.strip() and not ln.startswith("#")][:5]
        except Exception as exc:  # noqa: BLE001
            log.warning("llm.propose_invariants_failed", error=str(exc))
            return []


def _build_disambiguation_prompt(
    diff: SemanticDiff,
    mutation_type: str,
    baseline_body: object,
    experiment_body: object,
) -> str:
    return (
        "Tu es un expert en sécurité applicative web analysant un diff de réponses HTTP.\n\n"
        f"Type de mutation testée : {mutation_type}\n"
        "- identity_swap : même requête, credentials différents\n"
        "- object_ref_change : même credentials, ID d'objet différent\n"
        "- privilege_escalation : accès endpoint restreint avec rôle non-autorisé\n"
        "- field_injection : payload injecté dans un paramètre\n\n"
        f"Réponse de référence (légitime) :\n{str(baseline_body)[:500]}\n\n"
        f"Réponse expérimentale (après mutation) :\n{str(experiment_body)[:500]}\n\n"
        f"Différences observées : {diff.verdict_rationale}\n"
        f"Similarité structurelle : {diff.body_similarity:.0%}\n"
        f"Champs inattendus : {diff.leaked_fields}\n\n"
        "QUESTION : Cette différence indique-t-elle une violation de sécurité ?\n"
        "Réponds UNIQUEMENT par : VIOLATION ou PAS_DE_VIOLATION ou INCERTAIN\n\n"
        "Ne fournis aucune explication. Un seul mot parmi ces trois."
    )


def _parse_llm_verdict(text: str) -> ViolationAssessment:
    """
    Interprète la réponse LLM en ViolationAssessment.

    Invariant : ne retourne JAMAIS ViolationVerdict.CONFIRMED (ADR-002).
    """
    text_lower = text.lower()
    if "pas_de_violation" in text_lower or "pas de violation" in text_lower:
        return ViolationAssessment(
            verdict=ViolationVerdict.REFUTED,
            rationale="LLM (source:llm) : pas de violation détectée sémantiquement",
            confidence_hint=0.6,
        )
    if "violation" in text_lower:
        return ViolationAssessment(
            verdict=ViolationVerdict.AMBIGUOUS,  # Jamais CONFIRMED
            rationale="LLM (source:llm) suggère une violation probable — validation empirique requise",
            confidence_hint=0.55,  # Sous le seuil CONFIRMED (0.85)
        )
    return ViolationAssessment(
        verdict=ViolationVerdict.INSUFFICIENT,
        rationale="LLM (source:llm) : incertain",
        confidence_hint=0.2,
    )


def create_llm_layer(
    config: LLMConfig | None = None,
) -> LLMLayerProtocol | None:
    """
    Crée une LLMLayer depuis la configuration ou les variables d'environnement.

    Résolution de la clé API (par ordre de priorité) :
      1. Env var standard du provider : ANTHROPIC_API_KEY, OPENAI_API_KEY
      2. Env var générique : HDWP_LLM_API_KEY
      3. Pour Ollama local : aucune clé requise

    Rétrocompatibilité : si config=None et ANTHROPIC_API_KEY est définie → Anthropic.
    """

    if config is None or not config.enabled:
        # Rétrocompatibilité legacy — ANTHROPIC_API_KEY sans section llm: dans le YAML
        key = os.environ.get("ANTHROPIC_API_KEY")
        if key:
            try:
                import anthropic
                return AnthropicLLMLayer(api_key=key)
            except ImportError:
                log.warning("llm.disabled", reason="anthropic not installed")
        return None

    match config.provider:
        case "anthropic":
            key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("HDWP_LLM_API_KEY", "")
            if not key:
                log.warning("llm.no_api_key", provider="anthropic", hint="Set ANTHROPIC_API_KEY")
                return None
            try:
                import anthropic  # noqa: F401
                return AnthropicLLMLayer(api_key=key, model=config.model)
            except ImportError:
                log.warning("llm.disabled", reason="anthropic not installed — pip install hdwp[llm]")
                return None

        case "openai":
            key = os.environ.get("OPENAI_API_KEY") or os.environ.get("HDWP_LLM_API_KEY", "")
            if not key:
                log.warning("llm.no_api_key", provider="openai", hint="Set OPENAI_API_KEY")
                return None
            return OpenAICompatibleLLMLayer(key, model=config.model, base_url=config.base_url)

        case "ollama":
            base = config.base_url or "http://localhost:11434/v1"
            return OpenAICompatibleLLMLayer("none", model=config.model, base_url=base)

        case _:
            log.warning("llm.unknown_provider", provider=config.provider)
            return None
