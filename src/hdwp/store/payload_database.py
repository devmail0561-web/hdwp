# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Payload Database : système de gestion centralisé des payloads externalisés.

Architecture thread-safe utilisant frozen dataclasses pour garantir l'immutabilité
et permettre l'usage concurrent par plusieurs plugins simultanément.

Sources de chargement (priorité décroissante) :
1. User overrides: ~/.hdwp/payloads/
2. Built-in payloads: src/hdwp/core/payloads/payloads/
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PayloadVariant:
    """Variante de payload immutable (thread-safe).

    Attributes:
        id: Identifiant unique de la variante (ex: union_basic, time_based_mysql)
        value: Valeur du payload (str pour texte brut, dict pour JSON injection)
        tech_stack: Liste des tech stacks compatibles (ex: [mysql, mariadb])
        expected_result: Résultat attendu pour validation (optionnel)
        confidence_boost: Boost de confiance si ce payload réussit
        detection: Condition de détection spécifique (ex: timing_delta > 4000)
        encoding_chains: Liste des chaînes d'encoding à appliquer
        obfuscation_techniques: Liste des techniques d'obfuscation
    """
    id: str
    value: str | dict
    tech_stack: tuple[str, ...] = field(default_factory=tuple)
    expected_result: str | None = None
    confidence_boost: float = 0.0
    detection: str | None = None
    encoding_chains: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
    obfuscation_techniques: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class PayloadDefinition:
    """Définition complète d'un fichier de payloads.

    Attributes:
        plugin_id: ID du plugin cible (ex: core.injection.sqli)
        mutation_type: Type de mutation (ex: field_injection)
        payload_type: Type de payload (ex: sqli, xss)
        variants: Liste des variantes de payloads
        keywords: Mots-clés pour identifier paramètres candidats
    """
    plugin_id: str
    mutation_type: str
    payload_type: str
    variants: tuple[PayloadVariant, ...]
    keywords: tuple[str, ...] = field(default_factory=tuple)


class PayloadDatabase:
    """Singleton thread-safe pour gestion centralisée des payloads.

    Chargement au démarrage depuis YAML, cache en mémoire, accès lecture-seule.
    Aucune mutation après chargement → thread-safe par design.
    """

    _instance: PayloadDatabase | None = None
    _lock = threading.Lock()  # Phase 0.1: Thread-safe singleton

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    @classmethod
    def reset_for_testing(cls) -> None:
        global _global_payload_db
        with cls._lock:
            cls._instance = None
            _global_payload_db = None

    def __init__(self):
        if self._initialized:
            return

        self._payloads: dict[str, PayloadDefinition] = {}
        self._initialized = True
        logger.debug("PayloadDatabase singleton initialized")

    def load_all(self, builtin_dir: Path | None = None, user_dir: Path | None = None) -> None:
        """Charge tous les YAML depuis les répertoires de payloads.

        Args:
            builtin_dir: Répertoire des payloads built-in (défaut: src/hdwp/core/payloads/payloads/)
            user_dir: Répertoire des overrides utilisateur (défaut: ~/.hdwp/payloads/)

        Priorité: user_dir > builtin_dir (les overrides écrasent les built-in)
        """
        # Idempotence : réinitialiser avant rechargement pour éviter les entrées périmées
        self._payloads.clear()

        if builtin_dir is None:
            # Détecter le répertoire built-in relatif au module
            module_path = Path(__file__).parent.parent
            builtin_dir = module_path / "core" / "payloads" / "payloads"

        if user_dir is None:
            user_dir = Path.home() / ".hdwp" / "payloads"

        # Charger built-in d'abord
        if builtin_dir.exists():
            self._load_from_directory(builtin_dir, source="builtin")
        else:
            logger.warning(f"Built-in payload directory not found: {builtin_dir}")

        # Charger overrides utilisateur (écrasent les built-in)
        if user_dir.exists():
            self._load_from_directory(user_dir, source="user")
            logger.info(f"Loaded user payload overrides from {user_dir}")

    def _load_from_directory(self, directory: Path, source: str) -> None:
        """Charge tous les fichiers YAML d'un répertoire."""
        yaml_files = list(directory.glob("*.yaml")) + list(directory.glob("*.yml"))

        for yaml_file in yaml_files:
            try:
                self._load_payload_file(yaml_file, source)
            except Exception as e:
                # Phase 0.1: Log mais continue (graceful degradation)
                logger.error(f"Failed to load {yaml_file} from {source}: {e}")

    def _load_payload_file(self, file_path: Path, source: str) -> None:
        """Charge un fichier YAML de payloads."""
        # Phase 0.1: Explicit YAML error handling
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.error(f"YAML syntax error in {file_path}: {e}")
            return
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return

        if not data or not isinstance(data, dict):
            logger.warning(f"Empty or invalid YAML structure in {file_path}")
            return

        # Phase 0.1: Schema validation
        plugin_id = data.get("plugin_id")
        if not plugin_id:
            logger.error(f"Missing required field 'plugin_id' in {file_path}")
            return

        if "variants" not in data:
            logger.error(f"Missing required field 'variants' in {file_path}")
            return

        # Parser les variantes
        variants = []
        for variant_data in data.get("variants", []):
            variant = self._parse_variant(variant_data)
            if variant:
                variants.append(variant)

        # Créer la définition
        definition = PayloadDefinition(
            plugin_id=plugin_id,
            mutation_type=data.get("mutation_type", "field_injection"),
            payload_type=data.get("payload_type", "generic"),
            variants=tuple(variants),
            keywords=tuple(data.get("keywords", []))
        )

        self._payloads[plugin_id] = definition
        logger.debug(f"Loaded {len(variants)} variants for {plugin_id} from {source}")

    def _parse_variant(self, data: dict[str, Any]) -> PayloadVariant | None:
        """Parse une variante de payload depuis YAML."""
        if not data.get("id"):
            logger.warning(f"Variant missing 'id' field: {data}")
            return None

        payloads = data.get("payloads", [])
        if not payloads:
            logger.warning(f"Variant {data['id']} has no payloads")
            return None

        # Pour l'instant, on prend le premier payload de la liste
        # TODO Phase 1 : générer toutes les variantes
        first_payload = payloads[0]

        # Parser encoding_chains
        encoding_chains = []
        auto_variants = data.get("auto_variants", {})
        if auto_variants:
            for chain in auto_variants.get("encoding_chains", []):
                encoding_chains.append(tuple(chain) if isinstance(chain, list) else (chain,))

        return PayloadVariant(
            id=data["id"],
            value=first_payload,
            tech_stack=tuple(data.get("tech_stack", [])),
            expected_result=data.get("expected_result"),
            confidence_boost=data.get("confidence_boost", 0.0),
            detection=data.get("detection"),
            encoding_chains=tuple(encoding_chains),
            obfuscation_techniques=tuple(auto_variants.get("obfuscation", []))
        )

    def get_payloads(
        self,
        plugin_id: str,
        tech_stack: list[str] | None = None,
        encoding: list[str] | None = None,
        auto_encode: bool = False,       # Phase 1: NOUVEAU
        auto_obfuscate: bool = False,    # Phase 1: NOUVEAU
        max_variants: int = 20,          # Phase 1: NOUVEAU
    ) -> list[PayloadVariant]:
        """Retourne les variantes de payloads pour un plugin.

        Args:
            plugin_id: ID du plugin (ex: core.injection.sqli)
            tech_stack: Filtrer par tech stack (ex: [mysql, mariadb])
            encoding: Filtrer par encodings (legacy, non utilisé)
            auto_encode: Générer variantes encodées automatiquement (Phase 1)
            auto_obfuscate: Générer variantes obfusquées automatiquement (Phase 1)
            max_variants: Limite max de variantes par payload (Phase 1)

        Returns:
            Liste des PayloadVariant (JAMAIS None, retourne [] si non trouvé)
        """
        definition = self._payloads.get(plugin_id)
        if not definition:
            logger.debug(f"No payloads found for plugin {plugin_id}")
            return []

        variants = list(definition.variants)

        # Filtrer par tech_stack si fourni
        if tech_stack:
            tech_stack_set = set(tech_stack)
            variants = [
                v for v in variants
                if not v.tech_stack or tech_stack_set.intersection(v.tech_stack)
            ]

        # Phase 1: Génération auto-variants si activée
        if auto_encode or auto_obfuscate:
            expanded_variants = []
            for variant in variants:
                # Ajouter variante originale
                expanded_variants.append(variant)

                # Générer variantes encodées
                if auto_encode and variant.encoding_chains:
                    expanded_variants.extend(
                        self._generate_encoded_variants(variant, max_variants)
                    )

                # Générer variantes obfusquées
                if auto_obfuscate and variant.obfuscation_techniques:
                    expanded_variants.extend(
                        self._generate_obfuscated_variants(variant, definition.payload_type, max_variants)
                    )

            # Pas de cap globale ici : _generate_encoded_variants et _generate_obfuscated_variants
            # capent déjà individuellement à max_variants. Une slice ici tronquerait les variantes
            # obfusquées quand auto_encode ET auto_obfuscate sont actifs simultanément.
            return expanded_variants

        return variants

    def _generate_encoded_variants(
        self,
        variant: PayloadVariant,
        max_variants: int,
    ) -> list[PayloadVariant]:
        """Génère variantes encodées depuis encoding_chains.

        Args:
            variant: Variante de payload originale
            max_variants: Limite max de variantes

        Returns:
            Liste de PayloadVariant avec valeurs encodées
        """
        from hdwp.core.experiment.encoder_registry import get_encoder_registry

        registry = get_encoder_registry()
        encoded_variants = []

        for chain in variant.encoding_chains[:max_variants]:
            try:
                encoded_value = registry.apply_chain(str(variant.value), list(chain))

                # Créer nouvelle PayloadVariant avec valeur encodée
                encoded_variant = PayloadVariant(
                    id=f"{variant.id}_encoded_{'_'.join(chain)}",
                    value=encoded_value,
                    tech_stack=variant.tech_stack,
                    expected_result=variant.expected_result,
                    confidence_boost=variant.confidence_boost + 0.05,  # Boost encoding bypass
                    detection=variant.detection,
                    encoding_chains=tuple(),  # Déjà appliqué
                    obfuscation_techniques=variant.obfuscation_techniques,
                )
                encoded_variants.append(encoded_variant)
            except Exception as exc:
                logger.debug(f"Failed to encode variant {variant.id} with chain {chain}: {exc}")
                continue

        return encoded_variants

    def _generate_obfuscated_variants(
        self,
        variant: PayloadVariant,
        payload_type: str,
        max_variants: int,
    ) -> list[PayloadVariant]:
        """Génère variantes obfusquées depuis obfuscation_techniques.

        Args:
            variant: Variante de payload originale
            payload_type: Type de payload (sqli, cmdi, xss)
            max_variants: Limite max de variantes

        Returns:
            Liste de PayloadVariant avec valeurs obfusquées
        """
        from hdwp.core.payloads.obfuscation.obfuscator_registry import get_obfuscator_registry

        registry = get_obfuscator_registry()
        obfuscated_variants = []

        for technique_name in variant.obfuscation_techniques[:max_variants]:
            try:
                obfuscated_value = registry.obfuscate(str(variant.value), technique_name)

                # Créer nouvelle PayloadVariant avec valeur obfusquée
                obfuscated_variant = PayloadVariant(
                    id=f"{variant.id}_obfuscated_{technique_name}",
                    value=obfuscated_value,
                    tech_stack=variant.tech_stack,
                    expected_result=variant.expected_result,
                    confidence_boost=variant.confidence_boost + 0.08,  # Boost obfuscation
                    detection=variant.detection,
                    encoding_chains=variant.encoding_chains,
                    obfuscation_techniques=tuple(),  # Déjà appliqué
                )
                obfuscated_variants.append(obfuscated_variant)
            except Exception as exc:
                logger.debug(f"Failed to obfuscate variant {variant.id} with {technique_name}: {exc}")
                continue

        return obfuscated_variants

    def get_keywords(self, plugin_id: str) -> list[str]:
        """Retourne les keywords pour identifier paramètres candidats.

        Args:
            plugin_id: ID du plugin

        Returns:
            Liste des keywords (ex: [password, user, id])
        """
        definition = self._payloads.get(plugin_id)
        if not definition:
            return []

        return list(definition.keywords)

    def has_payloads(self, plugin_id: str) -> bool:
        """Vérifie si des payloads existent pour un plugin."""
        return plugin_id in self._payloads

    def get_loaded_plugins(self) -> list[str]:
        """Retourne la liste des plugin IDs avec payloads chargés."""
        return list(self._payloads.keys())


# Instance globale (singleton pattern)
_global_payload_db: PayloadDatabase | None = None


def get_payload_database() -> PayloadDatabase:
    """Retourne l'instance globale du PayloadDatabase."""
    global _global_payload_db
    if _global_payload_db is None:
        _global_payload_db = PayloadDatabase()
    return _global_payload_db
