# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
hdwp.interfaces — SDK public pour les modules HDWP.

Tout composant substituable implémente un Protocol de ce package.
Compatible pip : `from hdwp.interfaces import InferenceModuleProtocol`.
"""
from hdwp.interfaces.inference import InferenceModuleProtocol
from hdwp.interfaces.bus import PluginBusView
from hdwp.interfaces.kernel import KernelBuilder
from hdwp.core.mutation_registry import MutationSpec  # re-export pour register_mutations()
from hdwp.plugins.base import HDWPPlugin              # re-export

__all__ = [
    "InferenceModuleProtocol",
    "PluginBusView",
    "KernelBuilder",
    "MutationSpec",
    "HDWPPlugin",
]
