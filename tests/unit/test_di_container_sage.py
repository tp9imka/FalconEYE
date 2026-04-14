"""Unit tests for SAGE wiring in the DI container."""

import pytest
from contextlib import ExitStack
from unittest.mock import patch, MagicMock

from falconeye.infrastructure.config.config_models import FalconEyeConfig, SAGEConfig
from falconeye.infrastructure.config.config_loader import ConfigLoader


# ---------------------------------------------------------------------------
# Helper: create a fully-mocked DIContainer.create() context
# ---------------------------------------------------------------------------

_INFRA_TARGETS = [
    "falconeye.infrastructure.di.container.Path",
    "falconeye.infrastructure.di.container.ConfigLoader",
    "falconeye.infrastructure.di.container.OllamaLLMAdapter",
    "falconeye.infrastructure.di.container.ChromaVectorStoreAdapter",
    "falconeye.infrastructure.di.container.ChromaMetadataRepository",
    "falconeye.infrastructure.di.container.ChromaIndexRegistryAdapter",
    "falconeye.infrastructure.di.container.EnhancedASTAnalyzer",
    "falconeye.infrastructure.di.container.PluginRegistry",
]


def _patched_create(
    config: FalconEyeConfig,
    sage_import_fails: bool = False,
    **create_kwargs,
):
    """
    Call DIContainer.create() with all infrastructure mocked out.

    Args:
        config: The FalconEyeConfig to use
        sage_import_fails: If True, simulate sage_sdk not being installed
        **create_kwargs: Extra kwargs passed to DIContainer.create()

    Returns the created DIContainer instance.
    """
    with ExitStack() as stack:
        infra_mocks = {}
        for target in _INFRA_TARGETS:
            name = target.rsplit(".", 1)[-1]
            infra_mocks[name] = stack.enter_context(patch(target))

        infra_mocks["ConfigLoader"].load.return_value = config
        infra_mocks["PluginRegistry"].return_value = MagicMock()

        sage_will_be_enabled = config.sage.enabled or create_kwargs.get("sage_override", False)

        if sage_import_fails and sage_will_be_enabled:
            # Make the sage adapter import raise ImportError
            original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

            def _mock_import(name, *args, **kwargs):
                if "sage_adapter" in name or "sage_sdk" in name:
                    raise ImportError(f"No module named '{name}'")
                return original_import(name, *args, **kwargs)

            stack.enter_context(patch("builtins.__import__", side_effect=_mock_import))

        from falconeye.infrastructure.di.container import DIContainer
        return DIContainer.create(**create_kwargs)


# ---------------------------------------------------------------------------
# Tests: Container without SAGE
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestContainerWithoutSAGE:

    def test_container_without_sage(self):
        """When sage.enabled=False, memory_service should be None."""
        config = FalconEyeConfig()
        assert config.sage.enabled is False

        container = _patched_create(config)
        assert container.memory_service is None


# ---------------------------------------------------------------------------
# Tests: Container with SAGE unavailable
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestContainerWithSAGEEnabled:

    def test_container_sage_enabled_creates_memory_service(self):
        """
        When sage.enabled=True, memory_service should be set.
        Health is checked lazily on first use, not at container creation.
        """
        config = FalconEyeConfig(sage=SAGEConfig(enabled=True))
        container = _patched_create(config)
        assert container.memory_service is not None

    def test_container_sage_import_error_graceful(self):
        """
        When sage.enabled=True but sage_sdk cannot be imported,
        memory_service should gracefully be None.
        """
        config = FalconEyeConfig(sage=SAGEConfig(enabled=True))
        container = _patched_create(config, sage_import_fails=True)
        assert container.memory_service is None


# ---------------------------------------------------------------------------
# Tests: SAGE in config sections
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSAGEInConfigSections:

    def test_sage_in_known_config_sections(self):
        """'sage' must be in KNOWN_CONFIG_SECTIONS so env vars are processed."""
        assert "sage" in ConfigLoader.KNOWN_CONFIG_SECTIONS

    def test_known_config_sections_includes_all_falconeye_fields(self):
        """Every field of FalconEyeConfig should be in KNOWN_CONFIG_SECTIONS."""
        model_fields = set(FalconEyeConfig.model_fields.keys())
        for field_name in model_fields:
            assert field_name in ConfigLoader.KNOWN_CONFIG_SECTIONS, (
                f"FalconEyeConfig field '{field_name}' missing from KNOWN_CONFIG_SECTIONS"
            )


# ---------------------------------------------------------------------------
# Tests: SAGE override flag
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSAGEOverrideFlag:

    def test_sage_override_enables_sage(self):
        """sage_override=True should set config.sage.enabled=True."""
        config = FalconEyeConfig()
        assert config.sage.enabled is False

        container = _patched_create(config, sage_override=True)

        # The flag should have flipped config.sage.enabled
        assert config.sage.enabled is True
        # memory_service should be set (health checked lazily on first use)
        assert container.memory_service is not None

    def test_sage_override_false_does_not_enable(self):
        """sage_override=False should not change sage.enabled."""
        config = FalconEyeConfig()
        container = _patched_create(config, sage_override=False)

        assert config.sage.enabled is False
        assert container.memory_service is None
