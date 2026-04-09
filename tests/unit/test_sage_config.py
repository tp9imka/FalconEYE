"""Unit tests for SAGEConfig and its integration with FalconEyeConfig."""

import pytest
from pydantic import ValidationError

from falconeye.infrastructure.config.config_models import SAGEConfig, FalconEyeConfig


@pytest.mark.unit
class TestSAGEConfigDefaults:
    """Test SAGEConfig default values."""

    def test_default_enabled_is_false(self):
        config = SAGEConfig()
        assert config.enabled is False

    def test_default_base_url(self):
        config = SAGEConfig()
        assert config.base_url == "http://localhost:8080"

    def test_default_identity_path_is_none(self):
        config = SAGEConfig()
        assert config.identity_path is None

    def test_default_timeout(self):
        config = SAGEConfig()
        assert config.timeout == 15.0

    def test_default_store_findings(self):
        config = SAGEConfig()
        assert config.store_findings is True

    def test_default_recall_context(self):
        config = SAGEConfig()
        assert config.recall_context is True


@pytest.mark.unit
class TestSAGEConfigCustomValues:
    """Test SAGEConfig with custom constructor values."""

    def test_custom_enabled(self):
        config = SAGEConfig(enabled=True)
        assert config.enabled is True

    def test_custom_base_url(self):
        config = SAGEConfig(base_url="http://sage.internal:9090")
        assert config.base_url == "http://sage.internal:9090"

    def test_custom_identity_path(self):
        config = SAGEConfig(identity_path="/etc/sage/agent.key")
        assert config.identity_path == "/etc/sage/agent.key"

    def test_custom_timeout(self):
        config = SAGEConfig(timeout=30.0)
        assert config.timeout == 30.0

    def test_custom_store_findings_disabled(self):
        config = SAGEConfig(store_findings=False)
        assert config.store_findings is False

    def test_custom_recall_context_disabled(self):
        config = SAGEConfig(recall_context=False)
        assert config.recall_context is False

    def test_all_custom_values(self):
        config = SAGEConfig(
            enabled=True,
            base_url="https://sage.prod:443",
            identity_path="/opt/keys/agent.key",
            timeout=60.0,
            store_findings=False,
            recall_context=False,
        )
        assert config.enabled is True
        assert config.base_url == "https://sage.prod:443"
        assert config.identity_path == "/opt/keys/agent.key"
        assert config.timeout == 60.0
        assert config.store_findings is False
        assert config.recall_context is False


@pytest.mark.unit
class TestSAGEConfigValidation:
    """Test SAGEConfig field validation."""

    def test_timeout_minimum_boundary(self):
        """Timeout must be >= 1.0."""
        config = SAGEConfig(timeout=1.0)
        assert config.timeout == 1.0

    def test_timeout_maximum_boundary(self):
        """Timeout must be <= 120.0."""
        config = SAGEConfig(timeout=120.0)
        assert config.timeout == 120.0

    def test_timeout_below_minimum_raises(self):
        """Timeout below 1.0 must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            SAGEConfig(timeout=0.5)
        assert "timeout" in str(exc_info.value).lower() or "greater_than_equal" in str(exc_info.value).lower()

    def test_timeout_above_maximum_raises(self):
        """Timeout above 120.0 must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            SAGEConfig(timeout=121.0)
        assert "timeout" in str(exc_info.value).lower() or "less_than_equal" in str(exc_info.value).lower()

    def test_timeout_zero_raises(self):
        """Timeout of 0 must raise ValidationError."""
        with pytest.raises(ValidationError):
            SAGEConfig(timeout=0.0)

    def test_timeout_negative_raises(self):
        """Negative timeout must raise ValidationError."""
        with pytest.raises(ValidationError):
            SAGEConfig(timeout=-5.0)


@pytest.mark.unit
class TestSAGEConfigFromDict:
    """Test SAGEConfig creation from dict (simulating YAML parse)."""

    def test_from_dict_all_fields(self):
        data = {
            "enabled": True,
            "base_url": "http://sage:8080",
            "identity_path": "/keys/agent.key",
            "timeout": 20.0,
            "store_findings": True,
            "recall_context": False,
        }
        config = SAGEConfig(**data)
        assert config.enabled is True
        assert config.base_url == "http://sage:8080"
        assert config.identity_path == "/keys/agent.key"
        assert config.timeout == 20.0
        assert config.store_findings is True
        assert config.recall_context is False

    def test_from_dict_partial_uses_defaults(self):
        data = {"enabled": True}
        config = SAGEConfig(**data)
        assert config.enabled is True
        assert config.base_url == "http://localhost:8080"
        assert config.timeout == 15.0

    def test_from_empty_dict(self):
        config = SAGEConfig(**{})
        assert config.enabled is False
        assert config.base_url == "http://localhost:8080"

    def test_from_dict_integer_timeout_coerced(self):
        """Integer timeout from YAML should be coerced to float."""
        config = SAGEConfig(timeout=30)
        assert config.timeout == 30.0
        assert isinstance(config.timeout, float)


@pytest.mark.unit
class TestSAGEConfigInFalconEyeConfig:
    """Test that SAGEConfig is properly part of FalconEyeConfig."""

    def test_falconeye_config_has_sage_field(self):
        config = FalconEyeConfig()
        assert hasattr(config, "sage")
        assert isinstance(config.sage, SAGEConfig)

    def test_falconeye_default_sage_disabled(self):
        config = FalconEyeConfig()
        assert config.sage.enabled is False

    def test_falconeye_sage_from_dict(self):
        data = {
            "sage": {
                "enabled": True,
                "base_url": "http://sage-node:8080",
                "timeout": 25.0,
            }
        }
        config = FalconEyeConfig(**data)
        assert config.sage.enabled is True
        assert config.sage.base_url == "http://sage-node:8080"
        assert config.sage.timeout == 25.0

    def test_falconeye_config_to_dict_includes_sage(self):
        config = FalconEyeConfig()
        dumped = config.model_dump()
        assert "sage" in dumped
        assert dumped["sage"]["enabled"] is False
        assert dumped["sage"]["base_url"] == "http://localhost:8080"

    def test_falconeye_config_sage_validation_propagates(self):
        """Invalid sage timeout should be caught at FalconEyeConfig level."""
        with pytest.raises(ValidationError):
            FalconEyeConfig(sage={"timeout": 0.0})
