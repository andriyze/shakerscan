import pytest

from scanner.scanner_tools import model_intake_registry as registry


def test_builtin_adapter_catalog_is_model_agnostic_and_capability_explicit():
    catalog = {item["id"]: item for item in registry.adapter_catalog()}

    assert set(catalog) == {"azure_blob", "gcs", "http", "huggingface", "mlflow", "oci", "s3"}
    assert catalog["huggingface"]["repository_snapshot"] == "implemented"
    assert catalog["http"]["artifact_acquisition"] == "implemented"
    assert catalog["oci"]["artifact_acquisition"] == "implemented"
    assert catalog["mlflow"]["artifact_acquisition"] == "implemented"
    assert all("coderank" not in str(item).lower() and "codesage" not in str(item).lower() for item in catalog.values())


def test_adapter_aliases_normalize_provider_names():
    assert registry.adapter_capabilities("hf")["id"] == "huggingface"
    assert registry.adapter_capabilities("gs")["id"] == "gcs"
    assert registry.adapter_capabilities("azure")["id"] == "azure_blob"
    assert registry.adapter_capabilities("https")["id"] == "http"


def test_unknown_adapter_fails_closed():
    capabilities = registry.adapter_capabilities("future-registry")

    assert capabilities["id"] == "future-registry"
    assert capabilities["artifact_acquisition"] == "unsupported"
    assert capabilities["repository_snapshot"] == "unsupported"


def test_register_adapter_is_an_extension_point_without_replacing_builtins():
    adapter = registry.ModelSourceAdapter(
        id="test-registry",
        display_name="Test Registry",
        aliases=("test-models",),
        reference_schemes=("testmodel",),
        resolve="implemented",
        immutable_resolution="implemented",
        artifact_acquisition="implemented",
        repository_manifest="not_applicable",
        repository_snapshot="not_applicable",
        authentication="test-only",
    )
    registry.register_adapter(adapter)
    assert registry.get_adapter("test-models") == adapter
    with pytest.raises(ValueError, match="already registered"):
        registry.register_adapter(adapter)
