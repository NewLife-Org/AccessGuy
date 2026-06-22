from __future__ import annotations

from accessguy_processor.ingest import load_dataset


def test_sample_loads_and_validates(sample_dataset_path):
    ds = load_dataset(sample_dataset_path)
    assert ds.schema_version == "1.4"
    assert len(ds.accounts) == 3
    assert len(ds.subscribed_skus) == 3
    assert len(ds.groups) == 4
    assert len(ds.applications) == 3
    # kategorie poprawnie sparsowane
    cats = {a.user_principal_name: a.category for a in ds.accounts}
    assert cats["jan.kowalski@contoso.pl"] == "internal"
    assert cats["admin.ext@partner.com"] == "guest"
