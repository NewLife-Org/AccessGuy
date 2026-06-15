# AccessGuy — Processor (Python)

Faza obróbki: czyta `dataset.json` ze skanera, liczy scoring wg `../contracts/rules.yaml`,
generuje raport (konsola / HTML / PDF / CSV / JSON). Nie łączy się z tenantem.

```bash
pip install -e ".[dev]"        # ".[pdf]" dla PDF (weasyprint)
pytest -q
python -m accessguy_processor process ../contracts/samples/dataset.sample.json --out ./reports
python -m accessguy_processor validate ../contracts/samples/dataset.sample.json
```

Architektura: `models` (kontrakt) → `ingest` (walidacja) → `scoring` (rules.yaml + predykaty) → `report`.
Nową regułę dodajesz w `rules.yaml` i jako funkcję w `scoring/predicates.py` o tym samym `id`.
