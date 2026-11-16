# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`rag-and-vector-store-attacks`](SKILL.md) | Family: **AI and LLM**

Probes for `rag-and-vector-store-attacks`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Cross-tenant retrieval

Baseline: a query as tenant A returns only A's chunks. Probe: the same query with a chunk from tenant B ingested. Differential: a B chunk in A's top-k, or an answer that depends on B's content.

```bash
python -c "import json; print(json.load(open('query.json'))['filter'])"
python -c "import json; print([h['tenant'] for h in json.load(open('hits.json'))['hits']])"
```

## Ingestion authorisation

Baseline: an authorised writer ingests a document. Probe: an unauthorised caller attempts ingestion. Differential: an accepted unauthorised write puts attacker text in every future retrieval.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST $API/ingest -H 'content-type: application/json' -d @doc.json
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
