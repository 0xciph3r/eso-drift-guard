# eso-drift-guard

**Byte-verify the k8s Secrets your workloads actually consume against their SSM
Parameter Store source of truth.**

A key rotates. You PUT the new value into Parameter Store. Everyone believes
the External Secrets Operator will propagate it "after a refresh". Hours turn
into days. Somewhere between 210 healthy references and one stale render, a
consumer is still calling the old endpoint — and nobody can prove it until a
pod fails.

This happened in production, and this tool is the check that would have caught
it within one command.

## What it does

For one ExternalSecret:

1. reads `spec.data[]` (`secretKey` + `remoteRef{key, property}`) from the
   cluster via kubectl
2. fetches the rendered `Secret` from the same namespace and base64-decodes it
3. fetches each source parameter from SSM `--with-decryption`
4. compares **bytes** — not names, not formats, bytes — and prints a
   `sha256[:16]` for each side so drift is pointing-at-it provable
5. exit code `0` = all equal, `1` = drift/missing (CI-friendly)

## Quickstart

```bash
pip install boto3

python -m eso_drift_guard.guard consumer-relay-creds \
    -n integrations \
    --context kind-prod \
    --profile prod-a --region eu-west-2
```

Sample output:

```text
ExternalSecret target secret: relay-creds  (ns integrations)
key                                      ssm source                               k8s hash  ssm hash  status
API_KEY                                  /integration/RELAY_API_KEY               a3695058  bbca21a1  DRIFT

refs checked: 1, drifted/missing: 1
```

Fix flow (prints commands; you run them):

```bash
python -m eso_drift_guard.guard consumer-relay-creds -n integrations --fix
```

```text
kubectl --context kind-prod annotate externalsecret consumer-relay-creds -n integrations \
        external-secrets.io/force-sync="$(date +%s)" --overwrite
kubectl --context kind-prod patch externalsecret consumer-relay-creds -n integrations \
        --type merge -p '{"spec":{"refreshInterval":"1s"}}'
kubectl --context kind-prod rollout restart deployment <consumer> -n integrations
kubectl --context kind-prod patch externalsecret consumer-relay-creds -n integrations \
        --type merge -p '{"spec":{"refreshInterval":"1800s"}}'
```

## Field notes from real incidents

- **Do not trust "it should have synced".** The re-read happens every
  `refreshInterval` (commonly 900s–3600s). Right after a rotation, drop
  `refreshInterval` to `1s`, annotate `force-sync`, and *then* return it.
- **Verify pods, not CRDs.** `kubectl exec <pod> -- env | grep KEY` on a
  distroless image is impossible; hash-compare the rendered Secret + trigger a
  rollout restart in dependency order instead.
- **This tool found exactly 1 drift of 211 refs post-rotation** — silent,
  harmless-looking, and the reason a production consumer kept failing.
- The right follow-up for a store like this is a periodic CI scan, not a
  one-off: drift between SSM and render is not an "incident", it is an
  unobserved race.

## Design decisions

- **Diagnosis only.** Mutation of ExternalSecrets during a rotation is a
  reconciliation-grade change; printing commands keeps the audit trail human.
- `dataFrom/Extract` references skipped for now (manual inspection), while
  `data[]` references get the full byte-verify.
- Property references (`remoteRef.property`) are followed as dotted JSON
  paths.

## Limitations

- AWS + SSM Parameter Store sources only (that was the incident stack; other
  providers are trivial to add given the same shape).
- Requires kubectl access and SSM read (decrypt) on the scanning principal.
- Not a detector for changes *inside* running pods' env — restart or restart
  in the checks of your workload, or verify in-process where the image allows.

## License

MIT — see [LICENSE](LICENSE).
