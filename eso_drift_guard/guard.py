"""Core audit logic for eso-drift-guard.

What it checks, per ExternalSecret remoteRef:
    SSM Parameter Store (source of truth)  vs  rendered k8s Secret (what
    the workloads actually consume)

Byte-equality of the two is the standard nobody checks — ESO caches values
and only re-reads every `refreshInterval`, so a stale render survives
longer than anyone expects (real case: 210 healthy refs and exactly 1
stale one, discovered after a rotation "completed").

Real commands are executed via kubectl/awsctl wrappers:
    kubectl get externalsecret/secret -o json   (pod or CI environment)
    aws get-parameter --with-decryption          (boto3)

Nothing is written back: `fix` prints the remediation commands, humans run
them. Rotating secrets and patching controllers is reconciliation-grade
change; this tool's job is diagnosis, not mutation.
"""

import argparse
import base64
import hashlib
import json
import shlex
import subprocess
import sys


def sha16(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


def _run(cmd, context=None, extra=None):
    argv = list(cmd)
    if context:
        argv += ["--context", context]
    if extra:
        argv += list(extra)
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed: {shlex.join(argv)}\n{proc.stderr.strip()}")
    return proc.stdout


def get_externalsecret(name, namespace, context=None):
    out = _run(["kubectl", "get", "externalsecret", name, "-n", namespace, "-o", "json"], context)
    return json.loads(out)


def get_secret(name, namespace, context=None):
    out = _run(["kubectl", "get", "secret", name, "-n", namespace, "-o", "json"], context)
    return json.loads(out)


def ssm_value(parameter_name, region, profile=None):
    import boto3

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    resp = session.client("ssm", region_name=region).get_parameter(
        Name=parameter_name, WithDecryption=True)
    return resp["Parameter"]["Value"]


def extract_property(value: str, prop: str):
    """remoteRef.property: dotted path into a JSON value."""
    try:
        obj = json.loads(value)
    except json.JSONDecodeError:
        return None
    node = obj
    for part in prop.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    if isinstance(node, str):
        return node
    return json.dumps(node)


def audit(external_secret_name, namespace, context, region, profile):
    es = get_externalsecret(external_secret_name, namespace, context)
    spec = es.get("spec", {})

    secret_name = (spec.get("target") or {}).get("name") or external_secret_name

    entries = spec.get("data") or []
    if not entries and spec.get("dataFrom"):
        print(f"[skip] {external_secret_name}: dataFrom/Extract matching not supported yet; "
              f"inspect this one manually", file=sys.stderr)

    k8s_secret = None
    rendered_missing = []

    rows, drift = [], 0
    for entry in entries:
        remote_ref = entry.get("remoteRef", {})
        key = remote_ref.get("key")
        prop = remote_ref.get("property")

        secret_key = entry.get("secretKey") or key
        if not k8s_secret:
            try:
                k8s_secret = get_secret(secret_name, namespace, context)
            except RuntimeError:
                rendered_missing.append(secret_name)

        rendered_b64 = (k8s_secret or {}).get("data", {}).get(secret_key)
        if rendered_b64 is None:
            rows.append({"secret_key": secret_key, "ssm": key, "status": "MISSING",
                         "k8s": "-", "ssm16": "-", "k8s16": "-"})
            drift += 1
            continue
        rendered = base64.b64decode(rendered_b64).decode("utf-8", errors="replace")

        source_value = ssm_value(key, region, profile)
        if prop:
            source_value = extract_property(source_value, prop)

        ok = rendered == source_value
        rows.append({
            "secret_key": secret_key,
            "ssm": key + (f"#{prop}" if prop else ""),
            "status": "OK" if ok else "DRIFT",
            "k8s16": sha16(rendered),
            "ssm16": sha16(source_value or ""),
        })
        if not ok:
            drift += 1

    return {
        "secret_name": secret_name,
        "namespace": namespace,
        "rows": rows,
        "drift": drift,
        "missing_upgrade": rendered_missing,
    }


def print_report(result):
    print(f"\nExternalSecret target secret: {result['secret_name']}  "
          f"(ns {result['namespace']})")
    print(f"{'key':40} {'ssm source':40} {'k8s hash':9} {'ssm hash':9} status")
    for r in result["rows"]:
        print(f"{r['secret_key']:40} {r['ssm']:40} {r['k8s16']:9} {r['ssm16']:9} {r['status']}")
    total = len(result["rows"])
    print(f"\nrefs checked: {total}, drifted/missing: {result['drift']}")


def fix_commands(external_secret_name, namespace, context):
    """Print the force-sync sequence: annotated apply + interval pin (then revert)."""
    ctx = f"--context {shlex.quote(context)}" if context else ""
    return [
        f"kubectl {ctx} annotate externalsecret {external_secret_name} -n {namespace} "
        'external-secrets.io/force-sync="$(date +%s)" --overwrite',
        f"kubectl {ctx} patch externalsecret {external_secret_name} -n {namespace} "
        f'--type merge -p \'{{"spec":{{"refreshInterval":"1s"}}}}\'',
        f"# verify pod env actually updated before reverting:",
        f"kubectl {ctx} rollout restart deployment <consumer> -n {namespace}",
        f"kubectl {ctx} patch externalsecret {external_secret_name} -n {namespace} "
        f'--type merge -p \'{{"spec":{{"refreshInterval":"1800s"}}}}\'',
    ]


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="eso-drift-guard",
        description="Byte-verify k8s Secret renders against their SSM Parameter Store source.",
    )
    p.add_argument("name", help="ExternalSecret resource name")
    p.add_argument("-n", "--namespace", required=True)
    p.add_argument("--context", default=None, help="kubectl context")
    p.add_argument("--region", default="eu-west-2", help="SSM region of the source parameters")
    p.add_argument("--profile", default=None, help="AWS profile holding the SSM source")
    p.add_argument("--fix", action="store_true",
                   help="print the force-sync commands (does not apply anything)")
    args = p.parse_args(argv)

    if args.fix:
        print("# suggested force-sync sequence (run and verify manually):")
        for c in fix_commands(args.name, args.namespace, args.context):
            print(c)
        return 0

    try:
        result = audit(args.name, args.namespace, args.context, args.region, args.profile)
    except RuntimeError as exc:
        sys.exit(str(exc))
    print_report(result)
    return 1 if result["drift"] else 0


if __name__ == "__main__":
    sys.exit(main())
