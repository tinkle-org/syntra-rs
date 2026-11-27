"""Check the repository's carrier contract and public context fixtures against Rust."""

import argparse
import json

from context_probe import binding_sources, probe, record_fixture_bounds
from local_inputs import FIXTURES, ROOT, read_json

MUTATIONS = {"unsupported-domain", "unsupported-format", "zero-mode", "unknown-carrier",
             "bootstrap-epoch", "returning-handle", "empty-scope", "oversize-scope",
             "truncated", "trailing", "invalid-utf8", "scope-byte-length"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def indexed(rows):
    require(all(isinstance(row, dict) and isinstance(row.get("id"), str) and row["id"] for row in rows),
            "missing or invalid fixture ID")
    result = {row["id"]: row for row in rows}
    require(len(result) == len(rows), "duplicate fixture ID")
    return result


def coverage(contract, fixture, cases):
    rows, recipes = indexed(fixture["contexts"]), indexed(fixture["negative_recipes"])
    carriers = contract["carriers"]
    require(cases.keys() == carriers.keys(), "missing or extra carrier manifest")
    for name, code, binding, production in (("TCP", 1, "tcp-u16be", True), ("WS", 2, "websocket-h1-binary", False),
                                             ("WSS", 3, "websocket-h1-binary-verified-tls13", True)):
        row = carriers["SYNTRA-1.0-" + name]
        require(type(row["code"]) is int and row["code"] == code and row["binding"] == binding
                and row["production_allowed"] is production, f"{name} carrier binding policy mismatch")
    require(carriers["SYNTRA-1.0-WS"]["scope"] == "loopback-development-only", "WS must be loopback-only")
    wss = carriers["SYNTRA-1.0-WSS"]
    require(wss["tls_minimum"] == "1.3" and wss["tls_termination"] == "direct_host", "WSS TLS policy mismatch")
    codes = {carrier["code"] for carrier in carriers.values()}
    require(len(carriers) == 3 and all(type(r[k]) is int for r in rows.values() for k in ("mode", "carrier")),
            "unrecognized carrier/mode")
    require({(r["mode"], r["carrier"]) for r in rows.values()} == {(m, c) for m in (1, 2) for c in codes},
            "both modes required for each carrier")
    seen = set()
    for name, case in cases.items():
        mutations = []
        for identifier in case["recipes"]:
            recipe = recipes[identifier]
            base, mutation = rows[recipe["base"]], recipe["mutation"]
            require(identifier not in seen and base["carrier"] == carriers[name]["code"]
                    and recipe["expected"] == "reject-before-noise", f"invalid manifest recipe {identifier}")
            seen.add(identifier)
            require(base["mode"] == (2 if mutation in ("returning-handle", "scope-byte-length") else 1),
                    f"wrong base mode for {identifier}")
            scope = base["scope"].encode()
            require(mutation != "scope-byte-length" or len(scope) > len(base["scope"]), "multibyte scope required")
            require(mutation != "invalid-utf8" or len(scope) == 1, "single-byte scope required")
            mutations.append(mutation)
        require(set(mutations) == MUTATIONS and len(mutations) == len(MUTATIONS), f"incomplete mutations for {name}")
    require(seen == recipes.keys(), "unreferenced negative recipes")


def verify(root=ROOT):
    contract = read_json(root, 'protocol-contract.json')
    fixture = read_json(root, FIXTURES / 'syntra-1.0-context.json')
    cases = read_json(root, FIXTURES / 'context-cases.json')
    coverage(contract, fixture, cases)
    rows, negatives = fixture["contexts"], fixture["negative_recipes"]
    layout, limits = contract["context_layout"], contract["channel_limits"]
    observed = probe(root, rows, negatives, layout)

    def observations(kind):
        return [r for r in observed if r["kind"] == kind]

    constants, = observations("constants")
    c = constants
    require(contract['protocol'] == 'Syntra ' + c['domain'].removeprefix('syntra.'), "protocol name mismatch")
    require(c["protocol"] == c["domain"] == fixture["domain_ascii"] == contract["domain_ascii"]
            == contract["websocket_subprotocol"], "domain mismatch")
    require(type(contract["core_wire_version"]) is int and c["min_version"] == c["max_version"] == contract["core_wire_version"], "wire version mismatch")
    require(c["auth_key"] == 32 and c["noise"] == 32 + c["tag"] and c["frame"] == c["core_frame"], "record bounds mismatch")
    require(limits == dict(authorization_key_bytes=c["auth_key"], aead_tag_bytes=c["tag"], max_plaintext_bytes=c["plaintext"],
                           max_ciphertext_bytes=c["ciphertext"], max_serialized_frame_bytes=c["frame"],
                           max_records_per_direction=c["records"], max_age_seconds=c["age"]), "channel limits mismatch")
    require(layout == {"domain": [0, c["mode"]], "mode": [c["mode"], c["carrier"]],
                       "carrier": [c["carrier"], c["key_id"]], "server_key_id": [c["key_id"], c["epoch"]],
                       "epoch": [c["epoch"], c["handle"]], "handle": [c["handle"], c["scope_len"]],
                       "scope_length_u16be": [c["scope_len"], c["scope"]], "scope": [c["scope"], None],
                       "scope_bytes": [c["min_scope"], c["max_scope"]],
                       "context_bytes": [c["scope"] + c["min_scope"], c["scope"] + c["max_scope"]],
                       "m1_bytes": [c["min_m1"], c["max_m1"]], "m2_bytes": c["noise"]}, "context layout mismatch")
    encoded = indexed(observations("context"))
    for row in rows:
        size = len(bytes.fromhex(encoded[row["id"]]["hex"]))
        require(row["context_hex"] == row["prologue_hex"] == encoded[row["id"]]["hex"]
                and row["context_bytes"] == size and row["m1_bytes"] == size + c["noise"], f"context mismatch: {row['id']}")
    rejected = indexed(observations("negative"))
    require(rejected.keys() == indexed(negatives).keys() and all(r["rejected"] for r in rejected.values()), "negative context accepted")
    require({r["carrier"]: r["rejected"] for r in observations("default_candidate_rejection")} == {4: True, 5: True},
            "opt-in carrier accepted by default")
    independent = indexed(observations("independent"))
    reference = indexed(rows)
    require(len(independent) >= 4 and all(reference[k].get(f) == v for k, r in independent.items()
                                          for f, v in r.items() if f != "kind"), "independent context fixture drift")
    record, = observations("record_fixture")
    require(any(row["carrier"] == 3 and row["context_hex"] == record["hex"] for row in rows), "record WSS fixture drift")
    binding_sources(root, contract)
    record_fixture_bounds(root, contract)
    return {"protocol": contract["protocol"], "carriers": sorted(cases), "contexts": len(rows), "negative_recipes": len(negatives)}


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps(verify(), indent=2))
