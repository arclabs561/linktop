#!/usr/bin/env python3
"""Run a bounded, metadata-only campaign over `linktop review` fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

MIB = 1024 * 1024
MAX_CASES = 64
MAX_CASE_BYTES = 128 * MIB
MAX_TOTAL_BYTES = 512 * MIB
MAX_MANIFEST_BYTES = 1 * MIB
MAX_REVIEW_OUTPUT_BYTES = 16 * MIB
REVIEW_MAX_INPUT_MIB = 128
REVIEW_TIMEOUT_SECONDS = 30

MANIFEST_SCHEMA = "linktop.review_campaign.v1"
OUTPUT_SCHEMA = "linktop.review_campaign_eval.v1"
TRIAGE_SCHEMAS = frozenset({"netmon.saved_pcap_triage.v1"})
COMPARISON_SCHEMAS = frozenset({"linktop.saved_pcap_comparison.v2"})
HYPOTHESIS_SCHEMAS = frozenset({"netmon.saved_pcap_fingerprint_hypothesis_set.v0"})
CONTENT_RELATION_SCHEMAS = frozenset({"netbraid.content_relation_hypothesis_set.v0"})
QUALIFIED_COMPOSITION_SCHEMAS = frozenset(
    {"netbraid.provenance_qualified_finite_hypothesis_composition.v0"}
)
COMPOSITION_SCHEMAS = frozenset({"netbraid.finite_hypothesis_composition.v0"})
DEPENDENCE_STATUSES = frozenset({"declared_shared_lineage", "no_shared_ancestry_found"})
COMPOSITION_FAMILIES = (
    "netbraid.content_relation_hypothesis_set.v0",
    "netmon.saved_pcap_fingerprint_hypothesis_set.v0",
)
COMPLETENESS_STATUSES = frozenset({"complete_capture", "partial_packet_subset"})
WLAN_STATUSES = frozenset({"insufficient", "unsupported", "not_observed", "observed"})
CONVERSATION_STATUSES = frozenset({"insufficient", "unsupported", "observed"})
NEGATIVE_CLAIM_STATUSES = frozenset({"not_requested", "qualified", "abstained"})
TRIAGE_EXPECTED_FIELDS = (
    "schema",
    "completeness",
    "wlan",
    "conversation",
    "negative_claim",
)
TRIAGE_VOCABULARY = {
    "schema": TRIAGE_SCHEMAS,
    "completeness": COMPLETENESS_STATUSES,
    "wlan": WLAN_STATUSES,
    "conversation": CONVERSATION_STATUSES,
    "negative_claim": NEGATIVE_CLAIM_STATUSES,
}
COMPARISON_EXPECTED_FIELDS = (
    "schema",
    "hypothesis_schema",
    "content_relation_schema",
    "content_basis",
    "qualified_composition_schema",
    "composition_schema",
    "composition_claim_count",
    "dependence",
    "basis",
    "reason",
    "input_status",
    "compare_with_status",
    "input_capture_id",
    "compare_with_capture_id",
    "canonical_left_capture_id",
    "canonical_right_capture_id",
)
COMPARISON_VOCABULARY = {
    "schema": COMPARISON_SCHEMAS,
    "hypothesis_schema": HYPOTHESIS_SCHEMAS,
    "content_relation_schema": CONTENT_RELATION_SCHEMAS,
    "content_basis": frozenset({"sha256_equal", "sha256_different"}),
    "qualified_composition_schema": QUALIFIED_COMPOSITION_SCHEMAS,
    "composition_schema": COMPOSITION_SCHEMAS,
    "dependence": DEPENDENCE_STATUSES,
    "basis": frozenset({"corroborated", "conflicting", "not_comparable"}),
    "reason": frozenset(
        {
            "none",
            "left_not_observed",
            "right_not_observed",
            "different_schema",
            "different_claim_scope",
            "different_feature_set",
            "invalid_digest",
        }
    ),
    "input_status": frozenset({"observed", "insufficient", "unsupported"}),
    "compare_with_status": frozenset({"observed", "insufficient", "unsupported"}),
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
CAPTURE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "fixtures/review-campaign-v1.json"


class DuplicateKeyError(ValueError):
    pass


class CampaignError(Exception):
    def __init__(self, kind: str, stage: str, case: int | None = None) -> None:
        super().__init__(kind, stage, case)
        self.kind = kind
        self.stage = stage
        self.case = case


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(key)
        result[key] = value
    return result


def load_json_strict(data: bytes, stage: str, case: int | None = None) -> Any:
    try:
        return json.loads(data, object_pairs_hook=strict_object)
    except (
        DuplicateKeyError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ):
        raise CampaignError("malformed", stage, case) from None


def read_bounded(
    path: Path,
    limit: int,
    *,
    too_large_stage: str,
    unavailable_stage: str,
    case: int | None = None,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(min(MIB, limit + 1 - total))
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise CampaignError("bounds", too_large_stage, case)
    except CampaignError:
        raise
    except OSError:
        raise CampaignError("execution", unavailable_stage, case) from None


def input_metadata(path: Path, stage: str, case: int) -> tuple[int, int, int]:
    try:
        metadata = path.stat()
    except OSError:
        raise CampaignError("execution", stage, case) from None
    return metadata.st_size, metadata.st_mode, metadata.st_mtime_ns


def limits_metadata() -> dict[str, int]:
    return {
        "max_cases": MAX_CASES,
        "max_case_bytes": MAX_CASE_BYTES,
        "max_review_output_bytes": MAX_REVIEW_OUTPUT_BYTES,
        "max_total_bytes": MAX_TOTAL_BYTES,
        "review_max_input_mib": REVIEW_MAX_INPUT_MIB,
        "review_timeout_seconds": REVIEW_TIMEOUT_SECONDS,
    }


def error_report(error: CampaignError) -> dict[str, Any]:
    detail: dict[str, Any] = {"kind": error.kind, "stage": error.stage}
    if error.case is not None:
        detail["case"] = error.case
    return {
        "schema": OUTPUT_SCHEMA,
        "status": "error",
        "limits": limits_metadata(),
        "error": detail,
    }


def validate_manifest(
    manifest_path: Path, repo_root: Path
) -> tuple[list[dict[str, Any]], int]:
    raw = read_bounded(
        manifest_path,
        MAX_MANIFEST_BYTES,
        too_large_stage="manifest_size",
        unavailable_stage="manifest_read",
    )
    manifest = load_json_strict(raw, "manifest_json")
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "cases"}:
        raise CampaignError("malformed", "manifest_shape")
    if manifest["schema"] != MANIFEST_SCHEMA or not isinstance(manifest["cases"], list):
        raise CampaignError("malformed", "manifest_shape")
    cases = manifest["cases"]
    if not 1 <= len(cases) <= MAX_CASES:
        raise CampaignError("bounds", "case_count")

    root = repo_root.resolve()
    validated: list[dict[str, Any]] = []
    total_bytes = 0
    for ordinal, case in enumerate(cases, start=1):
        if not isinstance(case, dict) or case.get("operation") not in {
            "triage",
            "compare",
        }:
            raise CampaignError("malformed", "case_shape", ordinal)

        operation = case["operation"]
        required_fields = (
            {"operation", "input", "sha256", "expect"}
            if operation == "triage"
            else {
                "operation",
                "input",
                "sha256",
                "compare_with",
                "compare_with_sha256",
                "expect",
            }
        )
        if set(case) != required_fields:
            raise CampaignError("malformed", "case_shape", ordinal)

        relative_input = case["input"]
        expected_sha256 = case["sha256"]
        expected = case["expect"]
        if not isinstance(relative_input, str) or Path(relative_input).is_absolute():
            raise CampaignError("malformed", "input_reference", ordinal)
        if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(
            expected_sha256
        ):
            raise CampaignError("malformed", "sha256", ordinal)

        expected_fields = (
            TRIAGE_EXPECTED_FIELDS
            if operation == "triage"
            else COMPARISON_EXPECTED_FIELDS
        )
        vocabulary = (
            TRIAGE_VOCABULARY if operation == "triage" else COMPARISON_VOCABULARY
        )
        if not isinstance(expected, dict) or set(expected) != set(expected_fields):
            raise CampaignError("malformed", "expectation_shape", ordinal)
        for field in expected_fields:
            if field == "composition_claim_count":
                if expected[field] != 2:
                    raise CampaignError("malformed", "expectation_vocabulary", ordinal)
            elif field in {
                "input_capture_id",
                "compare_with_capture_id",
                "canonical_left_capture_id",
                "canonical_right_capture_id",
            }:
                if not isinstance(expected[field], str) or not CAPTURE_ID_RE.fullmatch(
                    expected[field]
                ):
                    raise CampaignError("malformed", "expectation_vocabulary", ordinal)
            elif expected[field] not in vocabulary[field]:
                raise CampaignError("malformed", "expectation_vocabulary", ordinal)

        if (expected.get("basis") == "not_comparable") != (
            expected.get("reason") not in {None, "none"}
        ):
            raise CampaignError("malformed", "expectation_coherence", ordinal)

        try:
            input_path = (manifest_path.parent / relative_input).resolve(strict=True)
            input_path.relative_to(root)
            file_stat = input_path.stat()
        except (OSError, ValueError):
            raise CampaignError("malformed", "input_reference", ordinal) from None
        if not stat.S_ISREG(file_stat.st_mode):
            raise CampaignError("malformed", "input_reference", ordinal)
        if file_stat.st_size > MAX_CASE_BYTES:
            raise CampaignError("bounds", "case_bytes", ordinal)
        total_bytes += file_stat.st_size
        if total_bytes > MAX_TOTAL_BYTES:
            raise CampaignError("bounds", "total_bytes", ordinal)
        validated_case = {
            "operation": operation,
            "path": input_path,
            "sha256": expected_sha256,
            "expect": expected,
            "size": file_stat.st_size,
        }

        if operation == "compare":
            relative_compare_with = case["compare_with"]
            compare_with_sha256 = case["compare_with_sha256"]
            if (
                not isinstance(relative_compare_with, str)
                or Path(relative_compare_with).is_absolute()
            ):
                raise CampaignError("malformed", "compare_with_reference", ordinal)
            if not isinstance(compare_with_sha256, str) or not SHA256_RE.fullmatch(
                compare_with_sha256
            ):
                raise CampaignError("malformed", "compare_with_sha256", ordinal)
            try:
                compare_with_path = (
                    manifest_path.parent / relative_compare_with
                ).resolve(strict=True)
                compare_with_path.relative_to(root)
                compare_with_stat = compare_with_path.stat()
            except (OSError, ValueError):
                raise CampaignError(
                    "malformed", "compare_with_reference", ordinal
                ) from None
            if not stat.S_ISREG(compare_with_stat.st_mode):
                raise CampaignError("malformed", "compare_with_reference", ordinal)
            if compare_with_stat.st_size > MAX_CASE_BYTES:
                raise CampaignError("bounds", "case_bytes", ordinal)
            total_bytes += compare_with_stat.st_size
            if total_bytes > MAX_TOTAL_BYTES:
                raise CampaignError("bounds", "total_bytes", ordinal)
            validated_case.update(
                {
                    "compare_with_path": compare_with_path,
                    "compare_with_sha256": compare_with_sha256,
                    "compare_with_size": compare_with_stat.st_size,
                }
            )

        validated.append(validated_case)
    return validated, total_bytes


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass


def run_review(
    binary: Path,
    input_path: Path,
    case: int,
    compare_with_path: Path | None = None,
) -> bytes:
    argv = [
        os.fspath(binary),
        "review",
        os.fspath(input_path),
    ]
    if compare_with_path is not None:
        argv.extend(["--compare-with", os.fspath(compare_with_path)])
    argv.extend(
        [
            "--json",
            "--max-input-mib",
            str(REVIEW_MAX_INPUT_MIB),
        ]
    )
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        raise CampaignError("execution", "review_start", case) from None

    if process.stdout is None:
        terminate_process(process)
        raise CampaignError("execution", "review_start", case)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output: list[bytes] = []
    output_bytes = 0
    deadline = time.monotonic() + REVIEW_TIMEOUT_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_process(process)
                raise CampaignError("execution", "review_timeout", case)
            events = selector.select(remaining)
            if not events:
                terminate_process(process)
                raise CampaignError("execution", "review_timeout", case)
            chunk = os.read(process.stdout.fileno(), 64 * 1024)
            if not chunk:
                break
            output_bytes += len(chunk)
            if output_bytes > MAX_REVIEW_OUTPUT_BYTES:
                terminate_process(process)
                raise CampaignError("bounds", "review_output_bytes", case)
            output.append(chunk)
        try:
            return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            terminate_process(process)
            raise CampaignError("execution", "review_timeout", case) from None
    finally:
        selector.close()
        process.stdout.close()
    if return_code != 0:
        raise CampaignError("execution", "review_exit", case)
    return b"".join(output)


def extract_triage_statuses(document: Any, case: int) -> dict[str, str]:
    try:
        statuses = {
            "schema": document["schema"],
            "completeness": document["normalization"]["completeness"],
            "wlan": document["wlan"]["status"],
            "conversation": document["top_capture_conversation"]["status"],
        }
        trailing = document.get("trailing_window")
        statuses["negative_claim"] = (
            "not_requested"
            if trailing is None
            else trailing["negative_claim_qualification"]["status"]
        )
    except (KeyError, TypeError, AttributeError):
        raise CampaignError("malformed", "review_shape", case) from None
    for field, value in statuses.items():
        if not isinstance(value, str) or value not in TRIAGE_VOCABULARY[field]:
            raise CampaignError("malformed", "review_vocabulary", case)
    return statuses


def _canonical_claim_key(claim: Any, case: int) -> dict[str, Any]:
    if not isinstance(claim, dict) or set(claim) != {"schema", "projection", "inputs"}:
        raise CampaignError("malformed", "review_coherence", case)
    projection = claim["projection"]
    inputs = claim["inputs"]
    if (
        claim["schema"] != "netbraid.finite_hypothesis_claim.v0"
        or not isinstance(projection, dict)
        or set(projection) != {"schema", "family_schema", "reducer", "alternatives"}
        or projection["schema"] != "netbraid.finite_hypothesis_projection.v0"
        or not isinstance(projection["family_schema"], str)
        or not isinstance(projection["reducer"], str)
        or not isinstance(projection["alternatives"], list)
        or not isinstance(inputs, list)
        or len(inputs) != 2
    ):
        raise CampaignError("malformed", "review_coherence", case)
    for item in inputs:
        if (
            not isinstance(item, dict)
            or set(item) != {"role", "source_schema", "source_id", "content_sha256"}
            or not all(isinstance(item[field], str) for field in item)
            or not SHA256_RE.fullmatch(item["content_sha256"])
        ):
            raise CampaignError("malformed", "review_coherence", case)
    if [item["role"] for item in inputs] != sorted(item["role"] for item in inputs):
        raise CampaignError("malformed", "review_coherence", case)
    return {
        "family_schema": projection["family_schema"],
        "reducer": projection["reducer"],
        "inputs": inputs,
    }


def _artifact_ref_key(reference: Any, case: int) -> str:
    if (
        not isinstance(reference, dict)
        or set(reference) != {"source_schema", "source_id", "content_sha256"}
        or not all(isinstance(reference[field], str) for field in reference)
        or not SHA256_RE.fullmatch(reference["content_sha256"])
    ):
        raise CampaignError("malformed", "review_coherence", case)
    return json.dumps(reference, sort_keys=True, separators=(",", ":"))


def _lineage_root_key(root: Any, case: int) -> str:
    key = _artifact_ref_key(root, case)
    if (
        root["source_schema"] != "netmon.capture_manifest.v0"
        or not CAPTURE_ID_RE.fullmatch(root["source_id"])
        or root["content_sha256"] != root["source_id"].removeprefix("sha256:")
    ):
        raise CampaignError("malformed", "review_coherence", case)
    return key


def _validate_qualified_composition(
    qualified: Any,
    canonical_capture_ids: tuple[str, str],
    case: int,
) -> tuple[tuple[str, ...], str]:
    if not isinstance(qualified, dict) or set(qualified) != {
        "schema",
        "composition",
        "provenance_graph",
        "claim_lineage_pairs",
    }:
        raise CampaignError("malformed", "review_coherence", case)
    canonical = qualified["composition"]
    if not isinstance(canonical, dict) or set(canonical) != {"schema", "claims"}:
        raise CampaignError("malformed", "review_coherence", case)
    claims = canonical["claims"]
    graph = qualified["provenance_graph"]
    lineage_pairs = qualified["claim_lineage_pairs"]
    if (
        not isinstance(claims, list)
        or len(claims) != 2
        or not isinstance(graph, dict)
        or set(graph) != {"schema", "records"}
        or graph["schema"] != "netbraid.provenance_graph.v0"
        or not isinstance(graph["records"], list)
        or not isinstance(lineage_pairs, list)
        or len(lineage_pairs) != 1
    ):
        raise CampaignError("malformed", "review_coherence", case)

    claim_keys = [_canonical_claim_key(claim, case) for claim in claims]
    families = tuple(key["family_schema"] for key in claim_keys)
    expected_outputs: dict[str, tuple[str, str]] = {}
    family_contracts = {
        "netbraid.content_relation_hypothesis_set.v0": (
            "netbraid.content_relation.sha256.v0",
            (
                ("left_content_evidence", "netbraid.content_digest_evidence.v0"),
                ("right_content_evidence", "netbraid.content_digest_evidence.v0"),
            ),
            "linktop:review:artifact-content",
        ),
        "netmon.saved_pcap_fingerprint_hypothesis_set.v0": (
            "netbraid.saved_pcap_fingerprint.packet_shape.v0",
            (
                ("left_candidate", "netmon.saved_pcap_fingerprint_candidate.v0"),
                ("right_candidate", "netmon.saved_pcap_fingerprint_candidate.v0"),
            ),
            "netbraid:project-saved-pcap-fingerprint-v0",
        ),
    }
    for claim_key in claim_keys:
        family = claim_key["family_schema"]
        contract = family_contracts.get(family)
        if contract is None:
            raise CampaignError("malformed", "review_coherence", case)
        reducer, expected_inputs, producer_id = contract
        observed_inputs = tuple(
            (claim_input["role"], claim_input["source_schema"])
            for claim_input in claim_key["inputs"]
        )
        if claim_key["reducer"] != reducer or observed_inputs != expected_inputs:
            raise CampaignError("malformed", "review_coherence", case)
        for claim_input in claim_key["inputs"]:
            expected_capture_id = canonical_capture_ids[
                0 if claim_input["role"].startswith("left_") else 1
            ]
            output = {key: value for key, value in claim_input.items() if key != "role"}
            output_key = _artifact_ref_key(output, case)
            if output_key in expected_outputs:
                raise CampaignError("malformed", "review_coherence", case)
            expected_outputs[output_key] = (expected_capture_id, producer_id)

    observed_outputs = set()
    for record in graph["records"]:
        if (
            not isinstance(record, dict)
            or set(record) != {"schema", "output", "producer", "activity", "inputs"}
            or record["schema"] != "netbraid.provenance_record.v0"
            or not isinstance(record["producer"], dict)
            or set(record["producer"]) != {"producer_id", "kind"}
            or record["producer"].get("kind") != "software"
            or not isinstance(record["activity"], dict)
            or set(record["activity"]) != {"activity_id", "kind"}
            or record["activity"].get("kind") != "deterministic_derivation"
            or not isinstance(record["inputs"], list)
            or len(record["inputs"]) != 1
        ):
            raise CampaignError("malformed", "review_coherence", case)
        output_key = _artifact_ref_key(record["output"], case)
        expected = expected_outputs.get(output_key)
        if expected is None or output_key in observed_outputs:
            raise CampaignError("malformed", "review_coherence", case)
        expected_capture_id, producer_id = expected
        _lineage_root_key(record["inputs"][0], case)
        if (
            record["producer"]["producer_id"] != producer_id
            or record["activity"]
            != {"activity_id": producer_id, "kind": "deterministic_derivation"}
            or record["inputs"][0]["source_id"] != expected_capture_id
        ):
            raise CampaignError("malformed", "review_coherence", case)
        observed_outputs.add(output_key)
    if observed_outputs != set(expected_outputs):
        raise CampaignError("malformed", "review_coherence", case)

    pair = lineage_pairs[0]
    if (
        not isinstance(pair, dict)
        or set(pair)
        != {"left_claim_index", "right_claim_index", "status", "input_relations"}
        or pair["left_claim_index"] != 0
        or pair["right_claim_index"] != 1
        or pair["status"] != "declared_shared_lineage"
        or not isinstance(pair["input_relations"], list)
        or len(pair["input_relations"]) != 2
    ):
        raise CampaignError("malformed", "review_coherence", case)
    observed_relation_indices = set()
    for relation in pair["input_relations"]:
        if (
            not isinstance(relation, dict)
            or set(relation) != {"left_input_index", "right_input_index", "comparison"}
            or relation.get("comparison")
            != {
                "content": "different_content_digest",
                "lineage": "shared_ancestor",
            }
        ):
            raise CampaignError("malformed", "review_coherence", case)
        observed_relation_indices.add(
            (relation["left_input_index"], relation["right_input_index"])
        )
    if observed_relation_indices != {(0, 0), (1, 1)}:
        raise CampaignError("malformed", "review_coherence", case)
    return families, pair["status"]


def extract_comparison_statuses(document: Any, case: int) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "input",
        "compare_with",
        "hypothesis",
        "content_relation",
        "composition",
        "limitations",
    }:
        raise CampaignError("malformed", "review_shape", case)
    try:
        basis = document["hypothesis"]["basis"]
        qualified_composition = document["composition"]
        canonical_composition = qualified_composition["composition"]
        claims = canonical_composition["claims"]
        canonical_capture_ids = (
            document["hypothesis"]["left"]["capture_id"],
            document["hypothesis"]["right"]["capture_id"],
        )
        composition_families, dependence_status = _validate_qualified_composition(
            qualified_composition, canonical_capture_ids, case
        )
        statuses = {
            "schema": document["schema"],
            "hypothesis_schema": document["hypothesis"]["schema"],
            "content_relation_schema": document["content_relation"]["schema"],
            "content_basis": document["content_relation"]["basis"]["basis"],
            "qualified_composition_schema": qualified_composition["schema"],
            "composition_schema": canonical_composition["schema"],
            "composition_claim_count": len(claims),
            "dependence": dependence_status,
            "basis": basis["status"],
            "reason": basis.get("reason", "none"),
            "input_status": document["input"]["status"]["status"],
            "compare_with_status": document["compare_with"]["status"]["status"],
            "input_capture_id": document["input"]["source"]["capture_id"],
            "compare_with_capture_id": document["compare_with"]["source"]["capture_id"],
            "canonical_left_capture_id": canonical_capture_ids[0],
            "canonical_right_capture_id": canonical_capture_ids[1],
        }
    except (KeyError, TypeError, AttributeError):
        raise CampaignError("malformed", "review_shape", case) from None
    for field in (
        "schema",
        "hypothesis_schema",
        "content_relation_schema",
        "content_basis",
        "qualified_composition_schema",
        "composition_schema",
        "dependence",
        "basis",
        "reason",
        "input_status",
        "compare_with_status",
    ):
        value = statuses[field]
        if not isinstance(value, str) or value not in COMPARISON_VOCABULARY[field]:
            raise CampaignError("malformed", "review_vocabulary", case)
    for field in (
        "input_capture_id",
        "compare_with_capture_id",
        "canonical_left_capture_id",
        "canonical_right_capture_id",
    ):
        if not isinstance(statuses[field], str) or not CAPTURE_ID_RE.fullmatch(
            statuses[field]
        ):
            raise CampaignError("malformed", "review_vocabulary", case)
    if (statuses["basis"] == "not_comparable") != (statuses["reason"] != "none"):
        raise CampaignError("malformed", "review_coherence", case)
    expected_reference = {
        "corroborated": {"hypothesis": "same_packet_shape"},
        "conflicting": {"hypothesis": "different_packet_shape"},
        "not_comparable": {
            "hypothesis": "unknown",
            "reason": statuses["reason"],
        },
    }[statuses["basis"]]
    if document["hypothesis"].get("reference") != expected_reference:
        raise CampaignError("malformed", "review_coherence", case)
    expected_content_reference = {
        "sha256_equal": {"hypothesis": "sha256_match"},
        "sha256_different": {"hypothesis": "sha256_mismatch"},
    }[statuses["content_basis"]]
    if document["content_relation"].get("reference") != expected_content_reference:
        raise CampaignError("malformed", "review_coherence", case)
    if (
        statuses["composition_claim_count"] != 2
        or composition_families != COMPOSITION_FAMILIES
    ):
        raise CampaignError("malformed", "review_coherence", case)
    return statuses


def evaluate_campaign(
    manifest_path: Path, binary: Path, repo_root: Path = REPO_ROOT
) -> tuple[int, dict[str, Any]]:
    cases, total_bytes = validate_manifest(manifest_path.resolve(), repo_root)
    results: list[dict[str, Any]] = []
    failures = 0

    for ordinal, case in enumerate(cases, start=1):
        input_path = case["path"]
        compare_with_path = case.get("compare_with_path")
        before = read_bounded(
            input_path,
            MAX_CASE_BYTES,
            too_large_stage="case_bytes",
            unavailable_stage="input_read",
            case=ordinal,
        )
        before_metadata = input_metadata(input_path, "input_read", ordinal)
        result: dict[str, Any] = {
            "case": ordinal,
            "operation": case["operation"],
            "input_bytes": len(before),
        }
        if len(before) != case["size"]:
            raise CampaignError("execution", "input_changed", ordinal)
        if hashlib.sha256(before).hexdigest() != case["sha256"]:
            raise CampaignError("malformed", "input_sha256", ordinal)

        compare_with_before = None
        compare_with_metadata = None
        if compare_with_path is not None:
            compare_with_before = read_bounded(
                compare_with_path,
                MAX_CASE_BYTES,
                too_large_stage="case_bytes",
                unavailable_stage="compare_with_read",
                case=ordinal,
            )
            compare_with_metadata = input_metadata(
                compare_with_path, "compare_with_read", ordinal
            )
            result["compare_with_bytes"] = len(compare_with_before)
            if len(compare_with_before) != case["compare_with_size"]:
                raise CampaignError("execution", "compare_with_changed", ordinal)
            if (
                hashlib.sha256(compare_with_before).hexdigest()
                != case["compare_with_sha256"]
            ):
                raise CampaignError("malformed", "compare_with_sha256", ordinal)

        outputs: list[bytes] = []
        for _ in range(2):
            outputs.append(run_review(binary, input_path, ordinal, compare_with_path))
            if (
                read_bounded(
                    input_path,
                    MAX_CASE_BYTES,
                    too_large_stage="case_bytes",
                    unavailable_stage="input_read",
                    case=ordinal,
                )
                != before
                or input_metadata(input_path, "input_read", ordinal) != before_metadata
            ):
                raise CampaignError("execution", "input_changed", ordinal)
            if compare_with_path is not None and (
                read_bounded(
                    compare_with_path,
                    MAX_CASE_BYTES,
                    too_large_stage="case_bytes",
                    unavailable_stage="compare_with_read",
                    case=ordinal,
                )
                != compare_with_before
                or input_metadata(compare_with_path, "compare_with_read", ordinal)
                != compare_with_metadata
            ):
                raise CampaignError("execution", "compare_with_changed", ordinal)
        first, second = outputs
        if first != second:
            raise CampaignError("execution", "nondeterministic_json", ordinal)

        document = load_json_strict(first, "review_json", ordinal)
        statuses = (
            extract_triage_statuses(document, ordinal)
            if case["operation"] == "triage"
            else extract_comparison_statuses(document, ordinal)
        )
        expected_fields = (
            TRIAGE_EXPECTED_FIELDS
            if case["operation"] == "triage"
            else COMPARISON_EXPECTED_FIELDS
        )
        mismatches = [
            field
            for field in expected_fields
            if statuses[field] != case["expect"][field]
        ]
        result.update(
            {
                field: value
                for field, value in statuses.items()
                if not field.endswith("capture_id")
            }
        )
        if mismatches:
            result.update({"result": "expectation_failure", "mismatches": mismatches})
            failures += 1
        else:
            result["result"] = "pass"
        results.append(result)

    status = "pass" if failures == 0 else "expectation_failure"
    report = {
        "schema": OUTPUT_SCHEMA,
        "status": status,
        "cases": len(cases),
        "expectation_failures": failures,
        "input_bytes": total_bytes,
        "limits": limits_metadata(),
        "results": results,
    }
    return (0 if failures == 0 else 1), report


def execute_campaign(
    manifest_path: Path, binary: Path, repo_root: Path = REPO_ROOT
) -> tuple[int, dict[str, Any]]:
    try:
        return evaluate_campaign(manifest_path, binary, repo_root)
    except CampaignError as error:
        return 2, error_report(error)


class EvaluatorSelfTests(unittest.TestCase):
    def make_campaign(
        self,
        root: Path,
        *,
        mode: str = "stable",
        expected_wlan: str = "observed",
        sha256: str | None = None,
    ) -> tuple[Path, Path]:
        input_path = root / "input.jsonl"
        input_path.write_bytes(b"fixture\n")
        digest = sha256 or hashlib.sha256(input_path.read_bytes()).hexdigest()
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "cases": [
                {
                    "operation": "triage",
                    "input": "input.jsonl",
                    "sha256": digest,
                    "expect": {
                        "schema": "netmon.saved_pcap_triage.v1",
                        "completeness": "complete_capture",
                        "wlan": expected_wlan,
                        "conversation": "observed",
                        "negative_claim": "not_requested",
                    },
                }
            ],
        }
        manifest_path = root / "campaign.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        binary = root / "fake-linktop"
        binary.write_text(
            "#!/usr/bin/env python3\n"
            "import json, pathlib, sys\n"
            "if len(sys.argv) != 6 or sys.argv[1] != 'review' or "
            "sys.argv[3:] != ['--json', '--max-input-mib', '128']:\n"
            "    raise SystemExit(9)\n"
            f"mode = {mode!r}\n"
            "input_path = pathlib.Path(sys.argv[2])\n"
            "if mode == 'mutate':\n"
            "    input_path.write_bytes(input_path.read_bytes() + b'x')\n"
            "payload = {\n"
            "    'schema': 'netmon.saved_pcap_triage.v1',\n"
            "    'normalization': {'completeness': 'complete_capture'},\n"
            "    'wlan': {'status': 'observed', 'endpoint': '192.0.2.1'},\n"
            "    'top_capture_conversation': {\n"
            "        'status': 'observed', 'alias': 'private-name',\n"
            "        'topology': {'peer': '198.51.100.2'}\n"
            "    },\n"
            "}\n"
            "if mode == 'vary':\n"
            "    counter = pathlib.Path(__file__).with_suffix('.count')\n"
            "    count = int(counter.read_text() or '0') if counter.exists() else 0\n"
            "    counter.write_text(str(count + 1))\n"
            "    print(json.dumps(payload, indent=(2 if count % 2 else None)))\n"
            "else:\n"
            "    print(json.dumps(payload, sort_keys=True))\n",
            encoding="utf-8",
        )
        binary.chmod(0o700)
        return manifest_path, binary

    def make_comparison_campaign(
        self,
        root: Path,
        *,
        mode: str = "stable",
        compare_with_sha256: str | None = None,
    ) -> tuple[Path, Path]:
        input_path = root / "input.jsonl"
        compare_with_path = root / "compare.jsonl"
        input_path.write_bytes(b"unsupported fixture\n")
        compare_with_path.write_bytes(b"observed fixture\n")
        input_capture_id = "sha256:" + "2" * 64
        compare_capture_id = "sha256:" + "0" * 64
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "cases": [
                {
                    "operation": "compare",
                    "input": input_path.name,
                    "sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
                    "compare_with": compare_with_path.name,
                    "compare_with_sha256": compare_with_sha256
                    or hashlib.sha256(compare_with_path.read_bytes()).hexdigest(),
                    "expect": {
                        "schema": "linktop.saved_pcap_comparison.v2",
                        "hypothesis_schema": (
                            "netmon.saved_pcap_fingerprint_hypothesis_set.v0"
                        ),
                        "content_relation_schema": (
                            "netbraid.content_relation_hypothesis_set.v0"
                        ),
                        "content_basis": "sha256_different",
                        "qualified_composition_schema": (
                            "netbraid.provenance_qualified_finite_hypothesis_"
                            "composition.v0"
                        ),
                        "composition_schema": (
                            "netbraid.finite_hypothesis_composition.v0"
                        ),
                        "composition_claim_count": 2,
                        "dependence": "declared_shared_lineage",
                        "basis": "not_comparable",
                        "reason": "right_not_observed",
                        "input_status": "unsupported",
                        "compare_with_status": "observed",
                        "input_capture_id": input_capture_id,
                        "compare_with_capture_id": compare_capture_id,
                        "canonical_left_capture_id": compare_capture_id,
                        "canonical_right_capture_id": input_capture_id,
                    },
                }
            ],
        }
        manifest_path = root / "comparison-campaign.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        binary = root / "fake-linktop"
        binary.write_text(
            "#!/usr/bin/env python3\n"
            "import json, pathlib, sys\n"
            "if len(sys.argv) != 8 or sys.argv[1] != 'review' or "
            "sys.argv[3] != '--compare-with' or "
            "sys.argv[5:] != ['--json', '--max-input-mib', '128']:\n"
            "    raise SystemExit(9)\n"
            f"mode = {mode!r}\n"
            "input_path = pathlib.Path(sys.argv[2])\n"
            "compare_path = pathlib.Path(sys.argv[4])\n"
            "if mode == 'mutate_compare':\n"
            "    compare_path.write_bytes(compare_path.read_bytes() + b'x')\n"
            f"input_id = {input_capture_id!r}\n"
            f"compare_id = {compare_capture_id!r}\n"
            "if mode == 'swap':\n"
            "    input_id, compare_id = compare_id, input_id\n"
            f"left_id = {compare_capture_id!r}\n"
            f"right_id = {input_capture_id!r}\n"
            "left_root = {'source_schema': 'netmon.capture_manifest.v0', "
            "'source_id': left_id, 'content_sha256': '0' * 64}\n"
            "right_root = {'source_schema': 'netmon.capture_manifest.v0', "
            "'source_id': right_id, 'content_sha256': '2' * 64}\n"
            "content_inputs = [\n"
            "    {'role': 'left_content_evidence', 'source_schema': "
            "'netbraid.content_digest_evidence.v0', 'source_id': "
            "left_id + ':artifact-content', 'content_sha256': 'a' * 64},\n"
            "    {'role': 'right_content_evidence', 'source_schema': "
            "'netbraid.content_digest_evidence.v0', 'source_id': "
            "right_id + ':artifact-content', 'content_sha256': 'b' * 64},\n"
            "]\n"
            "packet_inputs = [\n"
            "    {'role': 'left_candidate', 'source_schema': "
            "'netmon.saved_pcap_fingerprint_candidate.v0', 'source_id': "
            "left_id, 'content_sha256': 'c' * 64},\n"
            "    {'role': 'right_candidate', 'source_schema': "
            "'netmon.saved_pcap_fingerprint_candidate.v0', 'source_id': "
            "right_id, 'content_sha256': 'd' * 64},\n"
            "]\n"
            "content_key = {'family_schema': "
            "'netbraid.content_relation_hypothesis_set.v0', 'reducer': "
            "'netbraid.content_relation.sha256.v0', 'inputs': content_inputs}\n"
            "packet_key = {'family_schema': "
            "'netmon.saved_pcap_fingerprint_hypothesis_set.v0', 'reducer': "
            "'netbraid.saved_pcap_fingerprint.packet_shape.v0', "
            "'inputs': packet_inputs}\n"
            "records = []\n"
            "for output, root, producer_id in [\n"
            "    (content_inputs[0], left_root, "
            "'linktop:review:artifact-content'),\n"
            "    (content_inputs[1], right_root, "
            "'linktop:review:artifact-content'),\n"
            "    (packet_inputs[0], left_root, "
            "'netbraid:project-saved-pcap-fingerprint-v0'),\n"
            "    (packet_inputs[1], right_root, "
            "'netbraid:project-saved-pcap-fingerprint-v0'),\n"
            "]:\n"
            "    records.append({\n"
            "        'schema': 'netbraid.provenance_record.v0',\n"
            "        'output': {key: value for key, value in output.items() "
            "if key != 'role'},\n"
            "        'producer': {'producer_id': producer_id, "
            "'kind': 'software'},\n"
            "        'activity': {'activity_id': producer_id, "
            "'kind': 'deterministic_derivation'},\n"
            "        'inputs': [root],\n"
            "    })\n"
            "payload = {\n"
            "    'schema': 'linktop.saved_pcap_comparison.v2',\n"
            "    'input': {'source': {'capture_id': input_id}, "
            "'status': {'status': 'unsupported'}},\n"
            "    'compare_with': {'source': {'capture_id': compare_id}, "
            "'status': {'status': 'observed'}},\n"
            "    'hypothesis': {\n"
            "        'schema': "
            "'netmon.saved_pcap_fingerprint_hypothesis_set.v0',\n"
            f"        'left': {{'capture_id': {compare_capture_id!r}}},\n"
            f"        'right': {{'capture_id': {input_capture_id!r}}},\n"
            "        'basis': {'status': 'not_comparable', "
            "'reason': 'right_not_observed'},\n"
            "        'reference': {'hypothesis': 'unknown', "
            "'reason': 'right_not_observed'},\n"
            "    },\n"
            "    'content_relation': {\n"
            "        'schema': 'netbraid.content_relation_hypothesis_set.v0',\n"
            "        'basis': {'basis': 'sha256_different'},\n"
            "        'reference': {'hypothesis': 'sha256_mismatch'},\n"
            "    },\n"
            "    'composition': {\n"
            "        'schema': "
            "'netbraid.provenance_qualified_finite_hypothesis_composition.v0',\n"
            "        'composition': {\n"
            "            'schema': 'netbraid.finite_hypothesis_composition.v0',\n"
            "            'claims': [\n"
            "                {'schema': 'netbraid.finite_hypothesis_claim.v0', "
            "'projection': {'schema': "
            "'netbraid.finite_hypothesis_projection.v0', 'family_schema': "
            "content_key['family_schema'], 'reducer': content_key['reducer'], "
            "'alternatives': []}, 'inputs': content_inputs},\n"
            "                {'schema': 'netbraid.finite_hypothesis_claim.v0', "
            "'projection': {'schema': "
            "'netbraid.finite_hypothesis_projection.v0', 'family_schema': "
            "packet_key['family_schema'], 'reducer': packet_key['reducer'], "
            "'alternatives': []}, 'inputs': packet_inputs},\n"
            "            ],\n"
            "        },\n"
            "        'provenance_graph': {\n"
            "            'schema': 'netbraid.provenance_graph.v0',\n"
            "            'records': records,\n"
            "        },\n"
            "        'claim_lineage_pairs': [{\n"
            "            'left_claim_index': 0, 'right_claim_index': 1,\n"
            "            'status': 'declared_shared_lineage',\n"
            "            'input_relations': [\n"
            "                {'left_input_index': 0, 'right_input_index': 0, "
            "'comparison': {'content': 'different_content_digest', "
            "'lineage': 'shared_ancestor'}},\n"
            "                {'left_input_index': 1, 'right_input_index': 1, "
            "'comparison': {'content': 'different_content_digest', "
            "'lineage': 'shared_ancestor'}},\n"
            "            ],\n"
            "        }],\n"
            "    },\n"
            "    'limitations': [],\n"
            "}\n"
            "if mode == 'bad_composition':\n"
            "    payload['composition']['composition']['claims'].pop()\n"
            "if mode == 'empty_lineage_pairs':\n"
            "    payload['composition']['claim_lineage_pairs'].clear()\n"
            "if mode == 'missing_provenance_record':\n"
            "    payload['composition']['provenance_graph']['records'].pop()\n"
            "if mode == 'bad_content_reference':\n"
            "    payload['content_relation']['reference'] = "
            "{'hypothesis': 'sha256_match'}\n"
            "print(json.dumps(payload, sort_keys=True))\n",
            encoding="utf-8",
        )
        binary.chmod(0o700)
        return manifest_path, binary

    def test_pass_is_metadata_only_and_preserves_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, binary = self.make_campaign(root)
            before = (root / "input.jsonl").read_bytes()
            code, report = execute_campaign(manifest, binary, root)
            rendered = json.dumps(report, sort_keys=True)
            self.assertEqual(code, 0)
            self.assertEqual(report["status"], "pass")
            self.assertEqual((root / "input.jsonl").read_bytes(), before)
            self.assertNotIn(str(root), rendered)
            self.assertNotIn("192.0.2.1", rendered)
            self.assertNotIn("private-name", rendered)
            self.assertNotIn("198.51.100.2", rendered)

    def test_comparison_preserves_cli_roles_inputs_and_metadata_only_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, binary = self.make_comparison_campaign(root)
            input_before = (root / "input.jsonl").read_bytes()
            compare_before = (root / "compare.jsonl").read_bytes()
            code, report = execute_campaign(manifest, binary, root)
            rendered = json.dumps(report, sort_keys=True)
            self.assertEqual((code, report["status"]), (0, "pass"))
            self.assertEqual((root / "input.jsonl").read_bytes(), input_before)
            self.assertEqual((root / "compare.jsonl").read_bytes(), compare_before)
            self.assertEqual(report["results"][0]["operation"], "compare")
            self.assertNotIn("sha256:", rendered)
            self.assertNotIn(str(root), rendered)

    def test_comparison_rejects_second_input_mutation_and_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, binary = self.make_comparison_campaign(
                root, mode="mutate_compare"
            )
            code, report = execute_campaign(manifest, binary, root)
            self.assertEqual(code, 2)
            self.assertEqual(report["error"]["stage"], "compare_with_changed")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, binary = self.make_comparison_campaign(
                root, compare_with_sha256="0" * 64
            )
            code, report = execute_campaign(manifest, binary, root)
            self.assertEqual(code, 2)
            self.assertEqual(report["error"]["stage"], "compare_with_sha256")

    def test_comparison_cli_role_swap_is_an_expectation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, binary = self.make_comparison_campaign(root, mode="swap")
            code, report = execute_campaign(manifest, binary, root)
            self.assertEqual((code, report["status"]), (1, "expectation_failure"))
            self.assertEqual(
                report["results"][0]["mismatches"],
                ["input_capture_id", "compare_with_capture_id"],
            )

    def test_comparison_rejects_incoherent_composition_and_content_claim(self) -> None:
        for mode in (
            "bad_composition",
            "bad_content_reference",
            "empty_lineage_pairs",
            "missing_provenance_record",
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest, binary = self.make_comparison_campaign(root, mode=mode)
                code, report = execute_campaign(manifest, binary, root)
                self.assertEqual(code, 2)
                self.assertEqual(report["error"]["stage"], "review_coherence")

    def test_expectation_mismatch_exits_one_and_sha256_mismatch_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, binary = self.make_campaign(root, expected_wlan="unsupported")
            code, report = execute_campaign(manifest, binary, root)
            self.assertEqual((code, report["status"]), (1, "expectation_failure"))
            manifest, binary = self.make_campaign(root, sha256="0" * 64)
            code, report = execute_campaign(manifest, binary, root)
            self.assertEqual(code, 2)
            self.assertEqual(report["error"]["stage"], "input_sha256")

    def test_nondeterminism_and_input_mutation_exit_two(self) -> None:
        for mode, stage in [
            ("vary", "nondeterministic_json"),
            ("mutate", "input_changed"),
        ]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest, binary = self.make_campaign(root, mode=mode)
                code, report = execute_campaign(manifest, binary, root)
                self.assertEqual(code, 2)
                self.assertEqual(report["error"]["stage"], stage)

    def test_timeout_kills_descendant_after_leader_exit(self) -> None:
        global REVIEW_TIMEOUT_SECONDS
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "leader"
            pid_file = root / "child.pid"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, subprocess, sys\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import time; time.sleep(60)'])\n"
                f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            previous_timeout = REVIEW_TIMEOUT_SECONDS
            REVIEW_TIMEOUT_SECONDS = 1.0
            try:
                with self.assertRaises(CampaignError) as raised:
                    run_review(binary, root / "unused", 1)
                self.assertEqual(raised.exception.stage, "review_timeout")
            finally:
                REVIEW_TIMEOUT_SECONDS = previous_timeout
            deadline = time.monotonic() + 1
            while not pid_file.exists():
                if time.monotonic() >= deadline:
                    self.fail("timed-out review leader never recorded its child")
                time.sleep(0.01)
            child_pid = int(pid_file.read_text())
            while True:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() >= deadline:
                    self.fail("timed-out review descendant survived")
                time.sleep(0.01)

    def test_manifest_bounds_and_vocabulary_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, binary = self.make_campaign(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["cases"] *= MAX_CASES + 1
            manifest.write_text(json.dumps(document), encoding="utf-8")
            code, report = execute_campaign(manifest, binary, root)
            self.assertEqual(code, 2)
            self.assertEqual(report["error"]["stage"], "case_count")

            manifest, binary = self.make_campaign(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["cases"][0]["expect"]["wlan"] = "invented"
            manifest.write_text(json.dumps(document), encoding="utf-8")
            code, report = execute_campaign(manifest, binary, root)
            self.assertEqual(code, 2)
            self.assertEqual(report["error"]["stage"], "expectation_vocabulary")

            manifest, binary = self.make_campaign(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            del document["cases"][0]["operation"]
            manifest.write_text(json.dumps(document), encoding="utf-8")
            code, report = execute_campaign(manifest, binary, root)
            self.assertEqual(code, 2)
            self.assertEqual(report["error"]["stage"], "case_shape")

            manifest.write_bytes(b"{")
            code, report = execute_campaign(manifest, binary, root)
            self.assertEqual(code, 2)
            self.assertEqual(report["error"]["stage"], "manifest_json")

    def test_case_and_total_byte_bounds_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, binary = self.make_campaign(root)
            (root / "input.jsonl").write_bytes(b"")
            (root / "input.jsonl").open("ab").truncate(MAX_CASE_BYTES + 1)
            code, report = execute_campaign(manifest, binary, root)
            self.assertEqual(code, 2)
            self.assertEqual(report["error"]["stage"], "case_bytes")

            manifest, binary = self.make_campaign(root)
            (root / "input.jsonl").open("ab").truncate(MAX_CASE_BYTES)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["cases"] *= 5
            manifest.write_text(json.dumps(document), encoding="utf-8")
            code, report = execute_campaign(manifest, binary, root)
            self.assertEqual(code, 2)
            self.assertEqual(report["error"]["stage"], "total_bytes")


def run_self_tests() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvaluatorSelfTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "manifest",
        nargs="?",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="campaign manifest (default: checked repository fixture)",
    )
    parser.add_argument(
        "--linktop",
        type=Path,
        default=Path("target/debug/linktop"),
        help="linktop executable (default: target/debug/linktop)",
    )
    parser.add_argument(
        "--self-test", action="store_true", help="run focused evaluator tests"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_tests()
    code, report = execute_campaign(args.manifest, args.linktop)
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
