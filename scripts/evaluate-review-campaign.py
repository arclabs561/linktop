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

MANIFEST_SCHEMA = "linktop.review_campaign.v0"
OUTPUT_SCHEMA = "linktop.review_campaign_eval.v0"
REVIEW_SCHEMAS = frozenset({"netmon.saved_pcap_triage.v1"})
COMPLETENESS_STATUSES = frozenset({"complete_capture", "partial_packet_subset"})
WLAN_STATUSES = frozenset({"insufficient", "unsupported", "not_observed", "observed"})
CONVERSATION_STATUSES = frozenset({"insufficient", "unsupported", "observed"})
NEGATIVE_CLAIM_STATUSES = frozenset({"not_requested", "qualified", "abstained"})
EXPECTED_FIELDS = (
    "schema",
    "completeness",
    "wlan",
    "conversation",
    "negative_claim",
)
VOCABULARY = {
    "schema": REVIEW_SCHEMAS,
    "completeness": COMPLETENESS_STATUSES,
    "wlan": WLAN_STATUSES,
    "conversation": CONVERSATION_STATUSES,
    "negative_claim": NEGATIVE_CLAIM_STATUSES,
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "fixtures/review-campaign-v0.json"


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
    except (DuplicateKeyError, UnicodeDecodeError, json.JSONDecodeError):
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
        if not isinstance(case, dict) or set(case) != {"input", "sha256", "expect"}:
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
        if not isinstance(expected, dict) or set(expected) != set(EXPECTED_FIELDS):
            raise CampaignError("malformed", "expectation_shape", ordinal)
        for field in EXPECTED_FIELDS:
            if expected[field] not in VOCABULARY[field]:
                raise CampaignError("malformed", "expectation_vocabulary", ordinal)

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
        validated.append(
            {
                "path": input_path,
                "sha256": expected_sha256,
                "expect": expected,
                "size": file_stat.st_size,
            }
        )
    return validated, total_bytes


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass


def run_review(binary: Path, input_path: Path, case: int) -> bytes:
    argv = [
        os.fspath(binary),
        "review",
        os.fspath(input_path),
        "--json",
        "--max-input-mib",
        str(REVIEW_MAX_INPUT_MIB),
    ]
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


def extract_statuses(document: Any, case: int) -> dict[str, str]:
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
        if not isinstance(value, str) or value not in VOCABULARY[field]:
            raise CampaignError("malformed", "review_vocabulary", case)
    return statuses


def evaluate_campaign(
    manifest_path: Path, binary: Path, repo_root: Path = REPO_ROOT
) -> tuple[int, dict[str, Any]]:
    cases, total_bytes = validate_manifest(manifest_path.resolve(), repo_root)
    results: list[dict[str, Any]] = []
    failures = 0

    for ordinal, case in enumerate(cases, start=1):
        input_path = case["path"]
        before = read_bounded(
            input_path,
            MAX_CASE_BYTES,
            too_large_stage="case_bytes",
            unavailable_stage="input_read",
            case=ordinal,
        )
        result: dict[str, Any] = {
            "case": ordinal,
            "input_bytes": len(before),
        }
        if len(before) != case["size"]:
            raise CampaignError("execution", "input_changed", ordinal)
        if hashlib.sha256(before).hexdigest() != case["sha256"]:
            raise CampaignError("malformed", "input_sha256", ordinal)

        first = run_review(binary, input_path, ordinal)
        if (
            read_bounded(
                input_path,
                MAX_CASE_BYTES,
                too_large_stage="case_bytes",
                unavailable_stage="input_read",
                case=ordinal,
            )
            != before
        ):
            raise CampaignError("execution", "input_changed", ordinal)
        second = run_review(binary, input_path, ordinal)
        if (
            read_bounded(
                input_path,
                MAX_CASE_BYTES,
                too_large_stage="case_bytes",
                unavailable_stage="input_read",
                case=ordinal,
            )
            != before
        ):
            raise CampaignError("execution", "input_changed", ordinal)
        if first != second:
            raise CampaignError("execution", "nondeterministic_json", ordinal)

        statuses = extract_statuses(
            load_json_strict(first, "review_json", ordinal), ordinal
        )
        mismatches = [
            field
            for field in EXPECTED_FIELDS
            if statuses[field] != case["expect"][field]
        ]
        result.update(statuses)
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
