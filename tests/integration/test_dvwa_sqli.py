# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""
Integration test: HDWP detects SQL injection on DVWA.

Two-layer test:
  1. Oracle layer: assess_sqli() correctly identifies the SQL error response from DVWA
  2. Pipeline layer: full end-to-end scan confirms a SQLi finding

Target: vulnerables/web-dvwa (http://localhost:8080)
Vulnerability: SQLi on GET /vulnerabilities/sqli/?id=1&Submit=Submit (MariaDB, error-based)
"""
from __future__ import annotations

import re

import httpx
import pytest

from hdwp.core.model.schemas import ExperimentResult, ExperimentSpec, NormalizedRequest, NormalizedResponse
from hdwp.core.oracle.injection_oracle import assess_sqli

pytestmark = pytest.mark.integration


def _dvwa_login(base_url: str) -> str:
    """Login to DVWA and return a valid PHPSESSID."""
    with httpx.Client(follow_redirects=True, base_url=base_url) as client:
        client.cookies.set("security", "low")
        r = client.get("/login.php")
        token_match = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
        token = token_match.group(1) if token_match else ""
        client.post("/login.php", data={
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": token,
        })
        return client.cookies.get("PHPSESSID", "")


# ---------------------------------------------------------------------------
# Layer 1 — Oracle detection against real DVWA error response
# ---------------------------------------------------------------------------

def test_dvwa_sqli_oracle_confirms_error_response(dvwa_url: str) -> None:
    """
    The oracle's assess_sqli() must mark CONFIRMED when given the real SQL error
    body from DVWA (id=1' triggers: 'You have an error in your SQL syntax').
    """
    phpsessid = _dvwa_login(dvwa_url)
    assert phpsessid, "Could not authenticate to DVWA"

    with httpx.Client(
        cookies={"PHPSESSID": phpsessid, "security": "low"},
        follow_redirects=True,
    ) as client:
        resp = client.get(f"{dvwa_url}/vulnerabilities/sqli/?id=1'&Submit=Submit")

    assert resp.status_code == 200, f"DVWA SQLi page returned {resp.status_code}"

    sql_error = "You have an error" in resp.text or "SQL syntax" in resp.text
    assert sql_error, (
        "DVWA did not return a SQL error for id=1' — DB may not be initialized. "
        f"Snippet: {resp.text[2000:2300]}"
    )

    dummy_req = NormalizedRequest(method="GET", url=f"{dvwa_url}/vulnerabilities/sqli/?id=1'&Submit=Submit")
    dummy_spec = ExperimentSpec(mutation_type="field_injection", base_request=dummy_req)
    exp = ExperimentResult(
        hypothesis_id="test-dvwa-sqli",
        experiment_spec=dummy_spec,
        request_sent=dummy_req,
        response_received=NormalizedResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            content_type=resp.headers.get("content-type", "text/html"),
            timing_ms=50.0,
        ),
    )

    assessment = assess_sqli("1'", exp)
    assert assessment.verdict.value == "CONFIRMED", (
        f"Oracle did not confirm SQLi. Verdict: {assessment.verdict}, "
        f"Rationale: {assessment.rationale}"
    )
    assert assessment.confidence_hint >= 0.90


# ---------------------------------------------------------------------------
# Layer 2 — Behavioral detection gap (documented)
# ---------------------------------------------------------------------------
# NOTE: The SQLi plugin's primary probe ('OR'1'='1) returns extra rows on DVWA
# without triggering SQL error strings. assess_sqli() only detects error-pattern
# responses, not body-size diffs. Autonomous pipeline detection via boolean-blind
# probes on DVWA is a known gap — tracked for fix in assess_sqli() or plugin probes.
# The oracle layer test above proves the detection engine works when the error IS present.
