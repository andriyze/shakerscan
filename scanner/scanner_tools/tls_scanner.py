import json
import os
import re
from datetime import UTC, datetime
from typing import Any

from .common import run


async def tlsx_probe(host: str, port: int) -> dict[str, Any]:
    tlsx_cmd = "/opt/tools/tlsx" if os.path.exists("/opt/tools/tlsx") else "tlsx"
    # Add timeout, san flags and explicit resolver (Docker DNS not compatible with tlsx's fastdialer)
    out, err, rc = await run([tlsx_cmd, "-host", f"{host}:{port}", "-json", "-san", "-timeout", "30", "-resolvers", "8.8.8.8,1.1.1.1"], timeout=60)
    endpoints, cert = [], {}
    if rc == 0 and out:
        for line in out.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            endpoints.append({
                "ip": row.get("ip"),
                "port": row.get("port"),
                "tlsversion": row.get("tls_version") or row.get("tlsversion"),
                "cipher": row.get("cipher"),
                "alpn": row.get("alpn"),
                "handshake_completed": row.get("handshake_completed") or row.get("probe_status"),
            })
            # Handle both old format (certificate_response) and new format (flat fields)
            if not cert:
                c = row.get("certificate_response") or row
                # Check if we have certificate data
                if c.get("subject_dn") or c.get("subject_cn") or c.get("not_before"):
                    cert = {
                        "subject": c.get("subject_dn") or c.get("subject_cn"),
                        "issuer": c.get("issuer_dn"),
                        "issuer_org": c.get("issuer_org"),
                        "issuer_cn": c.get("issuer_cn"),
                        "sans": c.get("dns_names") or c.get("subject_an"),  # subject_an is new field name
                        "not_before": c.get("not_before"),
                        "not_after": c.get("not_after"),
                        "key_algo": c.get("public_key_info", {}).get("key_algorithm") if isinstance(c.get("public_key_info"), dict) else None,
                        "key_size": c.get("public_key_info", {}).get("key_size") if isinstance(c.get("public_key_info"), dict) else None,
                        "sig_algo": c.get("signature_algorithm"),
                        "ocsp_urls": c.get("ocsp_urls"),
                        "ca_issuer_urls": c.get("ca_issuers_urls"),
                        "serial": c.get("serial"),
                        "fingerprints": c.get("fingerprint_hash"),
                        "wildcard": c.get("wildcard_certificate"),
                    }
    return {"endpoints": endpoints, "certificate": cert}

def days_until(iso_dt: str | None) -> int | None:
    if not iso_dt:
        return None
    try:
        dt = datetime.fromisoformat(iso_dt.replace("Z", "+00:00"))
        return int((dt - datetime.now(UTC)).total_seconds() // 86400)
    except Exception:
        try:
            clean_dt = iso_dt.split('\n')[0].split(';')[0].strip()
            fmt = "%b %d %H:%M:%S %Y GMT"
            dt = datetime.strptime(clean_dt, fmt).replace(tzinfo=UTC)
            return int((dt - datetime.now(UTC)).total_seconds() // 86400)
        except Exception:
            return None


async def openssl_ocsp(host: str, port: int) -> dict[str, Any]:
    out, err, rc = await run(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-status"], timeout=45)
    stapled = False
    ocsp_url = None
    if out:
        stapled = "OCSP response:" in out and "no response sent" not in out
        m = re.search(r"OCSP\s+-\s+URI:(\S+)", out)
        if m:
            ocsp_url = m.group(1)
    return {"stapled": stapled, "ocsp_url": ocsp_url, "raw": (out or err)[:1500]}


async def testssl(host: str, port: int) -> dict[str, Any]:
    testssl_bin = os.environ.get("TESTSSL_BIN", "/opt/testssl.sh/testssl.sh")
    # Prefer JSON output; if unavailable, fall back to text mode
    out, err, rc = await run([testssl_bin, f"{host}:{port}", "-U", "--warnings", "off", "--quiet", "--openssl-timeout", "30", "--jsonfile", "-"], timeout=300)
    issues = []
    supports_tls13 = None
    raw_present = bool(out)
    scan_completed = False
    if rc == 0 and out:
        scan_completed = True  # Tool executed successfully
        try:
            data = json.loads(out)
            for entry in data.get("scanResult", []):
                finding = entry.get("finding", "")
                id_ = entry.get("id", "")
                severity = entry.get("severity", "")
                if id_ and severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                    issues.append({"id": id_, "severity": severity, "finding": finding})
                if id_ == "TLS13" and "offered" in finding.lower():
                    supports_tls13 = True
        except Exception:
            # JSON parse failed but tool ran - keep scan_completed = True
            pass
    if (rc != 0 or not issues) and not raw_present:
        # Text fallback to at least detect TLS1.3 and expose raw output
        txt_out, txt_err, txt_rc = await run([testssl_bin, f"{host}:{port}", "-U", "--warnings", "off", "--quiet", "--openssl-timeout", "30"], timeout=240)
        raw_present = raw_present or bool(txt_out or txt_err)
        if txt_rc == 0:
            scan_completed = True  # Text fallback executed successfully
        if (txt_out or txt_err):
            text = (txt_out or txt_err).lower()
            if "tls 1.3" in text and ("offered" in text or "supported" in text):
                supports_tls13 = True
            # We keep issues empty in text fallback to avoid false positives
    return {"supports_tls13": supports_tls13, "issues": issues, "raw_present": raw_present, "scan_completed": scan_completed}


async def sslyze_scan(host: str, port: int) -> dict[str, Any]:
    results = {
        "certificate_chain": [],
        "cipher_suites": {},
        "vulnerabilities": [],
        "tls_versions": {},
        "ocsp_stapling": False,
        "session_resumption": {},
        "scan_completed": False,
    }
    # Resolve sslyze binary robustly (PATH, /opt/tools, or Python module)
    # Note: SSLyze doesn't support --version, use -h instead to check availability
    sslyze_cmd = "/opt/tools/sslyze" if os.path.exists("/opt/tools/sslyze") else "sslyze"
    test_out, test_err, test_rc = await run([sslyze_cmd, "-h"], timeout=5)
    if test_rc != 0:
        # Fallback: call via python module if CLI is not on PATH
        py_bin = "python3"
        test_out2, test_err2, test_rc2 = await run([py_bin, "-m", "sslyze", "-h"], timeout=5)
        if test_rc2 != 0:
            return {"error": "SSLyze not installed", "scan_completed": False}
        sslyze_cmd = [py_bin, "-m", "sslyze"]
    cmd = ([sslyze_cmd] if isinstance(sslyze_cmd, str) else sslyze_cmd) + [
        f"{host}:{port}",
        "--json_out=-",
        "--sslv2",
        "--sslv3",
        "--tlsv1",
        "--tlsv1_1",
        "--tlsv1_2",
        "--tlsv1_3",
        "--certinfo",
        "--reneg",
        "--resum",
        "--heartbleed",
        "--openssl_ccs",
        "--fallback",
        "--compression",
        "--robot",
    ]
    out, err, rc = await run(cmd, timeout=180)
    if rc == 0:
        results["scan_completed"] = True  # Tool executed successfully
    if rc == 0 and out:
        try:
            data = json.loads(out)
            # Support both SSLyze 5.x (accepted_targets) and 6.x (server_scan_results)
            is_v6 = "server_scan_results" in data
            if is_v6:
                # SSLyze 6.x format - results are under scan_result directly
                server_results = data.get("server_scan_results", [])
                scan_result = server_results[0].get("scan_result") if server_results else None
                if scan_result is None:
                    scan_result = {}
                cert_info = scan_result.get("certificate_info", {}).get("result", {})
            else:
                # SSLyze 5.x format - results are under commands_results
                accepted = data.get("accepted_targets", [])
                scan_result = accepted[0] if accepted else {}
                cert_info = scan_result.get("commands_results", {}).get("certificate_info", {})

            # Helper function to get command results (handles both formats)
            def get_cmd(key):
                if is_v6:
                    return scan_result.get(key, {})
                return scan_result.get("commands_results", {}).get(key, {})

            if cert_info.get("certificate_deployments"):
                for deployment in cert_info["certificate_deployments"]:
                    chain = deployment.get("received_certificate_chain", [])
                    for cert in chain:
                        subject = cert.get("subject", {})
                        issuer = cert.get("issuer", {})
                        results["certificate_chain"].append({
                            "subject": subject,
                            "issuer": issuer,
                            "not_before": cert.get("not_valid_before"),
                            "not_after": cert.get("not_valid_after"),
                            "signature_algorithm": cert.get("signature_hash_algorithm", {}).get("name"),
                            "public_key_algorithm": cert.get("public_key", {}).get("algorithm"),
                        })
                    ocsp_response = deployment.get("ocsp_response")
                    results["ocsp_stapling"] = ocsp_response is not None
            protocols = ["ssl_2_0", "ssl_3_0", "tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"]
            for proto in protocols:
                proto_result = get_cmd(f"{proto}_cipher_suites")
                if proto_result:
                    accepted_ciphers = proto_result.get("accepted_cipher_suites", [])
                    if accepted_ciphers:
                        results["tls_versions"][proto] = True
                        results["cipher_suites"][proto] = []
                        for cipher in accepted_ciphers:
                            cipher_info = {
                                "name": cipher.get("cipher_suite", {}).get("name"),
                                "key_size": cipher.get("cipher_suite", {}).get("key_size"),
                                "is_anonymous": cipher.get("cipher_suite", {}).get("is_anonymous", False),
                            }
                            results["cipher_suites"][proto].append(cipher_info)
                            if cipher_info["is_anonymous"] or cipher_info.get("key_size", 256) < 128:
                                results["vulnerabilities"].append({
                                    "type": "weak_cipher",
                                    "protocol": proto,
                                    "details": f"Weak cipher: {cipher_info['name']}",
                                })
            heartbleed = get_cmd("heartbleed")
            # SSLyze 6.x uses result.is_vulnerable_to_heartbleed, 5.x uses is_vulnerable_to_heartbleed directly
            hb_result = heartbleed.get("result", heartbleed) if is_v6 else heartbleed
            if hb_result.get("is_vulnerable_to_heartbleed"):
                results["vulnerabilities"].append({
                    "type": "heartbleed",
                    "severity": "critical",
                    "cve": "CVE-2014-0160",
                })
            robot = get_cmd("robot")
            robot_result = robot.get("result", robot) if is_v6 else robot
            robot_enum = robot_result.get("robot_result_enum") or robot_result.get("robot_result")
            if robot_enum in ["VULNERABLE_STRONG_ORACLE", "VULNERABLE_WEAK_ORACLE"]:
                results["vulnerabilities"].append({
                    "type": "robot",
                    "severity": "high",
                    "details": str(robot_enum),
                })
            ccs_injection = get_cmd("openssl_ccs_injection")
            ccs_result = ccs_injection.get("result", ccs_injection) if is_v6 else ccs_injection
            if ccs_result.get("is_vulnerable_to_ccs_injection"):
                results["vulnerabilities"].append({
                    "type": "ccs_injection",
                    "severity": "high",
                    "cve": "CVE-2014-0224",
                })
            compression = get_cmd("tls_compression") if is_v6 else get_cmd("compression")
            comp_result = compression.get("result", compression) if is_v6 else compression
            if comp_result.get("compression_name") or comp_result.get("supports_compression"):
                results["vulnerabilities"].append({
                    "type": "crime",
                    "severity": "medium",
                    "details": f"Compression enabled: {comp_result.get('compression_name', 'TLS compression')}",
                })
            session_resum = get_cmd("session_resumption")
            resum_result = session_resum.get("result", session_resum) if is_v6 else session_resum
            if resum_result:
                results["session_resumption"] = {
                    "session_id": resum_result.get("is_session_id_resumption_supported"),
                    "tls_ticket": resum_result.get("is_tls_ticket_resumption_supported"),
                }
        except json.JSONDecodeError:
            results["error"] = "Failed to parse SSLyze output"
    return results


def parse_openssl_cert(raw: str) -> dict:
    if not raw:
        return {}
    out: dict[str, Any] = {}
    m = re.search(r"\n\s*0\s+s:(.+)\n\s*i:(.+)\n", raw)
    if m:
        out["subject"] = m.group(1).strip()
        out["issuer"] = m.group(2).strip()
    m2 = re.search(r"v:NotBefore:\s*([^;\n]+);\s*NotAfter:\s*([^\n]+)", raw)
    if m2:
        nb = m2.group(1).strip()
        na = m2.group(2).strip()
        try:
            fmt = "%b %d %H:%M:%S %Y %Z"
            nb_dt = datetime.strptime(nb, fmt).replace(tzinfo=UTC)
            na_dt = datetime.strptime(na, fmt).replace(tzinfo=UTC)
            out["not_before"] = nb_dt.isoformat()
            out["not_after"] = na_dt.isoformat()
        except Exception:
            out["not_before"] = nb
            out["not_after"] = na
    km = re.search(r"a:PKEY:\s*([^\s,]+),\s*([\d]+)", raw)
    if km:
        out["key_algo"] = km.group(1)
        try:
            out["key_size"] = int(km.group(2))
        except Exception:
            out["key_size"] = km.group(2)
    sm = re.search(r"sigalg:\s*([^\s]+)", raw)
    if sm:
        out["sig_algo"] = sm.group(1)
    return out
