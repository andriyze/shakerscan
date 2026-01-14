"""
Scan Delta / Change Detection Module

Compares current scan results against a baseline to identify:
- New findings (in current but not in baseline)
- Resolved findings (in baseline but not in current)
- Score and grade changes

Enables "continuous monitoring" by tracking what changed between scans.
"""

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


def find_previous_scan_key(
    s3_client,
    bucket_name: str,
    hostname: str,
    current_scan_key: str | None = None,
    max_lookback: int = 10
) -> str | None:
    """
    Find the most recent previous scan for a hostname in S3.

    Args:
        s3_client: boto3 S3 client
        bucket_name: S3 bucket name
        hostname: Target hostname (e.g., "example.com")
        current_scan_key: Current scan's S3 key to exclude
        max_lookback: Maximum number of scans to look back

    Returns:
        S3 key of the previous scan, or None if not found
    """
    try:
        # Normalize hostname (replace colons like port numbers)
        hostname_prefix = hostname.replace(':', '_')
        prefix = f"scans/{hostname_prefix}_"

        # List all objects with the hostname prefix using pagination
        # S3 returns in alphabetical order which equals chronological for timestamp-based keys
        # We need to paginate to ensure we get the newest scans, not just the oldest
        all_objects = []
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
            if 'Contents' in page:
                all_objects.extend(page['Contents'])

        if not all_objects:
            logger.info(f"No previous scans found for {hostname}")
            return None

        # Sort by LastModified descending (most recent first)
        objects = sorted(
            all_objects,
            key=lambda x: x['LastModified'],
            reverse=True
        )

        # Filter out status.json files and the current scan
        scan_objects = [
            obj for obj in objects
            if obj['Key'].endswith('.json')
            and not obj['Key'].endswith('status.json')
            and (current_scan_key is None or obj['Key'] != current_scan_key)
        ]

        if not scan_objects:
            logger.info(f"No previous scans found for {hostname} (after filtering)")
            return None

        # Return the most recent (which is the previous if current is excluded)
        previous_key = scan_objects[0]['Key']
        logger.info(f"Found previous scan: {previous_key}")
        return previous_key

    except Exception as e:
        logger.error(f"Error finding previous scan: {e}")
        return None


def load_scan_from_s3(
    s3_client,
    bucket_name: str,
    s3_key: str
) -> dict[str, Any] | None:
    """
    Load a scan result from S3.

    Args:
        s3_client: boto3 S3 client
        bucket_name: S3 bucket name
        s3_key: S3 object key

    Returns:
        Parsed scan result, or None if failed
    """
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
        content = response['Body'].read().decode('utf-8')
        return json.loads(content)
    except Exception as e:
        logger.error(f"Failed to load scan from S3: {e}")
        return None


def extract_finding_id(finding: dict[str, Any]) -> str:
    """
    Extract a stable identifier for a finding.

    Uses the 'id' field which is deterministic (tool:hash).
    Falls back to title + tool if id is missing.
    """
    if finding.get('id'):
        return finding['id']

    # Fallback: create ID from tool + title using deterministic hash
    tool = finding.get('tool', 'unknown')
    title = finding.get('title', 'unknown')
    title_hash = hashlib.md5(title.encode('utf-8')).hexdigest()[:8]
    return f"{tool}:{title_hash}"


def calculate_delta(
    current_scan: dict[str, Any],
    baseline_scan: dict[str, Any]
) -> dict[str, Any]:
    """
    Calculate the delta between current and baseline scans.

    Args:
        current_scan: Current scan results
        baseline_scan: Previous/baseline scan results

    Returns:
        Delta report with new/resolved findings and score changes
    """
    # Extract findings from both scans
    current_findings = current_scan.get('findings', [])
    baseline_findings = baseline_scan.get('findings', [])

    # Build lookup sets by finding ID
    current_ids = {extract_finding_id(f): f for f in current_findings}
    baseline_ids = {extract_finding_id(f): f for f in baseline_findings}

    # Calculate sets
    new_finding_ids = set(current_ids.keys()) - set(baseline_ids.keys())
    resolved_finding_ids = set(baseline_ids.keys()) - set(current_ids.keys())
    common_finding_ids = set(current_ids.keys()) & set(baseline_ids.keys())

    # Build finding lists
    new_findings = [current_ids[fid] for fid in new_finding_ids]
    resolved_findings = [baseline_ids[fid] for fid in resolved_finding_ids]

    # Detect changes in findings that exist in both scans (same ID but different attributes)
    changed_findings = []
    unchanged_findings = []
    for fid in common_finding_ids:
        current_f = current_ids[fid]
        baseline_f = baseline_ids[fid]

        changes = {}
        # Check for CVSS score changes
        curr_cvss = current_f.get('cvss_score', 0)
        base_cvss = baseline_f.get('cvss_score', 0)
        if curr_cvss != base_cvss:
            changes['cvss_score'] = [base_cvss, curr_cvss]

        # Check for severity changes
        curr_sev = current_f.get('severity', 'info')
        base_sev = baseline_f.get('severity', 'info')
        if curr_sev != base_sev:
            changes['severity'] = [base_sev, curr_sev]

        # Check for AI verdict changes
        curr_verdict = current_f.get('ai_verdict')
        base_verdict = baseline_f.get('ai_verdict')
        if curr_verdict != base_verdict:
            changes['ai_verdict'] = [base_verdict, curr_verdict]

        if changes:
            changed_findings.append({
                'id': fid,
                'title': current_f.get('title', 'Unknown'),
                'changes': changes,
                'current': current_f,
                'baseline': baseline_f
            })
        else:
            unchanged_findings.append(current_f)

    # Extract scores and grades
    current_result = current_scan.get('result', {})
    baseline_result = baseline_scan.get('result', {})

    current_score = current_result.get('score', 0)
    baseline_score = baseline_result.get('score', 0)
    score_delta = current_score - baseline_score

    current_grade = current_result.get('grade', 'N/A')
    baseline_grade = baseline_result.get('grade', 'N/A')

    # Format grade change
    if current_grade == baseline_grade:
        grade_change = "unchanged"
    else:
        grade_change = f"{baseline_grade} → {current_grade}"

    # Count by severity
    def count_by_severity(findings: list[dict]) -> dict[str, int]:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info').lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    new_by_severity = count_by_severity(new_findings)
    resolved_by_severity = count_by_severity(resolved_findings)

    # Generate summary
    summary_parts = []
    if new_findings:
        summary_parts.append(f"{len(new_findings)} new finding{'s' if len(new_findings) != 1 else ''}")
    if resolved_findings:
        summary_parts.append(f"{len(resolved_findings)} resolved")
    if changed_findings:
        summary_parts.append(f"{len(changed_findings)} changed")

    if score_delta > 0:
        summary_parts.append(f"score improved by {score_delta} points")
    elif score_delta < 0:
        summary_parts.append(f"score decreased by {abs(score_delta)} points")
    else:
        summary_parts.append("score unchanged")

    if not new_findings and not resolved_findings and not changed_findings:
        summary = "No changes detected"
    else:
        summary = ", ".join(summary_parts)

    # Extract baseline metadata
    baseline_metadata = baseline_scan.get('scan_metadata', {})
    baseline_scan_id = baseline_metadata.get('scan_id', 'unknown')
    baseline_completed = baseline_metadata.get('completed_at') or baseline_scan.get('timestamp_utc', 'unknown')

    return {
        'baseline_scan_id': baseline_scan_id,
        'baseline_date': baseline_completed,
        'new_findings': new_findings,
        'new_findings_count': len(new_findings),
        'new_by_severity': new_by_severity,
        'resolved_findings': resolved_findings,
        'resolved_findings_count': len(resolved_findings),
        'resolved_by_severity': resolved_by_severity,
        'changed_findings': changed_findings,
        'changed_findings_count': len(changed_findings),
        'unchanged_findings_count': len(unchanged_findings),
        'score_delta': score_delta,
        'score_current': current_score,
        'score_baseline': baseline_score,
        'grade_change': grade_change,
        'grade_current': current_grade,
        'grade_baseline': baseline_grade,
        'summary': summary,
        'calculated_at': datetime.now(UTC).isoformat()
    }


def generate_delta_summary_text(delta: dict[str, Any]) -> str:
    """
    Generate a human-readable summary of the delta.

    Args:
        delta: Delta report from calculate_delta()

    Returns:
        Formatted text summary
    """
    lines = [
        "═══════════════════════════════════════════════════════════",
        "                    SCAN DELTA REPORT                      ",
        "═══════════════════════════════════════════════════════════",
        "",
        f"Baseline: {delta['baseline_scan_id']} ({delta['baseline_date']})",
        "",
        "─── SCORE CHANGE ───",
        f"  {delta['score_baseline']} ({delta['grade_baseline']}) → {delta['score_current']} ({delta['grade_current']})",
    ]

    if delta['score_delta'] > 0:
        lines.append(f"  ↑ Improved by {delta['score_delta']} points")
    elif delta['score_delta'] < 0:
        lines.append(f"  ↓ Decreased by {abs(delta['score_delta'])} points")
    else:
        lines.append("  → No change")

    lines.extend([
        "",
        "─── NEW FINDINGS ───",
        f"  Total: {delta['new_findings_count']}",
    ])

    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = delta['new_by_severity'].get(sev, 0)
        if count > 0:
            lines.append(f"  {sev.upper()}: {count}")

    if delta['new_findings']:
        lines.append("")
        for f in delta['new_findings'][:5]:  # Show first 5
            title = f.get('title', 'Unknown')[:50]
            sev = f.get('severity', 'info').upper()
            lines.append(f"  • [{sev}] {title}")
        if len(delta['new_findings']) > 5:
            lines.append(f"  ... and {len(delta['new_findings']) - 5} more")

    lines.extend([
        "",
        "─── RESOLVED FINDINGS ───",
        f"  Total: {delta['resolved_findings_count']}",
    ])

    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = delta['resolved_by_severity'].get(sev, 0)
        if count > 0:
            lines.append(f"  {sev.upper()}: {count}")

    if delta['resolved_findings']:
        lines.append("")
        for f in delta['resolved_findings'][:5]:  # Show first 5
            title = f.get('title', 'Unknown')[:50]
            sev = f.get('severity', 'info').upper()
            lines.append(f"  ✓ [{sev}] {title}")
        if len(delta['resolved_findings']) > 5:
            lines.append(f"  ... and {len(delta['resolved_findings']) - 5} more")

    lines.extend([
        "",
        "─── SUMMARY ───",
        f"  {delta['summary']}",
        "",
        "═══════════════════════════════════════════════════════════",
    ])

    return "\n".join(lines)


async def calculate_delta_from_s3(
    s3_client,
    bucket_name: str,
    hostname: str,
    current_scan: dict[str, Any],
    current_scan_key: str | None = None,
    baseline_s3_key: str | None = None
) -> dict[str, Any] | None:
    """
    Calculate delta by fetching baseline from S3.

    Args:
        s3_client: boto3 S3 client
        bucket_name: S3 bucket name
        hostname: Target hostname
        current_scan: Current scan results
        current_scan_key: Current scan's S3 key (to exclude from baseline search)
        baseline_s3_key: Optional explicit baseline S3 key to use

    Returns:
        Delta report, or None if no baseline found
    """
    # Find or use specified baseline
    if baseline_s3_key:
        previous_key = baseline_s3_key
    else:
        previous_key = find_previous_scan_key(
            s3_client,
            bucket_name,
            hostname,
            current_scan_key
        )

    if not previous_key:
        logger.info(f"No baseline found for {hostname}, skipping delta calculation")
        return None

    # Load baseline scan
    baseline_scan = load_scan_from_s3(s3_client, bucket_name, previous_key)
    if not baseline_scan:
        logger.error(f"Failed to load baseline scan from {previous_key}")
        return None

    # Calculate delta
    delta = calculate_delta(current_scan, baseline_scan)
    delta['baseline_s3_key'] = previous_key

    return delta


def format_delta_for_callback(delta: dict[str, Any], compact: bool = True) -> dict[str, Any]:
    """
    Format delta for inclusion in callback/webhook payload.

    Args:
        delta: Full delta report
        compact: If True, exclude full finding details to reduce payload size

    Returns:
        Formatted delta for callback
    """
    if compact:
        return {
            'baseline_scan_id': delta['baseline_scan_id'],
            'baseline_date': delta['baseline_date'],
            'new_findings_count': delta['new_findings_count'],
            'new_by_severity': delta['new_by_severity'],
            'resolved_findings_count': delta['resolved_findings_count'],
            'resolved_by_severity': delta['resolved_by_severity'],
            'score_delta': delta['score_delta'],
            'grade_change': delta['grade_change'],
            'summary': delta['summary']
        }
    return delta
