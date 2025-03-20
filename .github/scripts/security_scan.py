#!/usr/bin/env python3
# .github/scripts/security_scan.py

import os
import re
import logging
import json
import tempfile
import subprocess
import time
from pathlib import Path
import sys
import requests
from fs.memoryfs import MemoryFS

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import from scan_utils if available, otherwise define minimal versions
try:
    from scan_utils import run_semgrep_scan_new, analyze_codebase_new, AnalysisReport
except ImportError:
    logger.warning("scan_utils not found, using minimal implementation")

    def run_semgrep_scan_new(mem_fs, ml_results=None):
        """Run semgrep scan using the memory filesystem"""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            # Copy files from memory filesystem to disk
            for path in mem_fs.walk.files():
                content = mem_fs.readtext(path)
                file_path = project_path / path.lstrip('/')  # Remove leading slash if present
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_text(content, encoding='utf-8')

            # Run semgrep
            try:
                cmd = ["semgrep", "--config=auto", "--json", "--output", f"{project_path}/results.json"]
                subprocess.run(cmd, cwd=project_path, check=True, capture_output=True)

                # Read results
                with open(f"{project_path}/results.json") as f:
                    results = json.load(f)

                return results
            except subprocess.CalledProcessError as e:
                logger.error(f"Semgrep error: {e.stderr.decode()}")
                return {"results": []}

    def analyze_codebase_new(project_path, sarif_path, ml_results_info=""):
        """Analyze scan results and generate report"""
        try:
            with open(sarif_path) as f:
                results = json.load(f)

            vulnerabilities = []
            for result in results.get("results", []):
                vuln = {
                    "rule_id": result.get("check_id", "unknown"),
                    "title": result.get("extra", {}).get("message", "Security Issue"),
                    "description": result.get("extra", {}).get("metadata", {}).get("description", "No description"),
                    "severity": result.get("extra", {}).get("metadata", {}).get("severity", "medium"),
                    "file_path": result.get("path", "unknown"),
                    "line_number": result.get("start", {}).get("line", 0),
                    "original_code": result.get("extra", {}).get("lines", "")
                }
                vulnerabilities.append(vuln)

            report = AnalysisReport(
                vulnerabilities=vulnerabilities,
                patches=[],
                summary=f"Found {len(vulnerabilities)} potential security issues.",
                metadata={"ml_results": ml_results_info}
            )
            return report
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            return AnalysisReport([], [], f"Error analyzing results: {str(e)}", {})

    class AnalysisReport:
        def __init__(self, vulnerabilities, patches, summary, metadata):
            self.vulnerabilities = vulnerabilities
            self.patches = patches
            self.summary = summary
            self.metadata = metadata

        def to_dict(self):
            return {
                "vulnerabilities": self.vulnerabilities,
                "patches": self.patches,
                "summary": self.summary,
                "metadata": self.metadata
            }

def get_changed_files():
    """Get files changed in this commit/PR"""
    changed_files = os.environ.get('CHANGED_FILES', '')
    if changed_files:
        return changed_files.split(' ')

    # Fallback to git diff
    try:
        base_ref = os.environ.get('GITHUB_BASE_REF', '')
        if base_ref:  # For PRs
            cmd = ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"]
        else:  # For pushes
            cmd = ["git", "diff", "--name-only", "HEAD^", "HEAD"]

        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return [file.strip() for file in result.stdout.splitlines() if file.strip()]
    except subprocess.CalledProcessError as e:
        logger.error(f"Git diff error: {e.stderr}")
        return []

def load_files_to_memory_fs():
    """Load changed files into memory filesystem"""
    mem_fs = MemoryFS()
    changed_files = get_changed_files()
    repo_root = os.environ.get('GITHUB_WORKSPACE', '.')

    for file_path in changed_files:
        # Ensure file_path is not an absolute path
        file_path = file_path.lstrip('/')

        full_path = Path(repo_root) / file_path
        if not full_path.exists() or not full_path.is_file():
            logger.warning(f"File {file_path} does not exist or is not a file, skipping")
            continue

        # Skip non-code files and hidden files
        if full_path.name.startswith('.') or not has_analyzable_extension(full_path):
            logger.info(f"Skipping non-analyzable file: {file_path}")
            continue

        try:
            content = full_path.read_text(encoding='utf-8')
            # Ensure correct path structure in memory filesystem
            parent_dir = str(Path(file_path).parent)
            if parent_dir:  # Only create parent dirs if needed
                mem_fs.makedirs(parent_dir, recreate=True)
            mem_fs.writetext(file_path, content)
            logger.info(f"Loaded file to memory: {file_path}")
        except Exception as e:
            logger.warning(f"Failed to load file {file_path}: {str(e)}")

    return mem_fs

def has_analyzable_extension(path):
    """Check if file has extension that can be analyzed"""
    code_extensions = {
        '.py', '.js', '.ts', '.tsx', '.jsx', '.php', '.java',
        '.c', '.cpp', '.h', '.hpp', '.cs', '.go', '.rb', '.rs',
        '.html', '.htm', '.xml', '.json', '.yaml', '.yml'
    }
    return path.suffix.lower() in code_extensions

def generate_report(report, changed_files):
    """Generate report JSON for later use"""
    output = {
        "summary": report.summary,
        "findings": [],
        "patches": [],
        "metadata": report.metadata,
        "scanned_files": changed_files
    }

    # Add vulnerabilities
    for vuln in report.vulnerabilities:
        if isinstance(vuln, dict):
            output["findings"].append(vuln)
        else:
            output["findings"].append(vuln.to_dict() if hasattr(vuln, 'to_dict') else vars(vuln))

    # Add patches
    for patch in report.patches:
        if isinstance(patch, dict):
            output["patches"].append(patch)
        else:
            output["patches"].append(patch.to_dict() if hasattr(patch, 'to_dict') else vars(patch))

    # Save report
    with open('security-report.json', 'w') as f:
        json.dump(output, f, indent=2)

    # Set output for GitHub Actions
    has_issues = len(output["findings"]) > 0
    print(f"::set-output name=has_issues::{str(has_issues).lower()}")

    return output

def send_slack_notification(report):
    """Send Slack notification if webhook is configured"""
    slack_webhook = os.environ.get('SLACK_WEBHOOK_URL')
    if not slack_webhook:
        return

    repo_name = os.environ.get('REPO_NAME', 'unknown')
    run_url = f"{os.environ.get('GITHUB_SERVER_URL', '')}/{repo_name}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"

    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔒 Security Scan Results for {repo_name}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": report["summary"]
                }
            }
        ]
    }

    # Add vulnerabilities if found
    if len(report["findings"]) > 0:
        findings_text = "\n".join([
            f"• *{v['severity'].upper()}*: {v['title']} in `{v['file_path']}`"
            for v in report["findings"][:5]  # Show top 5
        ])

        if len(report["findings"]) > 5:
            findings_text += f"\n_...and {len(report['findings']) - 5} more_"

        message["blocks"].append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Vulnerabilities Found:*\n{findings_text}"
            }
        })

    # Add link to full report
    message["blocks"].append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"<{run_url}|View Full Report>"
        }
    })

    try:
        requests.post(slack_webhook, json=message)
    except Exception as e:
        logger.error(f"Failed to send Slack notification: {str(e)}")

def main():
    """Main function to run security scan"""
    try:
        logger.info("Starting security scan")

        # Load changed files to memory FS
        mem_fs = load_files_to_memory_fs()
        changed_files = [path for path in mem_fs.walk.files()]

        if not changed_files:
            logger.info("No relevant files changed, skipping scan")
            report = AnalysisReport(
                vulnerabilities=[],
                patches=[],
                summary="No relevant files were changed in this commit/PR.",
                metadata={"scanned_files": 0}
            )
            generate_report(report, [])
            return

        logger.info(f"Scanning {len(changed_files)} changed files")

        # Check if ML service is enabled
        use_ml = os.environ.get('ML_ENABLED', 'false').lower() == 'true'
        ml_results = set()
        ml_results_info = ""

        if use_ml:
            ml_service_url = os.environ.get('ML_SERVICE_URL', 'http://localhost:5001/ml/scan')
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    project_path = Path(temp_dir)

                    # Copy files from memory FS to disk for ML scanning
                    for path in mem_fs.walk.files():
                        content = mem_fs.readtext(path)
                        file_path = project_path / path.lstrip('/')  # Remove leading slash
                        file_path.parent.mkdir(parents=True, exist_ok=True)
                        file_path.write_text(content, encoding='utf-8')

                    # Call ML service
                    response = requests.post(
                        ml_service_url,
                        json={'project_path': str(project_path)},
                        timeout=30
                    )
                    response.raise_for_status()
                    ml_data = response.json()
                    ml_results = set(ml_data['vulnerable_files'])
                    ml_results_info = f"ML Model Detection Results:\n{', '.join(ml_results) if ml_results else 'No vulnerabilities found.'}"
            except Exception as e:
                logger.error(f"ML service failed: {str(e)}")
                ml_results_info = f"ML Model Detection Results:\nError: {str(e)}"

        # Run semgrep scan
        scan_results = run_semgrep_scan_new(mem_fs, ml_results)

        # Save SARIF results
        with tempfile.NamedTemporaryFile(delete=False, suffix='.sarif') as sarif_file:
            sarif_file.write(json.dumps(scan_results).encode('utf-8'))
            sarif_path = Path(sarif_file.name)

        # Analyze results
        project_path = Path(os.environ.get('GITHUB_WORKSPACE', '.'))
        report = analyze_codebase_new(project_path, sarif_path, ml_results_info)

        # Generate and save report
        report_data = generate_report(report, changed_files)

        # Send notifications
        send_slack_notification(report_data)

        logger.info("Security scan completed")

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
