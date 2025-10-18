import argparse
import json
import sys
import re
import yaml
import subprocess
import requests
from pathlib import Path
from typing import Dict, Any
from urllib.parse import urljoin
from datetime import datetime, UTC

def load_mappings(path: str):
    p = Path(path)
    if not p.exists():
        print(f"Warning: mapping file not found at {path}, using empty defaults", file=sys.stderr)
        return {}, {}

    text = p.read_text()
    if path.endswith(".yml") or path.endswith(".yaml"):
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    cwe_map = data.get("cwe_to_stride", {})
    kw_map = data.get("keyword_to_stride", {})
    return cwe_map, kw_map

CWE_TO_STRIDE, KEYWORD_STRIDE = load_mappings("data/stride_mappings.yml")

def normalize_cwe(cwe):
    if not cwe:
        return None
    # Possible formats: "CWE-79", "79", "CWE79" -> normalize to CWE-79
    m = re.search(r'(\d+)', str(cwe))
    if m:
        return f"CWE-{m.group(1)}"
    return str(cwe)

def map_cwe_to_stride(cwe):
    if not cwe:
        return None
    cwe_norm = normalize_cwe(cwe)
    return CWE_TO_STRIDE.get(cwe_norm)

def infer_stride_from_text(text):
    if not text:
        return None
    t = text.lower()
    for k, v in KEYWORD_STRIDE.items():
        if k in t:
            return v
    return None

def extract_vulnerabilities(trivy_json):
    """
    Robust extractor for a few common trivy JSON shapes:
    - { "Results": [ { "Vulnerabilities": [ { ... } ] } ] }
    - Or older/different shapes with top-level 'vulnerabilities'
    """
    vulns = []
    if isinstance(trivy_json, dict):
        if "Results" in trivy_json and isinstance(trivy_json["Results"], list):
            for res in trivy_json["Results"]:
                for v in res.get("Vulnerabilities", []) or []:
                    vulns.append(v)
        elif "vulnerabilities" in trivy_json and isinstance(trivy_json["vulnerabilities"], list):
            vulns.extend(trivy_json["vulnerabilities"])
        else:
            # fallback: if top-level list
            for k, v in trivy_json.items():
                if isinstance(v, list):
                    # try to find any dict items that look like vulnerabilities
                    for item in v:
                        if isinstance(item, dict) and ("VulnerabilityID" in item or "id" in item or "vuln" in item):
                            vulns.append(item)
    elif isinstance(trivy_json, list):
        for item in trivy_json:
            if isinstance(item, dict):
                if "Vulnerabilities" in item:
                    vulns.extend(item["Vulnerabilities"])
                else:
                    vulns.append(item)
    return vulns

def get_cwe_from_vuln(v):
    for key in ("CweIDs", "CWE", "cwe", "cwes", "CweID", "cwe_ids", "cweId"):
        val = v.get(key)
        if val:
            if isinstance(val, list) and len(val) > 0:
                return val[0]
            return val
    # some scanners include CWE in references; try to find CWE-#### in description or references
    for text_key in ("Description", "description", "Title", "title", "PrimaryURL"):
        text = v.get(text_key) or ""
        m = re.search(r'(CWE[-\s]?\d+)', text, re.IGNORECASE)
        if m:
            return m.group(1).replace(' ', '-')
    return None

def find_component_for_vuln(v, sbom_components):
    # Try to match by PkgName / InstalledVersion or package reference fields
    pkg_names = []
    for key in ("PkgName", "PackageName", "pkg", "name"):
        if key in v and v.get(key):
            pkg_names.append((v.get(key), v.get("InstalledVersion") or v.get("Version") or None))
    # fallback: v might contain 'artifactName' or 'package'
    if not pkg_names:
        for key in ("artifactName", "package"):
            if v.get(key):
                pkg_names.append((v.get(key), None))
    # match against sbom components (list of dicts with 'name' and 'version')
    if sbom_components:
        for pkg, ver in pkg_names:
            for comp in sbom_components:
                name = comp.get("name") or comp.get("bom-ref") or comp.get("id")
                version = comp.get("version")
                if not name:
                    continue
                # simple case-insensitive contains or equality
                if pkg.lower() in name.lower() or name.lower() in (pkg or "").lower():
                    if ver is None or not version or ver == version:
                        return f"{name}@{version or 'unspecified'}"
    # If no sbom match, derive component id from PkgName/Version
    if pkg_names:
        pkg, ver = pkg_names[0]
        return f"{pkg}@{ver or 'unspecified'}"
    # ultimate fallback
    return "unknown-component"

def get_commit_hash() -> str:
    import os
    import subprocess

    # Check for GitHub Actions environment variable
    github_sha = os.getenv('GITHUB_SHA')
    if github_sha:
        return github_sha

    # Fallback to git command
    try:
        result = subprocess.run(['git', 'rev-parse', 'HEAD'],
                              capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"

def detect_sbom_format(sbom_data: Dict[str, Any]) -> str:
    """
    Detect the SBOM format from the data structure.

    Returns:
        "SPDX", "CycloneDX", or "Unknown"
    """
    if not isinstance(sbom_data, dict):
        return "Unknown"

    # Check for SPDX format
    if "spdxVersion" in sbom_data:
        return "SPDX"

    # Check for CycloneDX format
    if "bomFormat" in sbom_data and sbom_data.get("bomFormat") == "CycloneDX":
        return "CycloneDX"

    return "Unknown"

def load_sbom_components(sbom_path):
    if not sbom_path:
        return []
    p = Path(sbom_path)
    if not p.exists():
        return []
    j = json.loads(p.read_text())

    comps = []
    if isinstance(j, dict):
        format_type = detect_sbom_format(j)

        if format_type == "SPDX":
            # SPDX format: packages in "packages"
            packages = j.get("packages", [])
            for pkg in packages:
                name = pkg.get("name") or pkg.get("SPDXID")
                version = pkg.get("versionInfo")
                if name:
                    comps.append({"name": name, "version": version})

        elif format_type == "CycloneDX":
            # CycloneDX format: components in "components"
            for c in j.get("components", []):
                name = c.get("name") or c.get("bom-ref") or c.get("id")
                version = c.get("version")
                if name:
                    comps.append({"name": name, "version": version})

        else:
            # Fallback: try to find any array that might contain packages/components
            for key, value in j.items():
                if isinstance(value, list) and value:
                    for item in value[:5]:  # Check first few items
                        if isinstance(item, dict) and ("name" in item or "SPDXID" in item):
                            name = item.get("name") or item.get("SPDXID")
                            version = item.get("versionInfo") or item.get("version")
                            if name:
                                comps.append({"name": name, "version": version})
                            break
                    if comps:  # Found some components, stop looking
                        break

    return comps

def generate_sbom(target_path):
    print(f"Generating SBOM for: {target_path}")
    cmd = ["syft", f"dir:{target_path}", "-o", "cyclonedx-json"]
    with open("sbom.json", "w") as f:
        subprocess.run(cmd, stdout=f, check=True)
    print("Wrote sbom.json")

def scan_sbom(sbom_file):
    print(f"Scanning SBOM: {sbom_file}")
    cmd = ["trivy", "sbom", sbom_file, "-f", "json", "-o", "vulns.json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # Don't fail on vulnerabilities found
    if result.returncode not in (0, 1):
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    print("Wrote vulns.json")

def build_report(vulns_path, sbom_path, output_path, project_name):
    vulns_path = Path(vulns_path)
    if not vulns_path.exists():
        raise FileNotFoundError(f"Vulnerabilities file not found: {vulns_path}")
    vulns_json = json.loads(vulns_path.read_text())

    sbom_components = load_sbom_components(sbom_path) if sbom_path else []

    extracted = extract_vulnerabilities(vulns_json)

    components_map = {}  # id => component info
    threats = []

    for v in extracted:
        vuln_id = v.get("VulnerabilityID") or v.get("VulnID") or v.get("id") or v.get("name") or v.get("ID") or "UNKNOWN-ID"
        title = v.get("Title") or v.get("Title") or vuln_id
        severity = v.get("Severity") or v.get("severity") or "UNKNOWN"
        description = v.get("Description") or v.get("description") or ""

        cwe_raw = get_cwe_from_vuln(v)
        cwe = normalize_cwe(cwe_raw) if cwe_raw else None
        stride = map_cwe_to_stride(cwe)
        if not stride:
            # try heuristics on description/title
            stride = infer_stride_from_text(" ".join([title or "", description or ""])) or "Unknown"

        target = find_component_for_vuln(v, sbom_components)
        # register component
        if target not in components_map:
            components_map[target] = {
                "id": target,
                "name": target.split("@")[0],
                "type": "library"
            }

        threat = {
            "id": vuln_id,
            "title": title,
            "description": (description[:512] + "...") if description and len(description) > 512 else description,
            "cwe": cwe,
            "stride": stride,
            "severity": severity,
            "target": target,
        }
        threats.append(threat)

    result = {
        "project": {"name": project_name},
        "components": list(components_map.values()),
        "threats": threats,
    }

    Path(output_path).write_text(json.dumps(result, indent=2))
    print(f"Wrote {output_path} ({len(threats)} threats, {len(components_map)} components)")
    return threats

class AutoThreatSync:
    """Handles synchronization of SBOM data with AutoThreat platform."""

    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'AutoThreat-Action/main'
        })

    def read_sbom_file(self, sbom_path: str) -> Dict[str, Any]:
        try:
            with open(sbom_path, 'r', encoding='utf-8') as f:
                sbom_data = json.load(f)
            return sbom_data
        except FileNotFoundError:
            raise FileNotFoundError(f"SBOM file not found: {sbom_path}")
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(f"Invalid JSON in SBOM file: {e}", e.doc, e.pos)

    def validate_sbom_data(self, sbom_data: Dict[str, Any]) -> bool:
        format_type = detect_sbom_format(sbom_data)

        if format_type == "SPDX":
            required_spdx_fields = ['spdxVersion', 'dataLicense', 'SPDXID', 'name']
            if not all(field in sbom_data for field in required_spdx_fields):
                print("Warning: SBOM data is missing required SPDX fields")
                return False
            print("SBOM validated as SPDX format")
            return True

        elif format_type == "CycloneDX":
            required_cd_fields = ['bomFormat', 'specVersion', 'version']
            if not all(field in sbom_data for field in required_cd_fields):
                print("Warning: SBOM data is missing required CycloneDX fields")
                return False
            print("SBOM validated as CycloneDX format")
            return True

        else:
            print("Warning: SBOM data does not appear to be in SPDX or CycloneDX format")
            return False

    def sync_sbom(self, sbom_data: Dict[str, Any], project_name: str) -> Dict[str, Any]:
        format_type = detect_sbom_format(sbom_data)
        commit_hash = get_commit_hash()

        endpoint = "/sbom/sync"
        url = urljoin(self.base_url + '/', endpoint.lstrip('/'))

        payload = {
            'project': project_name,
            'sbom': sbom_data,
            'metadata': {
                'source': 'github-action',
                'timestamp': self._get_current_timestamp(),
                'format': format_type,
                'commit_hash': commit_hash
            }
        }

        print(f"Syncing SBOM data for project: {project_name} (format: {format_type}, commit: {commit_hash[:8]})")
        print(f"API Endpoint: {url}")

        response = self.session.post(url, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        print(f"Successfully synced SBOM data. Response: {result}")
        return result

    def _get_current_timestamp(self) -> str:
        return datetime.now(UTC).isoformat()

def sync_with_platform(sbom_path, api_key, project_name, api_url='http://localhost:3000/api'):
    sync_client = AutoThreatSync(api_key, api_url)
    sbom_data = sync_client.read_sbom_file(sbom_path)
    if sync_client.validate_sbom_data(sbom_data):
        print("SBOM data validation passed")
    else:
        print("Warning: SBOM data validation failed, proceeding anyway...")
    result = sync_client.sync_sbom(sbom_data, project_name)
    print("✅ SBOM sync completed successfully!")
    if 'id' in result:
        print(f"Sync ID: {result['id']}")
    if 'status' in result:
        print(f"Status: {result['status']}")

def check_fail_condition(threats, fail_on_severity):
    severity_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    fail_level = severity_levels.get(fail_on_severity.upper(), 4)
    for threat in threats:
        sev = threat.get("severity", "UNKNOWN").upper()
        if sev in severity_levels and severity_levels[sev] >= fail_level:
            print(f"Failing due to vulnerability: {threat['id']} with severity {sev}")
            return True
    return False

def main():
    parser = argparse.ArgumentParser(description="AutoThreat CI: Generate SBOM, scan for vulnerabilities, and produce a report.")
    parser.add_argument("--path", default=".", help="Path to scan")
    parser.add_argument("--api-key", required=True, help="API key for AutoThreat platform")
    parser.add_argument("--fail-on-severity", default="CRITICAL", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Fail workflow if vulnerabilities at or above this severity are found")
    parser.add_argument("--project", required=True, help="Project name (e.g., owner/repo)")
    parser.add_argument("--api-url", default="http://localhost:3000/api", help="AutoThreat API base URL")
    args = parser.parse_args()

    try:
        generate_sbom(args.path)
        scan_sbom("sbom.json")
        threats = build_report("vulns.json", "sbom.json", "report.json", args.project)
        sync_with_platform("sbom.json", args.api_key, args.project, args.api_url)
        if check_fail_condition(threats, args.fail_on_severity):
            print(f"Failing build due to vulnerabilities at or above {args.fail_on_severity} severity")
            sys.exit(1)

        print("AutoThreat CI completed successfully")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
