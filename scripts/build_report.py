#!/usr/bin/env python3
import argparse, json, sys, re, yaml
from pathlib import Path

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

def load_sbom_components(sbom_path):
    if not sbom_path:
        return []
    p = Path(sbom_path)
    if not p.exists():
        return []
    j = json.loads(p.read_text())
    # CycloneDX: components in j["components"]
    comps = []
    if isinstance(j, dict) and "components" in j:
        for c in j["components"] or []:
            comps.append({"name": c.get("name") or c.get("bom-ref"), "version": c.get("version")})
    return comps

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vulns", required=True, help="Trivy vulns JSON path (vulns.json)")
    ap.add_argument("--sbom", required=False, help="SBOM (CycloneDX) path")
    ap.add_argument("--output", required=False, default="report.json")
    ap.add_argument("--project", required=False, default="MyApp Report")
    args = ap.parse_args()

    vulns_path = Path(args.vulns)
    if not vulns_path.exists():
        print(f"Vulnerabilities file not found: {vulns_path}", file=sys.stderr)
        sys.exit(2)
    vulns_json = json.loads(vulns_path.read_text())

    sbom_components = load_sbom_components(args.sbom) if args.sbom else []

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
        "project": {"name": args.project},
        "components": list(components_map.values()),
        "threats": threats,
    }

    Path(args.output).write_text(json.dumps(result, indent=2))
    print(f"Wrote {args.output} ({len(threats)} threats, {len(components_map)} components)")

if __name__ == "__main__":
    main()
