# 🔐 CI Threat Scanner

Automated **SBOM → Vulnerability Scan → Threat Report** pipeline as a **GitHub Action**.

---

## 🚀 Features
- Generate SBOM using [Syft](https://github.com/anchore/syft)
- Scan SBOM with [Trivy](https://github.com/aquasecurity/trivy)
- Map CVEs → CWEs → STRIDE threat categories
- Produce `report.json`
- Upload threat report as an artifact in CI/CD

---

## 📦 Usage

In your repo:

```yaml
name: AutoThreat Scan
on: [push, pull_request]

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - name: Use CI Threat Modeler
        uses: harshsoni-harsh/autothreat-action@main
        with:
          path: .
