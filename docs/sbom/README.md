# Software Bill of Materials

`darkstar.cdx.json` is the generated CycloneDX 1.5 software bill of materials
for this repository.

Do not edit the SBOM by hand. Regenerate it with:

```bash
python3 scripts/generate_sbom.py
```

Check that the committed SBOM is current:

```bash
python3 scripts/generate_sbom.py --check
```

The GitHub Actions workflow in `.github/workflows/sbom.yml` keeps the file up to
date. Pull requests fail when dependency manifests change without the generated
SBOM, and pushes to `main` regenerate and commit the SBOM automatically when it
drifts.

Coverage is manifest based and deterministic: Python requirement files,
`pyproject.toml`, Go modules, Docker base images, Docker Compose images,
Dockerfile apt packages, and Dockerfile-installed tools are included without
network resolution. Build-time package managers can still install transitive
packages that are not pinned in source manifests.
