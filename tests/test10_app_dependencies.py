"""Test 10 — Application Dependencies (Python, Node, Java, Go) Support."""
from phishnet.matcher import parse_cve_matches
from phishnet.layers import attribute_cves_to_layers, generate_fix_suggestions, LayerInfo
from phishnet.remediate import build_remediation_plan, generate_patched_dockerfile, DockerfileLine

def test_app_dependencies_parsing():
    print("=" * 60)
    print("TEST 10a — Application Dependencies Parsing & Classification")
    print("=" * 60)

    # Mock Trivy output containing both OS and language packages
    mock_trivy = {
        "Results": [
            {
                "Target": "nginx:1.14 (debian 9.5)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2019-1549",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.0.2k",
                        "FixedVersion": "1.0.2u",
                        "Severity": "CRITICAL",
                        "CVSS": {"nvd": {"V3Score": 9.8}},
                        "Layer": {"DiffID": "sha256:layer-os"},
                    }
                ],
            },
            {
                "Target": "app/requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "InstalledVersion": "2.28.1",
                        "FixedVersion": "2.31.0",
                        "Severity": "MEDIUM",
                        "CVSS": {"nvd": {"V3Score": 6.1}},
                        "Layer": {"DiffID": "sha256:layer-pip"},
                    }
                ],
            },
            {
                "Target": "frontend/package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2022-25883",
                        "PkgName": "semver",
                        "InstalledVersion": "7.3.5",
                        "FixedVersion": "7.5.2",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 7.5}},
                        "Layer": {"DiffID": "sha256:layer-npm"},
                    }
                ],
            },
            {
                "Target": "backend/pom.xml",
                "Class": "lang-pkgs",
                "Type": "maven",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-44228",
                        "PkgName": "log4j-core",
                        "InstalledVersion": "2.14.1",
                        "FixedVersion": "2.17.1",
                        "Severity": "CRITICAL",
                        "CVSS": {"nvd": {"V3Score": 10.0}},
                        "Layer": {"DiffID": "sha256:layer-java"},
                    }
                ],
            },
        ]
    }

    cves = parse_cve_matches(mock_trivy)
    assert len(cves) == 4

    cve_dict = {c.package: c for c in cves}

    # Verify classification
    assert cve_dict["openssl"].pkg_type == "os"
    assert cve_dict["requests"].pkg_type == "python"
    assert cve_dict["requests"].target_path == "app/requirements.txt"
    assert cve_dict["semver"].pkg_type == "node"
    assert cve_dict["semver"].target_path == "frontend/package-lock.json"
    assert cve_dict["log4j-core"].pkg_type == "java"
    assert cve_dict["log4j-core"].target_path == "backend/pom.xml"

    print("All application package ecosystems correctly classified!")

def test_app_dependencies_remediation():
    print()
    print("=" * 60)
    print("TEST 10b — Application Dependencies Fix Suggestions & Remediation")
    print("=" * 60)

    # Reconstruct layer attribution
    layers = [
        LayerInfo(layer_id="sha256:layer-os", command="FROM python:3.9-slim", size_bytes=100),
        LayerInfo(layer_id="sha256:layer-pip", command="RUN pip install -r requirements.txt", size_bytes=50),
        LayerInfo(layer_id="sha256:layer-npm", command="RUN npm install", size_bytes=40),
        LayerInfo(layer_id="sha256:layer-java", command="RUN mvn clean package", size_bytes=80),
    ]

    mock_cves = parse_cve_matches({
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2023-32681",
                    "PkgName": "requests",
                    "InstalledVersion": "2.28.1",
                    "FixedVersion": "2.31.0",
                    "Severity": "MEDIUM",
                    "Layer": {"DiffID": "sha256:layer-pip"},
                }]
            },
            {
                "Target": "package.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2022-25883",
                    "PkgName": "semver",
                    "InstalledVersion": "7.3.5",
                    "FixedVersion": "7.5.2",
                    "Severity": "HIGH",
                    "Layer": {"DiffID": "sha256:layer-npm"},
                }]
            }
        ]
    })

    attributed_cves = attribute_cves_to_layers(mock_cves, layers)
    with_suggestions = generate_fix_suggestions(attributed_cves, layers)

    req_cve = next(c for c in with_suggestions if c.package == "requests")
    semver_cve = next(c for c in with_suggestions if c.package == "semver")

    print(f"Python fix suggestion:\n{req_cve.fix_suggestion}\n")
    print(f"Node fix suggestion:\n{semver_cve.fix_suggestion}\n")

    assert "pip install requests>=2.31.0" in req_cve.fix_suggestion
    assert "npm install semver@7.5.2" in semver_cve.fix_suggestion

    # Test remediation plan generation
    dockerfile_lines = [
        DockerfileLine(instruction="FROM", arguments="python:3.9-slim", original="FROM python:3.9-slim"),
        DockerfileLine(instruction="RUN", arguments="pip install -r requirements.txt", original="RUN pip install -r requirements.txt"),
    ]

    plan = build_remediation_plan("python:3.9-slim", with_suggestions, dockerfile_lines)
    assert "requests" in plan.package_pins["pip"]
    assert "semver" in plan.package_pins["npm"]

    patched = generate_patched_dockerfile(plan)
    print("Patched Dockerfile excerpt:")
    print(patched)
    assert "pip install --no-cache-dir --upgrade requests>=2.31.0" in patched

if __name__ == "__main__":
    test_app_dependencies_parsing()
    test_app_dependencies_remediation()
