"""Test 9 — Multi-Registry Reference Parsing & OCI Client."""
from phishnet.registry import (
    parse_image_reference,
    ImageReference,
    verify_registry_image_exists,
    check_registry_tag_exists,
)

def test_multi_registry_parsing():
    print("=" * 60)
    print("TEST 9a — Multi-Registry Parsing")
    print("=" * 60)

    # 1. Docker Hub official image
    r1 = parse_image_reference("nginx:1.25.3")
    assert r1.is_docker_hub is True
    assert r1.registry == "docker.io"
    assert r1.registry_host == "registry-1.docker.io"
    assert r1.repository == "library/nginx"
    assert r1.tag == "1.25.3"
    print(f"nginx:1.25.3 -> {r1}")

    # 2. Docker Hub user repo
    r2 = parse_image_reference("bitnami/redis:7.0")
    assert r2.is_docker_hub is True
    assert r2.repository == "bitnami/redis"
    assert r2.tag == "7.0"
    print(f"bitnami/redis:7.0 -> {r2}")

    # 3. GitHub Container Registry (ghcr.io)
    r3 = parse_image_reference("ghcr.io/org/repo:v1.0")
    assert r3.is_docker_hub is False
    assert r3.registry == "ghcr.io"
    assert r3.registry_host == "ghcr.io"
    assert r3.repository == "org/repo"
    assert r3.tag == "v1.0"
    print(f"ghcr.io/org/repo:v1.0 -> {r3}")

    # 4. Quay.io
    r4 = parse_image_reference("quay.io/coreos/etcd:v3.5.0")
    assert r4.is_docker_hub is False
    assert r4.registry == "quay.io"
    assert r4.repository == "coreos/etcd"
    assert r4.tag == "v3.5.0"
    print(f"quay.io/coreos/etcd:v3.5.0 -> {r4}")

    # 5. Public AWS ECR
    r5 = parse_image_reference("public.ecr.aws/docker/library/redis:latest")
    assert r5.is_docker_hub is False
    assert r5.registry == "public.ecr.aws"
    assert r5.repository == "docker/library/redis"
    assert r5.tag == "latest"
    print(f"public.ecr.aws/docker/library/redis:latest -> {r5}")

    # 6. Digest reference
    r6 = parse_image_reference("ghcr.io/org/app@sha256:" + "a" * 64)
    assert r6.digest == "sha256:" + "a" * 64
    assert r6.repository == "org/app"
    print(f"ghcr.io/org/app@sha256:... -> {r6}")

def test_multi_registry_existence():
    print()
    print("=" * 60)
    print("TEST 9b — Multi-Registry Existence & Tag Check")
    print("=" * 60)

    # Third-party registry tags check should not crash or query Docker Hub
    exists, msg = verify_registry_image_exists("ghcr.io/github/super-linter:latest")
    print(f"GHCR exists: {exists} | {msg}")
    assert msg is not None

    is_fake, fake_msg = check_registry_tag_exists("ghcr.io/github/super-linter:v999.999.fake")
    print(f"GHCR fake tag: {is_fake} | {fake_msg}")

if __name__ == "__main__":
    test_multi_registry_parsing()
    test_multi_registry_existence()
