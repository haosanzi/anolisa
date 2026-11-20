"""Credential setup and assertions for the optional GitHub GET /user case."""

import getpass
import http.client
import json
import os
import shutil
import subprocess
import time
import warnings
from pathlib import Path


def github_user(token: bytes, expected: int) -> str:
    conn = http.client.HTTPSConnection("api.github.com", timeout=20)
    try:
        conn.request(
            "GET",
            "/user",
            headers={
                "User-Agent": "anolisa-local-selftest",
                "Authorization": b"Bearer " + token,
            },
        )
        response = conn.getresponse()
        if response.status != expected:
            raise RuntimeError(
                f"Direct GitHub control expected HTTP {expected}, got {response.status}"
            )
        return json.loads(response.read())["login"] if expected == 200 else ""
    finally:
        conn.close()


def credentials(directory: Path, source: str) -> tuple[bytes, bytes, str]:
    if source == "gh":
        token = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=20,
        ).stdout.strip()
    else:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            token = getpass.getpass("GitHub test token (hidden): ").strip().encode()
    if not token or not token.isascii() or not all(33 <= char <= 126 for char in token):
        raise RuntimeError("Expected one nonempty ASCII token")
    real = directory / "real"
    fake = directory / "fake"
    real.write_bytes(token)
    subprocess.run(
        [
            "agent-sec-cli",
            "key",
            "generate-fake",
            "--real-token-file",
            real,
            "--output",
            fake,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=20,
    )
    surrogate = fake.read_bytes().strip()
    if not surrogate or token in surrogate:
        raise RuntimeError("Invalid surrogate returned by generate-fake")
    login = github_user(token, 200)
    github_user(surrogate, 401)
    if not isinstance(login, str) or not login:
        raise RuntimeError("Missing login in direct GitHub control")
    return token, surrogate, login


def enable(cli, cleanup) -> Path:
    if cli("gateway", "status")["enabled"] is False:
        cleanup.callback(cli, "gateway", "disable")
        cli("gateway", "enable")
    for _ in range(30):
        if cli("gateway", "status")["ready"] is True:
            bundle = Path(cli("gateway", "ca")["caBundlePath"])
            if bundle.is_file():
                return bundle
        time.sleep(1)
    raise RuntimeError("Gateway did not become ready with a CA bundle")


def client_files(row: Path, bundle: Path, fake: bytes, uid: int, gid: int) -> None:
    shutil.copyfile(bundle, row / "home/gateway-ca.pem")
    header = row / "home/github-header"
    header.write_bytes(b"Authorization: Bearer " + fake + b"\n")
    for path in (header, row / "home/gateway-ca.pem"):
        os.chown(path, uid, gid)


def policy_text(directory: Path) -> str:
    template = Path(__file__).with_name("gateway.cedar.in").read_text()
    return template.replace("{real_file}", str(directory / "real")).replace(
        "{fake_file}", str(directory / "fake")
    )


def packets(scope: str) -> int:
    output = subprocess.check_output(
        ["nft", "-j", "list", "table", "inet", "agent_sec_gateway"], timeout=10
    )
    counters = [
        expr["counter"]["packets"]
        for entry in json.loads(output)["nftables"]
        if entry.get("rule", {}).get("comment") == f"asc:scope:{scope}"
        for expr in entry["rule"]["expr"]
        if "counter" in expr
    ]
    if not counters:
        raise RuntimeError("Missing nftables packet counter for this Gateway scope")
    return sum(counters)


def verify(read, real: bytes, fake: bytes, login: str) -> None:
    log = read("out/debug.log")
    body = read("out/github-user.json")
    if real in log or real in body:
        raise RuntimeError("Real credential found in a client artifact")
    if log.splitlines() != [b"Authorization: Bearer " + fake]:
        raise RuntimeError(
            "Expected exactly the surrogate header in the client debug log"
        )
    document = json.loads(body)
    if (
        read("out/http-status").strip() != b"200"
        or not isinstance(document, dict)
        or document.get("login") != login
    ):
        raise RuntimeError(
            "Expected HTTP 200 and the same login as the direct GitHub control"
        )
