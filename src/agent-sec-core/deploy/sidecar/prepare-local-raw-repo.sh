#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
raw_output_dir="${repo_root}/target/raw"
raw_repo_dir="${1:-${script_dir}/raw-repo}"
target_os="linux"
target_arch="x86_64"

cd "${repo_root}"

if [[ "$(uname -m)" != "${target_arch}" ]]; then
    echo "ERROR: sec-core raw sidecar artifacts currently support x86_64 only" >&2
    exit 1
fi

make -C "${repo_root}" package-raw OUTPUT_DIR="${raw_output_dir}"

version="$(
    python3 -c \
        'import pathlib, tomllib; print(tomllib.loads(pathlib.Path(".anolisa/component.toml").read_text())["component"]["version"])' \
        2>/dev/null
)"
artifact_name="sec-core-${version}-${target_os}-${target_arch}.tar.gz"
artifact="${raw_output_dir}/${artifact_name}"

if [[ ! -f "${artifact}" ]]; then
    echo "ERROR: raw artifact was not created: ${artifact}" >&2
    exit 1
fi

repo_v1_dir="${raw_repo_dir}/v1"
artifact_relative_path="sec-core/${version}/${target_os}/${target_arch}/${artifact_name}"
artifact_dir="${repo_v1_dir}/sec-core/${version}/${target_os}/${target_arch}"

rm -rf "${repo_v1_dir}"
install -d -m 0755 "${artifact_dir}"
install -p -m 0644 "${artifact}" "${artifact_dir}/${artifact_name}"
install -p -m 0644 \
    "${repo_root}/.anolisa/component.toml" \
    "${repo_v1_dir}/sec-core/${version}/meta.toml"

artifact_sha256="$(sha256sum "${artifact}" | cut -d ' ' -f 1)"
manifest_sha256="$(sha256sum "${repo_root}/.anolisa/component.toml" | cut -d ' ' -f 1)"

for index_name in index.toml index-v2.toml; do
    index_path="${repo_v1_dir}/${index_name}"
    printf '%s\n' \
        'schema_version = 1' \
        'channel = "stable"' \
        'publisher = "agent-sec-core-local"' \
        '' \
        '[[entries]]' \
        'component = "sec-core"' \
        "version = \"${version}\"" \
        'channel = "stable"' \
        'artifact_type = "tar_gz"' \
        'backend = "raw"' \
        "url = \"${artifact_relative_path}\"" \
        "os = \"${target_os}\"" \
        "arch = \"${target_arch}\"" \
        'install_modes = ["system"]' \
        "sha256 = \"${artifact_sha256}\"" \
        "manifest_digest = \"sha256:${manifest_sha256}\"" \
        > "${index_path}"
done

printf 'Prepared sec-core %s Anolisa raw repository at %s\n' \
    "${version}" "${raw_repo_dir}"
