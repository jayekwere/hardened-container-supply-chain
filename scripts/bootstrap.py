#!/usr/bin/env python3
"""Install only locked tool bytes. No package manager or mutable install script."""
import hashlib, io, json, platform, tarfile, urllib.request
from pathlib import Path
root = Path(__file__).resolve().parent.parent
os_name = {"Darwin": "darwin", "Linux": "linux"}[platform.system()]
arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}[platform.machine()]
key = os_name + "-" + arch
for name, tool in json.loads((root / "tools.lock.json").read_text()).items():
    item = tool["platforms"].get(key)
    if item is None:
        raise SystemExit("unsupported platform: " + key)
    download = root / ".tools/downloads" / (name + "-" + key if name == "kubectl" else item["url"].rsplit("/", 1)[1])
    download.parent.mkdir(parents=True, exist_ok=True)
    if not download.exists():
        download.write_bytes(urllib.request.urlopen(item["url"], timeout=120).read())
    data = download.read_bytes()
    if hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise SystemExit("checksum mismatch: " + name)
    if name == "go":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            archive.extractall(root / ".tools", filter="data")
        dest = root / ".tools/bin/go"
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_symlink() or dest.exists():
            dest.unlink()
        dest.symlink_to("../go/bin/go")
        print("go " + tool["version"] + ": checksum verified")
        continue
    if item["url"].endswith(".tar.gz"):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = next(m for m in archive.getmembers() if m.isfile() and m.name.rsplit("/", 1)[-1] == name)
            data = archive.extractfile(member).read()
    dest = root / ".tools/bin" / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    dest.chmod(0o755)
    print(name + " " + tool["version"] + ": checksum verified")
