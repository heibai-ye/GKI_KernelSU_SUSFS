import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import zlib


SOURCE_COMMIT = "d415a2d4bd29d2e3d5b138d72fe606034ebdef44"
SOURCE_TAG = "android15-6.6-2025-03_r1"
KSU_COMMIT = "0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d"
PATCH_COMMIT = "dc0f76bedd790b7738e5695509297ee71ca4a2c2"
REQUIRED = (
    "SYSVIPC", "POSIX_MQUEUE", "IPC_NS", "PID_NS", "DEVTMPFS",
    "USER_NS", "NETFILTER_XT_MATCH_ADDRTYPE", "TMPFS_XATTR",
    "TMPFS_POSIX_ACL", "ARM64_4K_PAGES", "KSU", "IKCONFIG",
    "IKCONFIG_PROC",
)
DISABLED = ("CFS_BANDWIDTH", "CGROUP_PIDS", "NTSYNC", "KSU_SUSFS", "KPM")


def git(directory, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(directory), *arguments], text=True
    ).strip()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check_source(common):
    require(git(common, "rev-parse", "HEAD") == SOURCE_COMMIT, "Source commit drift")
    makefile = (common / "Makefile").read_text()
    for key, value in (("VERSION", "6"), ("PATCHLEVEL", "6"), ("SUBLEVEL", "77")):
        require(re.search(rf"^{key}\s*=\s*{value}$", makefile, re.M), f"Unexpected {key}")
    require(re.search(r"^KMI_GENERATION=['\"]?8['\"]?$", (common / "build.config.common").read_text(), re.M), "KMI must be 8")
    require(re.search(r"^CLANG_VERSION=['\"]?r510928['\"]?$", (common / "build.config.constants").read_text(), re.M), "Clang must be r510928")


def pin(root, output):
    common = root / "common"
    subprocess.run([
        "git", "-C", str(common), "fetch", "--depth=1",
        "https://android.googlesource.com/kernel/common",
        f"refs/tags/{SOURCE_TAG}",
    ], check=True)
    subprocess.run(["git", "-C", str(common), "checkout", "--detach", SOURCE_COMMIT], check=True)
    check_source(common)
    manifest = subprocess.check_output([os.environ["REPO"], "manifest", "-r"], cwd=root)
    (output / "repo-manifest.xml").write_bytes(manifest)
    (output / "baseline.json").write_text(json.dumps({
        "source_commit": SOURCE_COMMIT,
        "source_tag": SOURCE_TAG,
        "kernelsu_commit": KSU_COMMIT,
        "kernelsu_release": "3.3.1",
        "droidspaces_patch_commit": PATCH_COMMIT,
        "running_kernel_exact_source_confirmed": False,
        "flash_ready": False,
    }, indent=2) + "\n")


def prepare(root, output):
    common = root / "common"
    check_source(common)
    require(git(root / "KernelSU", "rev-parse", "HEAD") == KSU_COMMIT, "KernelSU drift")
    require((common / "drivers/kernelsu").is_symlink(), "KernelSU driver link missing")
    sched = (common / "include/linux/sched.h").read_text()
    require("ANDROID_KABI_USE(3, struct sysv_sem sysvsem);" in sched, "SYSVIPC slot 3 missing")
    require("_ANDROID_KABI_REPLACE(ANDROID_KABI_RESERVE(4); ANDROID_KABI_RESERVE(5), struct sysv_shm sysvshm);" in sched, "SYSVIPC slots 4/5 missing")
    rtmutex = (common / "kernel/locking/rtmutex.c").read_text()
    proxy = (common / "kernel/locking/rtmutex_api.c").read_text()
    require("struct task_struct *waiter_task = waiter->task;" in rtmutex, "rtmutex waiter fix missing")
    require("if (!waiter_task)" in rtmutex, "rtmutex NULL guard missing")
    require(re.search(r"ret = __rt_mutex_start_proxy_lock\([^;]+;\s*if \(unlikely\(ret < 0\)\)", proxy), "Proxy cleanup fix missing")
    require(not list(common.rglob("*.rej")), "Patch reject files present")
    require("$(obj)/config_data: $(KCONFIG_CONFIG) FORCE" in (common / "kernel/Makefile").read_text(), "Embedded config must describe the actual build")
    config = Path(os.environ["DEFCONFIG"])
    for symbol in REQUIRED:
        subprocess.run([str(common / "scripts/config"), "--file", str(config), "-e", symbol], check=True)
    for symbol in DISABLED:
        if re.search(rf"^(?:# )?CONFIG_{symbol}(?:=| is not set$)", config.read_text(), re.M):
            subprocess.run([str(common / "scripts/config"), "--file", str(config), "-d", symbol], check=True)
    shutil.copyfile(config, output / "requested-defconfig")
    (output / "common.diff").write_text(git(common, "diff", "--binary") + "\n")
    (output / "kernelsu.diff").write_text(git(root / "KernelSU", "diff", "--binary") + "\n")
    subprocess.run(["git", "-C", str(common), "status", "--short"], check=True,
                   stdout=(output / "common-status.txt").open("w"))
    patch = Path(os.environ["DROIDSPACES_PATCHES"]) / "below-kernel-6.12/001.GKI-below-6.12-fix_sysvipc_kabi_3_4_5.patch"
    shutil.copyfile(patch, output / "sysvipc-345.patch")


def collect(root, output):
    candidates = [
        root / "bazel-bin/common/kernel_aarch64",
        root / "out/android15-6.6/dist",
    ]
    build = next((candidate for candidate in candidates if (candidate / "Image").is_file()), None)
    require(build is not None, "No compiled aarch64 Image")
    for name in ("Image", "Module.symvers"):
        source = build / name
        require(source.is_file(), f"Required verification output missing: {source}")
        shutil.copyfile(source, output / name)
    for name in ("vmlinux", "System.map", "vmlinux.symvers", "kernel.release"):
        if (build / name).is_file():
            shutil.copyfile(build / name, output / name)
    image = (output / "Image").read_bytes()
    config_start = image.find(b"IKCFG_ST")
    require(config_start >= 0, "Actual embedded kernel config missing")
    compressed_config = zlib.decompressobj(wbits=31)
    config_bytes = compressed_config.decompress(image[config_start + 8:])
    require(compressed_config.eof and compressed_config.unused_data.startswith(b"IKCFG_ED"), "Invalid embedded config markers")
    (output / "final.config").write_bytes(config_bytes)
    config = config_bytes.decode()
    if (build / ".config").is_file():
        require((build / ".config").read_bytes() == config_bytes, "Build config and embedded config differ")
    for symbol in REQUIRED:
        require(f"CONFIG_{symbol}=y" in config.splitlines(), f"Final config missing {symbol}")
    for symbol in DISABLED:
        require(not re.search(rf"^CONFIG_{symbol}=[ym]$", config, re.M), f"Unexpected {symbol}")
    require(image[56:60] == b"ARM\x64", "Bad ARM64 Image magic")
    require(((struct.unpack_from("<Q", image, 24)[0] >> 1) & 3) == 1, "Image must use 4 KiB pages")
    release = re.search(rb"Linux version ([^\x00\n]+)", image)
    require(release is not None and release.group(1).startswith(b"6.6.77-android15-8"), "Unexpected kernel release")
    (output / "kernel-version.txt").write_bytes(release.group(1) + b"\n")
    metadata = {"run_id": os.environ.get("GITHUB_RUN_ID"), "workflow_commit": os.environ.get("GITHUB_SHA"), "config_source": "Image IKCONFIG with stock-config spoofing disabled", "module_abi_validation": "pending", "sunuefi_repack": "pending", "flash_ready": False}
    (output / "build-result.json").write_text(json.dumps(metadata, indent=2) + "\n")
    hashes = []
    for artifact in sorted(output.iterdir()):
        if artifact.is_file() and artifact.name != "SHA256SUMS":
            digest = hashlib.file_digest(artifact.open("rb"), "sha256").hexdigest()
            hashes.append(f"{digest}  {artifact.name}\n")
    (output / "SHA256SUMS").write_text("".join(hashes))


if __name__ == "__main__":
    kernel_root = Path(os.environ["KERNEL_ROOT"])
    artifacts = Path(os.environ["GITHUB_WORKSPACE"]) / "piano-verification"
    artifacts.mkdir(exist_ok=True)
    try:
        {"pin": pin, "prepare": prepare, "collect": collect}[sys.argv[1]](kernel_root, artifacts)
    except Exception as error:
        (artifacts / "failure.json").write_text(json.dumps({"stage": sys.argv[1], "error": str(error)}, indent=2) + "\n")
        raise
