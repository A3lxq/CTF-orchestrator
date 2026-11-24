"""Runs once at container boot, before supervisord starts anything --
everything here is per-team (derived from CTF_SECRET); every OTHER
account/cron/sshd/decoy fixture is baked into the image at build time
instead, since none of it varies by team (see the Dockerfile).

Order matters: Flag 5's own encrypted artifact uses Flag 3's freshly-
computed value as its *password* -- not a separately-derived secret,
Flag 3's actual plaintext value, mirroring the original box's own
chain (recover a passphrase from git history, decrypt flag 3, carry
that value forward to unlock the final root-only artifact).
"""
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, "/opt/shared")
import flagcrypto  # noqa: E402
from generate_flags import flag_for  # noqa: E402

SECRET = os.environ["CTF_SECRET"]
MATERIALS = Path("/var/www/materials")


def flag(n: int) -> str:
    return flag_for(SECRET, n)


def write_handover_photo_exif() -> None:
    """Flag 2: overwrite just the Comment tag on the bundled template
    photo, keeping every other tag (Artist etc.) as originally
    authored."""
    dest = MATERIALS / "metadata" / "handover_photo.png"
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["cp", "/opt/materials/handover_photo.png", str(dest)],
        check=True,
    )
    subprocess.run(
        [
            "exiftool", "-overwrite_original",
            f"-Comment=handover desk photo -- {flag(2)}",
            str(dest),
        ],
        check=True, capture_output=True,
    )
    # scan_backup.png (decoy d2b) is fully static -- its EXIF was
    # authored once and never needs to change per team.
    subprocess.run(
        ["cp", "/opt/materials/scan_backup.png", str(dest.parent / "scan_backup.png")],
        check=True,
    )


def build_stage3_git_archive() -> None:
    """Flag 3: a fresh 4-commit git repo every boot, same structure the
    original box used -- a real backup commit, a louder decoy commit
    closer to HEAD (password right in its own commit message), then a
    cleanup commit that deletes both from the working tree (still
    recoverable via `git show <commit>:path`)."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "stage3-git-history"
        repo.mkdir()

        def git(*args, env_extra=None):
            env = {**os.environ, "GIT_AUTHOR_NAME": "jtyler_dev", "GIT_AUTHOR_EMAIL": "jtyler@example.invalid",
                    "GIT_COMMITTER_NAME": "jtyler_dev", "GIT_COMMITTER_EMAIL": "jtyler@example.invalid"}
            if env_extra:
                env.update(env_extra)
            subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, env=env)

        def commit_at(ts: str, message: str):
            git("commit", "-q", "-m", message, env_extra={"GIT_AUTHOR_DATE": ts, "GIT_COMMITTER_DATE": ts})

        git("init", "-q", "-b", "main")
        (repo / "README.md").write_text("# ledger-tools\n\nInternal handover tooling.\n")
        git("add", "README.md")
        commit_at("2019-10-01T09:00:00", "Initial commit")

        (repo / "notes.txt").write_text(
            "Encrypting the handover backup with our standard passphrase for "
            "this rotation: BlueHarbor-99\n"
            "(old 2018 wifi password was retired: old-wifi-2018 -- don't reuse "
            "that one)\n"
        )
        (repo / "handover_backup.enc").write_bytes(flagcrypto.encrypt_bytes("BlueHarbor-99", flag(3).encode()))
        git("add", "notes.txt", "handover_backup.enc")
        commit_at("2019-10-15T14:22:00", "Add encrypted handover backup + passphrase note")

        # Decoy, deliberately louder and closer to HEAD: a player
        # scanning `git log` newest-first hits this one first.
        (repo / "old_backup_2018.enc").write_bytes(
            flagcrypto.encrypt_bytes("old-wifi-2018", b"FFLAG{rotated_out_jan_2019_e2a4}")
        )
        git("add", "old_backup_2018.enc")
        commit_at(
            "2019-11-02T11:05:00",
            "Found the old 2018 backup again! Password is old-wifi-2018, decrypt old_backup_2018.enc",
        )

        (repo / "handover_backup.enc").unlink()
        (repo / "notes.txt").unlink()
        (repo / "old_backup_2018.enc").unlink()
        (repo / "README.md").write_text(
            "# ledger-tools\n\nInternal handover tooling.\n\n"
            "(cleanup: removed stale backup files from the working tree)\n"
        )
        git("add", "-A")
        commit_at("2019-11-10T16:40:00", "Clean up stale backup files")

        archive_dir = MATERIALS / "stage3"
        archive_dir.mkdir(parents=True, exist_ok=True)
        archive_path = archive_dir / "stage3-git-history.tar.gz"
        if archive_path.exists():
            archive_path.unlink()
        with tarfile.open(archive_path, "w:gz") as tf:
            tf.add(repo, arcname="stage3-git-history")


def write_admin_flag4() -> None:
    flags_dir = Path("/home/admin/flags")
    flags_dir.mkdir(parents=True, exist_ok=True)
    blob = flagcrypto.encrypt_bytes("oldhandoff-rotate-2024", flag(4).encode())
    (flags_dir / "original_flag_4.enc").write_bytes(blob)
    subprocess.run(["chown", "-R", "admin:admin", str(flags_dir)], check=True)
    subprocess.run(["chmod", "640", str(flags_dir / "original_flag_4.enc")], check=True)


def write_root_flag5() -> None:
    """Flag 5's passphrase is Flag 3's own plaintext value -- the one
    genuinely dynamic password anywhere in this box."""
    blob = flagcrypto.encrypt_bytes(flag(3), flag(5).encode())
    dest = Path("/root/final_evidence.enc")
    dest.write_bytes(blob)
    subprocess.run(["chmod", "600", str(dest)], check=True)


def main() -> None:
    write_handover_photo_exif()
    build_stage3_git_archive()
    write_admin_flag4()
    write_root_flag5()
    print("[boot_setup] per-team content generated.")


if __name__ == "__main__":
    main()
