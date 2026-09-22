"""Cleanup fault tests: all Docker, sudo and removal commands are inert stubs.

The fake daemon persists state so an empty result is distinct from a failed list
and successful removals must really change the inventory before local deletion.
No test calls the real Docker daemon, rm, systemctl or sudo.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "clean-shakerscan.sh"
STUB = r'''#!PYTHON
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
statefile = pathlib.Path(os.environ["CLEAN_TEST_STATE"])
state = json.loads(statefile.read_text())
with open(os.environ["CLEAN_TEST_LOG"], "a") as log:
    log.write(json.dumps([name, *args]) + "\n")
def save():
    statefile.write_text(json.dumps(state))
def fail(message="injected failure"):
    print(message, file=sys.stderr); sys.exit(1)
if name in ("rm", "rmdir"):
    # No deletion at all, even in /tmp. Hide only the runtime via a bounded rename
    # so the script's final absence check runs; unittest removes the fixture later.
    if state.get("rm_failure"):
        fail()
    if name == "rm" and "-rf" in args:
        target = pathlib.Path(args[-1])
        root = pathlib.Path(os.environ["CLEAN_TEST_ROOT"])
        if target == root / "home" / ".shakerscan" and target.is_dir():
            target.rename(root / "removed-runtime")
    elif name == "rmdir":
        fail("inert rmdir: directory retained")
    sys.exit(0)
if name == "sudo":
    if args[:2] != ["--", "docker"]:
        fail("unexpected sudo command")
    name, args = "docker", args[2:]
if name != "docker":
    fail("host integration commands must not run")
if args[:2] == ["context", "show"]:
    print("test-context"); sys.exit(0)
if args[:2] == ["context", "inspect"]:
    if state.get("context_failure"): fail()
    print(state.get("endpoint", "unix:///test/docker.sock")); sys.exit(0)
if args[:1] != ["--host"]:
    fail("daemon was not pinned")
if os.environ.get("DOCKER_CONTEXT") or os.environ.get("DOCKER_HOST"):
    fail("inherited context override")
args = args[2:]
if args[:1] == ["info"]:
    if state.get("offline"): fail("permission denied connecting to Docker")
    state["info_calls"] = state.get("info_calls", 0) + 1
    save()
    print("changed" if state.get("change_daemon") and state["info_calls"] > 1 else "daemon-1")
    sys.exit(0)
kind = None
if args[:1] == ["ps"]: kind = "containers"
elif args[:2] == ["volume", "ls"]: kind = "volumes"
elif args[:2] == ["network", "ls"]: kind = "networks"
if kind:
    if "--filter" not in args or args[args.index("--filter") + 1] != "label=com.docker.compose.project=" + state.get("project", "shakerscan"):
        fail("wrong project filter")
    state["list_" + kind] = state.get("list_" + kind, 0) + 1
    save()
    if state.get("list_failure") == kind: fail()
    if state.get("verify_failure") == kind and state["list_" + kind] >= 3: fail()
    if state.get("change_resources") and kind == "containers" and state["list_" + kind] >= 2:
        state[kind] = ["new-container"]
    print("\n".join(state.get(kind, []))); sys.exit(0)
if args[:1] == ["inspect"]:
    if state.get("inspect_failure"): fail()
    if "working_dir" in args[args.index("--format") + 1]:
        print(state.get("workdir", os.environ["CLEAN_TEST_RUNTIME"]))
    else: print("shakerscan/shakerscan-api:fixture")
    sys.exit(0)
if args[:1] == ["rm"]: kind = "containers"
elif args[:2] == ["volume", "rm"]: kind = "volumes"
elif args[:2] == ["network", "rm"]: kind = "networks"
elif args[:2] == ["image", "rm"]: kind = "images"
if kind:
    if state.get("remove_failure") == kind: fail()
    if not state.get("leave_resources"):
        state[kind] = [i for i in state.get(kind, []) if i != args[-1]]
    if state.get("swap_path") and kind == "networks":
        p = pathlib.Path(os.environ["CLEAN_TEST_RUNTIME"])
        p.rename(p.with_name("old-runtime"))
        p.symlink_to(pathlib.Path(os.environ["HOME"]) / "Documents", target_is_directory=True)
    save(); sys.exit(0)
fail("unexpected Docker command: " + repr(args))
'''


class CleanShakerScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="shakerscan-clean-test-")
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "home"
        self.runtime = self.home / ".shakerscan"
        self.config = self.home / ".config" / "shakerscan"
        self.bin = self.home / ".local" / "bin"
        for p in (self.runtime, self.config, self.bin, self.home / "Documents"):
            p.mkdir(parents=True, exist_ok=True)
        (self.runtime / "scanner.sh").write_text("#!/bin/bash\n# ShakerScan - CLI Management Tool\n")
        (self.runtime / "docker-compose.release.yml").write_text("# ShakerScan\nservices: {}\n")
        (self.config / "config.json").write_text('{"url":"http://fixture:8080"}\n')
        (self.config / "token").write_text("synthetic-test-token\n")
        (self.bin / "shakerscan").write_text(f'#!/bin/sh\nexec "{self.runtime}/scanner.sh" "$@"\n')
        self.state = self.root / "state.json"
        self.state.write_text(json.dumps({"containers": ["c1"], "volumes": ["v1"], "networks": ["n1"]}))
        self.log = self.root / "commands.jsonl"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        for command in ("docker", "sudo", "rm", "rmdir", "systemctl", "wg-quick"):
            p = self.tools / command
            p.write_text(STUB.replace("#!PYTHON", "#!" + sys.executable + " -S"))
            p.chmod(0o755)
        self.env = dict(os.environ)
        for name in list(self.env):
            if name.startswith(("SHAKERSCAN_", "DOCKER_", "COMPOSE_")) or name == "SUDO_USER":
                self.env.pop(name)
        self.env.update(HOME=str(self.home), PATH=str(self.tools) + os.pathsep + os.environ["PATH"],
                        CLEAN_TEST_STATE=str(self.state), CLEAN_TEST_LOG=str(self.log),
                        CLEAN_TEST_ROOT=str(self.root), CLEAN_TEST_RUNTIME=str(self.runtime))
        self.bash = os.environ.get("CLEAN_TEST_BASH") or shutil.which("bash")

    def tearDown(self):
        self.tmp.cleanup()

    def configure(self, **changes):
        state = json.loads(self.state.read_text()); state.update(changes)
        self.state.write_text(json.dumps(state))

    def run_script(self, *args, env=None, stdin=""):
        return subprocess.run([self.bash, str(SCRIPT), *args], cwd=self.root,
                              env={**self.env, **(env or {})}, input=stdin,
                              text=True, capture_output=True, timeout=20)

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def assert_no_local_removal(self):
        self.assertFalse([c for c in self.commands() if c[0] in {"rm", "rmdir"}], self.commands())

    def assert_no_mutation(self):
        self.assert_no_local_removal()
        self.assertFalse([c for c in self.commands() if c[0] in {"systemctl", "wg-quick"} or "rm" in c], self.commands())

    def test_help_and_syntax(self):
        self.assertEqual(subprocess.run([self.bash, "-n", str(SCRIPT)]).returncode, 0)
        self.assertEqual(self.run_script("--help").returncode, 0)
        self.assert_no_mutation()

    def test_home_aliases_and_shared_roots_are_rejected(self):
        for path in (str(self.home), str(self.home) + "/", str(self.home) + "///",
                     str(self.runtime / ".."), str(self.home / "Documents"), "/", "/tmp", "/etc", ""):
            with self.subTest(path=path):
                result = self.run_script("--home", path, "--yes")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assert_no_mutation()

    def test_symlinked_runtime_is_rejected(self):
        link = self.home / "alias"; link.symlink_to(self.runtime, target_is_directory=True)
        result = self.run_script("--home", str(link) + "/", "--yes")
        self.assertNotEqual(result.returncode, 0); self.assert_no_mutation()

    def test_home_symlink_is_rejected(self):
        link = self.root / "home-alias"; link.symlink_to(self.home, target_is_directory=True)
        result = self.run_script("--home", str(link), "--yes")
        self.assertNotEqual(result.returncode, 0); self.assert_no_mutation()

    def test_unmarked_directory_is_rejected(self):
        path = self.home / "unrelated"; path.mkdir()
        result = self.run_script("--home", str(path), "--yes")
        self.assertNotEqual(result.returncode, 0); self.assert_no_mutation()

    def test_unrecognized_compose_is_rejected(self):
        (self.runtime / "docker-compose.release.yml").write_text("services: {}\n")
        self.assertNotEqual(self.run_script("--yes").returncode, 0); self.assert_no_mutation()

    def test_config_home_and_ancestors_are_rejected(self):
        for path in (str(self.home), str(self.home) + "/", str(self.root), str(self.home / ".config"), ""):
            with self.subTest(path=path):
                self.assertNotEqual(self.run_script("--yes", env={"SHAKERSCAN_CONFIG_DIR": path}).returncode, 0)
                self.assert_no_mutation()

    def test_config_symlink_to_home_is_rejected(self):
        alias = self.root / "config-alias"; alias.symlink_to(self.home, target_is_directory=True)
        self.assertNotEqual(self.run_script("--yes", env={"SHAKERSCAN_CONFIG_DIR": str(alias)}).returncode, 0)
        self.assert_no_mutation()

    def test_unrecognized_profile_is_retained(self):
        (self.config / "config.json").write_text('{"unrelated":"application"}')
        self.assertNotEqual(self.run_script("--yes").returncode, 0); self.assert_no_mutation()

    def test_dry_run_and_cancel_do_not_mutate(self):
        self.assertEqual(self.run_script("--dry-run").returncode, 0)
        self.assertEqual(self.run_script(stdin="NO\n").returncode, 0)
        self.assertEqual(self.run_script(stdin="").returncode, 0)
        self.assert_no_mutation()

    def test_daemon_permission_error_keeps_all_files(self):
        self.configure(offline=True)
        result = self.run_script("--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--sudo-docker", result.stderr)
        self.assertNotIn("cleanup complete", result.stdout); self.assert_no_mutation()

    def test_initial_inventory_failures_stop_before_removal(self):
        for kind in ("containers", "volumes", "networks"):
            with self.subTest(kind=kind):
                self.configure(list_failure=kind)
                self.assertNotEqual(self.run_script("--yes").returncode, 0)
                self.assert_no_mutation()

    def test_removal_errors_preserve_local_config(self):
        for kind in ("containers", "volumes", "networks", "images"):
            with self.subTest(kind=kind):
                self.configure(containers=["c1"], volumes=["v1"], networks=["n1"], remove_failure=kind)
                result = self.run_script("--yes", "--images")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn("cleanup complete", result.stdout); self.assert_no_local_removal()

    def test_post_removal_inventory_failures_preserve_local_config(self):
        for kind in ("containers", "volumes", "networks"):
            with self.subTest(kind=kind):
                self.configure(containers=["c1"], volumes=["v1"], networks=["n1"],
                               list_containers=0, list_volumes=0, list_networks=0, verify_failure=kind)
                self.assertNotEqual(self.run_script("--yes").returncode, 0)
                self.assert_no_local_removal()

    def test_lingering_resources_are_not_success(self):
        self.configure(leave_resources=True)
        self.assertNotEqual(self.run_script("--yes").returncode, 0); self.assert_no_local_removal()

    def test_context_and_daemon_changes_abort(self):
        self.configure(change_daemon=True)
        self.assertNotEqual(self.run_script("--yes").returncode, 0); self.assert_no_mutation()

    def test_changed_inventory_requires_new_preview(self):
        self.configure(change_resources=True)
        self.assertNotEqual(self.run_script("--yes").returncode, 0); self.assert_no_mutation()

    def test_remote_context_is_not_a_local_cleanup(self):
        for endpoint in ("ssh://remote", "tcp://127.0.0.1:2375"):
            with self.subTest(endpoint=endpoint):
                self.configure(endpoint=endpoint)
                self.assertNotEqual(self.run_script("--yes").returncode, 0)
                self.assert_no_mutation()

    def test_wrong_project_workdir_is_rejected(self):
        self.configure(workdir=str(self.home / "other-install"))
        self.assertNotEqual(self.run_script("--yes").returncode, 0); self.assert_no_mutation()

    def test_context_lookup_and_ownership_inspection_fail_closed(self):
        for failure in ("context_failure", "inspect_failure"):
            with self.subTest(failure=failure):
                self.configure(context_failure=False, inspect_failure=False)
                self.configure(**{failure: True})
                self.assertNotEqual(self.run_script("--yes").returncode, 0)
                self.assert_no_mutation()

    def test_invalid_project_and_control_character_path(self):
        for args in (("--project", ""), ("--project", "../wrong"), ("--home", str(self.runtime) + "\n")):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_script(*args, "--yes").returncode, 0)
                self.assert_no_mutation()

    def test_keep_client_cannot_erase_nested_client_state(self):
        result = self.run_script("--keep-client", "--yes", env={"SHAKERSCAN_CONFIG_DIR": str(self.runtime / "client")})
        self.assertNotEqual(result.returncode, 0); self.assert_no_mutation()

    def test_missing_config_and_launcher_are_idempotent(self):
        self.config.rename(self.home / "saved-client")
        (self.bin / "shakerscan").unlink()
        self.assertEqual(self.run_script("--yes").returncode, 0)

    def test_local_removal_failure_is_not_success(self):
        self.configure(rm_failure=True)
        result = self.run_script("--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("cleanup complete", result.stdout)
        self.assertIn("Local cleanup incomplete", result.stderr)

    def test_docker_host_override_is_pinned(self):
        result = self.run_script("--yes", env={"DOCKER_HOST": "unix:///test/rootless.sock"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(c[1:3] == ["--host", "unix:///test/rootless.sock"] for c in self.commands() if c[0] == "docker"))

    def test_runtime_symlink_swap_preserves_local_files(self):
        self.configure(swap_path=True)
        self.assertNotEqual(self.run_script("--yes").returncode, 0); self.assert_no_local_removal()

    def test_valid_removal_is_ordered_and_label_scoped(self):
        (self.config / "unrelated.txt").write_text("retain")
        result = self.run_script("--yes")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        commands = self.commands()
        removes = [c for c in commands if c[0] == "docker" and "rm" in c]
        self.assertEqual([c[-1] for c in removes], ["c1", "v1", "n1"])
        last_docker = max(i for i, c in enumerate(commands) if c[0] == "docker")
        first_local = min(i for i, c in enumerate(commands) if c[0] == "rm")
        self.assertLess(last_docker, first_local)
        self.assertEqual([c[-1] for c in commands if c[0] == "rm" and "-rf" in c], [str(self.runtime)])
        self.assertTrue((self.config / "unrelated.txt").exists())
        self.assertIn("cleanup complete", result.stdout)

    def test_valid_runtime_with_trailing_slash_and_space_parent(self):
        # Spaces already work in all quoted paths; exercise an aliasing parent too.
        alias = self.root / "parent with spaces"; alias.symlink_to(self.home, target_is_directory=True)
        result = self.run_script("--home", str(alias / ".shakerscan") + "/", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_runtime_and_empty_docker_is_idempotent(self):
        self.runtime.rename(self.home / "previous-runtime")
        self.configure(containers=[], volumes=[], networks=[])
        self.assertEqual(self.run_script("--yes").returncode, 0)

    def test_keep_client_preserves_profile_and_launcher(self):
        result = self.run_script("--keep-client", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c[-1] for c in self.commands() if c[0] == "rm"], [str(self.runtime)])

    def test_owned_launcher_is_selected_before_runtime_disappears(self):
        self.assertEqual(self.run_script("--yes").returncode, 0)
        self.assertIn(["rm", "-f", "--", str(self.bin / "shakerscan")], self.commands())

    def test_package_manager_launcher_is_preserved(self):
        launcher = self.bin / "shakerscan"; launcher.unlink()
        launcher.symlink_to("/not-installed/package-manager-client")
        self.assertEqual(self.run_script("--yes").returncode, 0)
        self.assertNotIn(["rm", "-f", "--", str(launcher)], self.commands())

    def test_explicit_sudo_pins_same_socket(self):
        result = self.run_script("--sudo-docker", "--yes", env={"DOCKER_CONTEXT": "owner-context"})
        self.assertEqual(result.returncode, 0, result.stderr)
        for cmd in self.commands():
            if cmd[0] == "sudo": self.assertEqual(cmd[1:5], ["--", "docker", "--host", "unix:///test/docker.sock"])

    def test_custom_project_is_used_for_every_inventory(self):
        self.configure(project="my_lab")
        self.assertEqual(self.run_script("--project", "my_lab", "--yes").returncode, 0)

    def test_missing_docker_never_removes_local_files(self):
        (self.tools / "docker").unlink()
        # Restrict PATH to known safe utilities; do not accidentally find host Docker.
        for name in ("sed", "grep", "sort"):
            (self.tools / name).symlink_to(shutil.which(name))
        result = self.run_script("--yes", env={"PATH": str(self.tools)})
        self.assertNotEqual(result.returncode, 0); self.assert_no_mutation()

    def test_no_compose_env_or_host_integration_execution(self):
        (self.runtime / ".env").write_text("$(touch /never-execute-this)\nPOSTGRES_PASSWORD=\n")
        self.assertEqual(self.run_script("--yes").returncode, 0)
        self.assertFalse([c for c in self.commands() if "compose" in c or c[0] in {"systemctl", "wg-quick"}])


if __name__ == "__main__":
    unittest.main()
