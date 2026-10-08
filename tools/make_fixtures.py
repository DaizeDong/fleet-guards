"""Generate synthetic records and visibility receipts for the guard regressions."""
import json
import hashlib
from pathlib import Path


# ------------------------------------------------- spawning processes (identical in every kit file)
# A console program started by a process that has NO console (pythonw, a scheduled task, a service)
# is handed a brand-new console, and Windows shows it as a window. Measured 2026-10-05: a daemon
# under pythonw ran a companion proof on every log line, each proof ran about 19 git commands, and
# the machine took roughly 9,000 terminal windows in eight hours. So every spawn in this kit goes
# through _no_window(), and tools/test_no_console_window.py fails on any spawn that does not.
#
# The flag is added ONLY when this process has no console. A process that has one already shares it
# with its children and never opens a window; giving those children CREATE_NO_WINDOW would instead
# move their unredirected output and terminal prompts into a hidden console, where a hook's findings
# would vanish (measured: an unredirected child's output is simply lost). DETACHED_PROCESS and
# CREATE_NEW_CONSOLE are refused outright: the first makes Windows ignore CREATE_NO_WINDOW and
# leaves a console-less child whose own children open windows again, and the second opens a window
# by definition.
#
# Each file carries its own copy because consumers load these files one at a time by path; a
# shared sibling module would be a new way for a single copied file to fail. That test holds
# every copy identical, so the copies cannot drift.
def _console_less_windows():
    """True on Windows when this process has no console, so a console child would get a window.

    A hidden console counts as a console: children of a CREATE_NO_WINDOW child share it unseen.
    If the console cannot be queried the answer is True, the side on which no window can open.
    """
    import sys
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return not ctypes.WinDLL("kernel32").GetConsoleCP()
    except (ImportError, AttributeError, OSError):
        return True


def _no_window(**kwargs):
    """Return subprocess keywords that can never open a console window.

    Merges into any creationflags the caller passes: subprocess.run(args, **_no_window(cwd=root)).
    """
    flags = kwargs.get("creationflags", 0) or 0
    if flags & 0x00000018:              # DETACHED_PROCESS | CREATE_NEW_CONSOLE
        raise ValueError("DETACHED_PROCESS and CREATE_NEW_CONSOLE can open console windows")
    if _console_less_windows():
        kwargs["creationflags"] = flags | 0x08000000      # CREATE_NO_WINDOW
    return kwargs


def https_transport_cases():
    """Generate transport policy cases without contacting or configuring a real remote."""
    cases = [{"id": "canonical", "config": [], "env": {}, "blocked": False}]
    settings = {
        "proxy": "http://proxy.example.invalid:8080",
        "curloptresolve": "github.com:443:192.0.2.10",
        "sslverify": "false",
        "sslcainfo": "synthetic-ca.pem",
        "sslcapath": "synthetic-ca",
        "sslbackend": "synthetic-backend",
        "schannelusesslcainfo": "true",
        "schannelcheckrevoke": "false",
        "pinnedpubkey": "synthetic-public-key",
        "followredirects": "true",
        "extraheader": "Host: mirror.example.invalid",
        "cookiefile": "synthetic-cookies.txt",
        "proxysslcainfo": "synthetic-proxy-ca.pem",
        "newtransportoption": "synthetic-option",
    }
    for key, value in settings.items():
        for prefix, scope in (("http.", "global"), ("http.https://github.com/.", "url")):
            cases.append({"id": scope + "-" + key, "config": [(prefix + key, value)],
                          "env": {}, "blocked": True})
    for key in ("proxy", "proxyAuthMethod"):
        cases.append({"id": "remote-" + key, "config": [("remote.origin." + key, "synthetic")],
                      "env": {}, "blocked": True})
    cases.append({"id": "multivalue-reset", "config": [
        ("http.curloptresolve", "github.com:443:192.0.2.10"), ("http.curloptresolve", "")],
        "env": {}, "blocked": True})
    for key in ("HTTPS_PROXY", "http_proxy", "All_Proxy", "GIT_SSL_NO_VERIFY", "GIT_SSL_CAINFO",
                "GIT_SSL_CAPATH", "GIT_PROXY_SSL_CAINFO", "CURL_CA_BUNDLE", "CURL_SSL_BACKEND",
                "SSL_CERT_FILE", "ssl_cert_dir", "GIT_EXEC_PATH", "GIT_HTTP_USER_AGENT"):
        cases.append({"id": "env-" + key, "config": [], "env": {key: "synthetic-override"},
                      "blocked": True})
    loopback = "http://127.0.0.1:8788"
    for case_id, env, blocked in (
            ("proxy-bypass-exact", {"HTTPS_PROXY": loopback, "NO_PROXY": "github.com"}, False),
            ("proxy-bypass-dot", {"https_proxy": loopback, "no_proxy": ".GitHub.com"}, False),
            ("proxy-bypass-list", {"HTTPS_PROXY": loopback, "https_proxy": loopback,
                                   "NO_PROXY": "localhost,127.0.0.1,::1, github.com",
                                   "NODE_EXTRA_CA_CERTS": "synthetic-ca.pem"}, False),
            ("proxy-bypass-all", {"All_Proxy": loopback, "NO_PROXY": " * "}, False),
            ("proxy-bypass-loopback-only", {"HTTPS_PROXY": loopback, "NO_PROXY": "localhost,127.0.0.1"}, True),
            ("proxy-bypass-subdomain", {"HTTPS_PROXY": loopback, "NO_PROXY": "gist.github.com"}, True),
            ("proxy-bypass-lookalike", {"HTTPS_PROXY": loopback, "NO_PROXY": "github.com.example.invalid"}, True),
            ("proxy-bypass-port", {"HTTPS_PROXY": loopback, "NO_PROXY": "github.com:443"}, True),
            ("proxy-bypass-space-list", {"HTTPS_PROXY": loopback, "NO_PROXY": "localhost github.com"}, True),
            ("proxy-bypass-star-entry", {"HTTPS_PROXY": loopback, "NO_PROXY": "localhost,*"}, True),
            ("proxy-bypass-split-spelling", {"HTTPS_PROXY": loopback, "NO_PROXY": "github.com",
                                             "no_proxy": "localhost"}, True),
            ("proxy-bypass-keeps-trust", {"HTTPS_PROXY": loopback, "NO_PROXY": "github.com",
                                          "SSL_CERT_FILE": "synthetic-ca.pem"}, True),
            ("proxy-bypass-keeps-git-env", {"HTTPS_PROXY": loopback, "NO_PROXY": "github.com",
                                            "GIT_SSL_NO_VERIFY": "1"}, True)):
        cases.append({"id": case_id, "config": [], "env": env, "blocked": blocked})
    cases.append({"id": "proxy-bypass-keeps-config", "config": [("http.proxy", loopback)],
                  "env": {"NO_PROXY": "github.com"}, "blocked": True})
    for value in ("true", "YES", "On", "1"):
        cases.append({"id": "verification-" + value, "config": [("http.sslVerify", value)],
                      "env": {}, "blocked": False})
    for key, value in (("version", "HTTP/2"), ("maxRequests", "5"), ("minSessions", "1"),
                       ("postBuffer", "1048576"), ("lowSpeedLimit", "10"), ("lowSpeedTime", "30"),
                       ("keepAliveIdle", "30"), ("keepAliveInterval", "5"), ("keepAliveCount", "3")):
        cases.append({"id": "performance-" + key, "config": [("http." + key, value)],
                      "env": {}, "blocked": False})
    cases.append({"id": "credential-config", "config": [("credential.helper", "synthetic-helper")],
                  "env": {}, "blocked": False})
    cases.append({"id": "performance-env", "config": [], "env": {
        "GIT_HTTP_LOW_SPEED_LIMIT": "10", "GIT_HTTP_LOW_SPEED_TIME": "30", "no_proxy": "localhost"},
        "blocked": False})
    authorization = "AUTHORIZATION: basic c3ludGhldGlj"
    for label, key, value, blocked in (
        ("authorization-basic", "http.extraHeader", authorization, False),
        ("authorization-checkout", "http.https://github.com/.extraHeader", authorization, False),
        ("authorization-case-space", "HTTP.HTTPS://GITHUB.COM/.EXTRAHEADER", "Authorization:   Basic c3ludGhldGlj", False),
        ("authorization-bearer", "http.extraHeader", "authorization: bearer synthetic-token", False),
        ("authorization-host-mismatch", "http.https://example.invalid/.extraHeader", authorization, True),
        ("authorization-host-suffix", "http.https://github.com.example.invalid/.extraHeader", authorization, True),
        ("authorization-crlf", "http.extraHeader", authorization + "\r\nHost: example.invalid", True),
        ("authorization-newline", "http.extraHeader", authorization + "\n", True),
        ("authorization-leading-space", "http.extraHeader", " " + authorization, True),
        ("authorization-tab", "http.extraHeader", "Authorization:\tBasic c3ludGhldGlj", True),
        ("authorization-empty", "http.extraHeader", "Authorization: Basic ", True),
    ):
        cases.append({"id": label, "config": [(key, value)], "env": {}, "blocked": blocked})
    cases.append({"id": "authorization-plus-host", "config": [
        ("http.extraHeader", authorization), ("http.extraHeader", "Host: example.invalid")],
        "env": {}, "blocked": True})
    return cases


def ssh_trust_cases():
    """Generate SSH server-authentication cases without touching a real SSH profile."""
    rows = [
        ("default", [None], False),
        ("canonical", ["Host github.com\n HostName github.com\n User git\n Port 22\n"], False),
        ("strict", ["Host github.com\n StrictHostKeyChecking yes\n"], False),
        ("ask", ["Host github.com\n StrictHostKeyChecking ask\n"], False),
        ("case-equals", ["Host GITHUB.COM\n StrictHostKeyChecking=YES\n"], False),
        ("client-identity", ["Host github.com\n IdentityFile ~/.ssh/synthetic-key\n IdentitiesOnly yes\n"], False),
        ("unrelated", ["Host example.invalid\n StrictHostKeyChecking no\n UserKnownHostsFile /dev/null\n"], False),
        ("negated", ["Host * !github.com\n StrictHostKeyChecking no\n"], False),
        ("no", ["Host github.com\n StrictHostKeyChecking no\n"], True),
        ("off", ["Host github.com\n StrictHostKeyChecking off\n"], True),
        ("false", ["Host github.com\n StrictHostKeyChecking false\n"], True),
        ("accept-new", ["Host github.com\n StrictHostKeyChecking accept-new\n"], True),
        ("empty", ['Host github.com\n StrictHostKeyChecking ""\n'], True),
        ("multiple", ["Host github.com\n StrictHostKeyChecking yes no\n"], True),
        ("global", ["StrictHostKeyChecking no\n"], True),
        ("wildcard", ["Host *\n StrictHostKeyChecking no\n"], True),
        ("user-null", ["Host github.com\n UserKnownHostsFile /dev/null\n"], True),
        ("user-windows-null", ["Host github.com\n UserKnownHostsFile NUL\n"], True),
        ("global-none", ["Host github.com\n GlobalKnownHostsFile none\n"], True),
        ("user-custom", ["Host github.com\n UserKnownHostsFile synthetic-known-hosts\n"], True),
        ("global-custom", ["Host github.com\n GlobalKnownHostsFile synthetic-known-hosts\n"], True),
        ("strict-custom", ["Host github.com\n StrictHostKeyChecking yes\n UserKnownHostsFile synthetic-known-hosts\n"], True),
        ("disabled-empty-trust", ["Host github.com\n StrictHostKeyChecking no\n UserKnownHostsFile /dev/null\n GlobalKnownHostsFile /dev/null\n"], True),
        ("first-value-wins", ["StrictHostKeyChecking no\nHost github.com\n StrictHostKeyChecking yes\n"], True),
        ("second-config", ["Host github.com\n IdentityFile ~/.ssh/synthetic-key\n", "Host github.com\n StrictHostKeyChecking no\n"], True),
    ]
    return [{"id": label, "configs": configs, "blocked": blocked}
            for label, configs, blocked in rows]


def write_ssh_trust_case(root, case):
    """Materialize a generated case in the caller's temporary directory."""
    directory = Path(root) / "synthetic-ssh"
    directory.mkdir(parents=True)
    paths = []
    for index, content in enumerate(case["configs"]):
        path = directory / ("config-" + str(index))
        if content is not None:
            path.write_text(content, encoding="utf-8")
        paths.append(str(path))
    return paths


def write_record(root, relative):
    path = Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"id":"synthetic-record","run":1}\n', encoding="utf-8")
    return path


def write_visibility(path, states, refreshed):
    path = Path(path)
    path.write_text(json.dumps({"_refreshed": refreshed, **states}, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def synthetic_token(label):
    return "synthetic-private-" + hashlib.sha256(label.encode("utf-8")).hexdigest()[:16]


def make_identity_shape_fixture(repo, root, role, domain_case, numeric):
    """Generate isolated commit identities with and without a numeric noreply ID."""
    root = Path(root)
    home = root / "identity-home"
    home.mkdir()
    domain = "users.noreply.github.com"
    domain = {"lower": domain, "upper": domain.upper(), "mixed": "Users.NoReply.GitHub.Com"}[domain_case]
    valid = "12345678+Fixture@users.noreply.github.com"
    tested = ("12345678+Fixture" if numeric else "Fixture") + "@" + domain
    repo.env.update(HOME=str(home), USERPROFILE=str(home),
                    GIT_AUTHOR_NAME="Fixture", GIT_COMMITTER_NAME="Fixture",
                    GIT_AUTHOR_EMAIL=valid, GIT_COMMITTER_EMAIL=valid)
    repo.env["GIT_" + role.upper() + "_EMAIL"] = tested
    write_empty_tool_classification(repo.root)
    write_encoded_record(repo.root, "seed.md", ["synthetic identity hook control"])
    return numeric


def write_owner_scope_visibility(path, refreshed, duplicate=False, reverse=False):
    """Fresh cross-owner records in a deliberately preserved input order."""
    name = "synthetic-demo-skill"
    current = "example-owner-a/" + ("other-tool" if duplicate else name)
    pairs = [("example-owner-a/" + name, "PUBLIC")]
    if duplicate:
        pairs.append(("example-owner-a/" + name + "-config", "PRIVATE"))
    pairs.append(("example-owner-b/" + name + "-config", "PRIVATE"))
    if reverse:
        pairs.reverse()
    Path(path).write_text(json.dumps({"_refreshed": refreshed, **dict(pairs)}) + "\n",
                          encoding="utf-8")
    return current, name + "-config"


def write_mailbox_filename(root, suffix=".png", blocked=True, placeholder=False):
    """Place an entirely synthetic identifier in a public pathname, with binary bytes."""
    mailbox = ("synthetic.person." + hashlib.sha256(b"filename-control").hexdigest()[:12]
               + "@" + "gmail.com") if blocked else "user1@example.com"
    if placeholder:
        mailbox = "user1" + "@" + "gmail.com"
    relative = "contacts/" + mailbox + suffix
    path = Path(root)/relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x89PNG\r\n\x1a\n\x00synthetic\x00")
    return relative, mailbox


def make_tag_metadata_fixture(repo, field, target="commit", blocked=True):
    """Publish generated metadata through ordinary, aliased, and nested synthetic tags."""
    token = synthetic_token("source7-tag-metadata")
    text = token if blocked else "synthetic safe metadata"
    write_encoded_record(repo.root, "seed.md", ["synthetic clean seed"])
    repo.commit("synthetic clean commit")
    object_id = repo.git("rev-parse", {"commit": "HEAD", "tree": "HEAD^{tree}",
                                      "blob": "HEAD:seed.md"}[target]).stdout.strip()
    name = token if blocked and field in ("ref_name", "object_name") else "synthetic-tag"
    message = text if field in ("annotation", "nested_annotation") else "synthetic annotation"
    expected = token
    if field == "tagger_email":
        expected = "user1@example.com"
        if blocked:
            repo.env["GIT_COMMITTER_EMAIL"] = expected
    elif field == "tagger_name" and blocked:
        repo.env["GIT_COMMITTER_NAME"] = token
    if field == "ref_name":
        repo.git("tag", name, object_id)
    else:
        repo.git("tag", "-a", "-m", message, name, object_id)
    if field == "object_name":
        oid = repo.git("rev-parse", "refs/tags/" + name).stdout.strip()
        repo.git("update-ref", "refs/tags/synthetic-retained", oid)
        repo.git("tag", "-d", name)
    elif field == "nested_annotation":
        repo.git("tag", "-a", "-m", "synthetic wrapper", "synthetic-outer", name)
        repo.git("tag", "-d", name)
    return {"token": token, "expected": expected}


def write_empty_tool_classification(root):
    path = Path(root)/".dataclass.json"
    path.write_text(json.dumps({"data": [], "fixture": [], "_audited": "synthetic tool"}) + "\n",
                    encoding="utf-8")
    return path


def make_history_fixture(repo, head_state, violation="clean"):
    """Generate reachable-ref controls in an isolated synthetic Repo fixture."""
    token = synthetic_token("reachable-history-" + violation)
    if head_state == "empty":
        return token
    write_encoded_record(repo.root, "notes.md", [token if violation == "blob" else "synthetic content"])
    if head_state == "blob-tag":
        oid = repo.git("hash-object", "-w", "notes.md").stdout.strip()
        repo.git("tag", "synthetic-retained", oid)
        return token
    repo.git("add", "notes.md")
    message = token if violation == "message" else "synthetic history"
    author = ["--author", "Fixture <user1@example.com>"] if violation == "author" else []
    repo.git("commit", "-qm", message, *author)
    if head_state in {"unborn-branch", "unborn-tag"}:
        if head_state == "unborn-tag":
            repo.git("tag", "synthetic-retained")
        repo.git("symbolic-ref", "HEAD", "refs/heads/synthetic-unborn")
        if head_state == "unborn-tag":
            repo.git("update-ref", "-d", "refs/heads/master")
    elif head_state == "broken":
        (Path(repo.root) / ".git/HEAD").write_text("f" * 40 + "\n", encoding="ascii")
    elif head_state != "valid":
        raise ValueError("Unknown synthetic HEAD state")
    return token


def make_tree_ref_fixture(repo, shape, blocked, with_commit=False, annotated=False):
    """Generate tree refs without relying on filesystem support for unusual Git names."""
    import subprocess

    def object_command(arguments, payload):
        result = subprocess.run(["git", *arguments], cwd=repo.root, env=repo.env,
                                input=payload, capture_output=True, text=True, encoding="utf-8",
                                **_no_window())
        if result.returncode:
            raise RuntimeError(result.stderr)
        return result.stdout.strip()

    def tree(entries):
        return object_command(["mktree", "-z"], "".join(
            "%s %s %s\t%s\0" % entry for entry in entries))

    if with_commit:
        write_encoded_record(repo.root, "seed.md", ["synthetic committed seed"])
        repo.commit("synthetic committed root")
    token = synthetic_token("tree-ref-path")
    name = token if blocked else "synthetic-safe"
    body = structural_probe() if shape == "aliases" else "synthetic tree-ref body\n"
    blob = object_command(["hash-object", "-w", "--stdin"], body)
    roots = []
    if shape == "directory":
        child = tree([("100644", "blob", blob, "notes.md")])
        paths = [name, name + "/notes.md"]
        roots.append(tree([("040000", "tree", child, name)]))
    elif shape in {"gitlink", "gitlink-only"}:
        empty = tree([])
        commit = object_command(["commit-tree", empty], "synthetic detached commit\n")
        paths = [name]
        entries = [("160000", "commit", commit, name)]
        if shape == "gitlink":
            entries.append(("100644", "blob", blob, "notes.md"))
        roots.append(tree(entries))
    elif shape == "aliases":
        child = tree([("100644", "blob", blob, "pii_guard.py")])
        roots.append(tree([("040000", "tree", child, "tools")]))
        paths = ["tools/pii_guard.py"]
        if blocked:
            roots.append(tree([("100644", "blob", blob, "notes.md")]))
            paths.append("notes.md")
    else:
        relative = ("odd space\tline\n\"" + name + ".md" if shape == "odd-name"
                    else name + ".md")
        paths = [relative]
        roots.append(tree([("100644", "blob", blob, relative)]))
    for number, oid in enumerate(roots):
        arguments = ["tag"]
        if annotated:
            arguments += ["-a", "-m", "synthetic retained tree"]
        repo.git(*arguments, "synthetic-tree-%d" % number, oid)
    return {"token": token, "paths": paths, "trees": roots, "blob": blob}


def write_policy(path, token, canary):
    path = Path(path)
    path.write_text(json.dumps({"format": 2, "canary": canary, "count": 2,
                              "tokens": [{"value": value, "kind": "secret"}
                                         for value in (token, canary)]}) + "\n", encoding="utf-8")
    return path


def write_ci_suite(root, outcome):
    path = Path(root) / "guards/tools/test_data_boundary.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    if outcome != "missing":
        path.write_text("def test_synthetic_boundary():\n    assert %r\n" % (outcome == "pass"),
                        encoding="utf-8")
    return path


def write_invalid_git_marker(root, relative):
    path = Path(root) / relative / ".git"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("synthetic invalid git marker\n", encoding="utf-8")
    return path


def write_stale_guard(root, relative):
    path = Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("import os\nfrom pathlib import Path\n"
                    "Path(os.environ['FG_SYNTHETIC_RECEIPT']).write_text('stale called')\n",
                    encoding="utf-8")
    return path


def write_origin_config(root, section, key, value):
    path = Path(root) / ".git/config"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("%s\n%s = %s\n" % (section, key, value), encoding="utf-8")
    return path


def structural_probe():
    return "# See ~/.claude/scripts/synthetic_fixture.py\n"


def write_commit_message_rule(root):
    path = Path(root) / "commit-msg"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('#!/bin/sh\nprintf "called\\n" >> "$FG_SYNTHETIC_RECEIPT"\n'
                    'exit "$FG_SYNTHETIC_COMMIT_STATUS"\n', encoding="utf-8")
    path.chmod(0o755)
    return path


def write_encoded_record(root, relative, lines, encoding="utf-8"):
    """Generate a text fixture in an editor-supported encoding, without platform newlines."""
    path = Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(lines) + "\n"
    data = (b"\xfe\xff" + text.encode("utf-16-be") if encoding == "utf-16-be-bom"
            else text.encode(encoding))
    path.write_bytes(data)
    return path


def write_encoding_probe(root, relative, encoding, variant="mixed", token=None):
    """Generate editor text, including both plausible byte orders in one ambiguous record."""
    token = token or synthetic_token("encoding-probe")
    if variant == "ambiguous":
        other = synthetic_token("other-byte-order")
        data = (token + "\n").encode("utf-16-le") + (other + "\n").encode("utf-16-be")
        path = Path(root) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path, [token, other]
    prefix = "# synthetic text" if variant == "ascii" else "# café 中文 Ā"
    return write_encoded_record(root, relative, [prefix, token], encoding), [token]


def reencode_record(path, source_encoding, target_encoding):
    """Change only the encoding of a generated record, preserving every decoded character."""
    path = Path(path)
    path.write_bytes(path.read_bytes().decode(source_encoding).encode(target_encoding))
    return path


def write_ssh_config(root, variant, relative=".ssh/config"):
    """Generate only synthetic OpenSSH configuration for static destination attestation."""
    configurations = {
        "absent": None,
        "identity": "Host github.com\n IdentityFile ~/.ssh/synthetic-key\n IdentitiesOnly yes\n",
        "canonical": "Host github.com\n HostName github.com\n User git\n Port 22\n",
        "unrelated": "Host example.invalid\n HostName other.invalid\n",
        "remap": "Host github.com\n HostName example.invalid\n",
        "wildcard": "Host *\n HostName example.invalid\n",
        "include": "Include synthetic-config.d/*\n",
        "match-exec": 'Match exec "synthetic-command-that-must-never-run"\n HostName example.invalid\n',
        "proxy": "Host github.com\n ProxyCommand synthetic-command-that-must-never-run\n",
        "canonicalize": "Host github.com\n CanonicalizeHostname yes\n CanonicalDomains example.invalid\n",
        "port": "Host github.com\n Port 2222\n",
    }
    path = Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if configurations[variant] is not None:
        path.write_text(configurations[variant], encoding="utf-8")
    return path


def make_ssh_layout(root, *, bundled_client=False):
    """Generate distinct account, environment, client and system locations for SSH tests."""
    root = Path(root)
    layout = {name: root / name for name in (
        "environment-home", "userprofile", "account-home", "expanded-home",
        "windows", "program-data", "git-installation")}
    for name in ("environment-home", "userprofile", "account-home", "expanded-home"):
        write_ssh_config(layout[name], "absent")
    write_ssh_config(layout["program-data"], "absent", "ssh/ssh_config")
    write_ssh_config(layout["git-installation"], "absent", "etc/ssh/ssh_config")
    if bundled_client:
        executable = layout["git-installation"] / "usr/bin/ssh.exe"
        executable.parent.mkdir(parents=True)
        executable.write_text("synthetic client metadata; never execute\n", encoding="utf-8")
    return layout


def write_count_policy(path, token, canary, variant):
    """Generate completeness controls with one enforceable token retained after truncation."""
    entries = [token, synthetic_token("removed-policy-entry"), canary]
    data = {"format": 2, "count": len(entries), "canary": canary, "tokens": entries}
    if variant != "healthy":
        data["tokens"].pop(1)
    if variant == "missing":
        del data["count"]
    elif variant in {"null", "boolean", "string", "float"}:
        data["count"] = {"null": None, "boolean": True, "string": "2", "float": 2.0}[variant]
    elif variant == "legacy-list":
        data = [token]
    elif variant in {"legacy-dict", "legacy-format1"}:
        data = {"tokens": [token]}
        if variant == "legacy-format1":
            data["format"] = 1
    path = Path(path)
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")
    return path


def make_install_alias(alias, target):
    """Generate a native directory alias to a synthetic installation."""
    import os
    import subprocess
    alias, target = Path(alias), Path(target)
    if os.name == "nt":
        env = dict(os.environ, FG_FIXTURE_ALIAS=str(alias), FG_FIXTURE_TARGET=str(target))
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        "$ErrorActionPreference='Stop'; New-Item -ItemType Junction "
                        "-Path $env:FG_FIXTURE_ALIAS -Target $env:FG_FIXTURE_TARGET | Out-Null"],
                       env=env, check=True, capture_output=True, **_no_window())
    else:
        alias.symlink_to(target, target_is_directory=True)
    return alias


def declaration_name_cases():
    """Generate canonical paths and ambiguous Windows declaration spellings."""
    return {
        "ambiguous": (
            ("directory-dot", "private-store./"),
            ("directory-space", "private-store /"),
            ("ancestor-dot", "private-store./nested/profile.txt"),
            ("ancestor-space", "private-store /nested/profile.txt"),
            ("leaf-dot", "private-store/profile.txt."),
            ("leaf-space", "private-store/profile.txt "),
            ("repeated-dots", "private-store.../profile.txt"),
            ("mixed-suffix", "private-store. /profile.txt. "),
            ("glob-ancestor", "private-store./*.txt"),
            ("glob-leaf", "private-store/*.txt "),
        ),
        "canonical": (
            ("directory", "private-store/"),
            ("hidden-directory", ".private-store/"),
            ("file", "private-store/profile.txt"),
            ("interior-space", "private store/profile.txt"),
            ("interior-dot", "private.store/profile.txt"),
            ("star-glob", "private-store/*.txt"),
            ("class-glob", "private-store/file[12].txt"),
            ("question-glob", "private-store/file?.txt"),
        ),
    }


def write_declaration_name_fixture(root, key, level, suffix, aliased, present):
    """Generate a declaration plus a canonical synthetic record and any required schema."""
    root = Path(root)
    relative = "private-store/profile.txt"
    ending = suffix if aliased else ""
    declaration = ("private-store" + ending + "/" if level == "directory"
                   else relative + ending)
    manifest = {"data": [], "data_sealed": [], "fixture": [], "tool": [],
                "_audited": "synthetic declaration-name control", key: [declaration]}
    (root / ".dataclass.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    if key == "data" and level == "leaf":
        write_record(root, declaration + ".example")
    record = write_record(root, relative) if present else None
    return declaration, relative, record


class GitContextFixture:
    """Native Git fixture with generated identities and an isolated configuration."""

    def __init__(self, root, configuration, initialize=True):
        import os
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.upper().startswith("GIT_")}
        self.env.update(GIT_CONFIG_GLOBAL=str(configuration),
                        GIT_CONFIG_SYSTEM=str(Path(configuration).with_suffix(".absent")),
                        GIT_CONFIG_NOSYSTEM="1", GIT_OPTIONAL_LOCKS="0",
                        GIT_TERMINAL_PROMPT="0",
                        GIT_AUTHOR_DATE="2001-01-01T00:00:00+0000",
                        GIT_COMMITTER_DATE="2001-01-01T00:00:00+0000")
        if initialize:
            self.git("init", "-q", "-b", "main")

    def git(self, *arguments, payload=None, env=None):
        import subprocess
        result = subprocess.run(["git", *arguments], cwd=self.root, env=env or self.env,
                                input=payload.encode("utf-8") if payload is not None else None,
                                capture_output=True, **_no_window())
        if result.returncode:
            raise RuntimeError("synthetic Git setup failed: " + result.stderr.decode("utf-8", "replace"))
        return result.stdout.decode("utf-8").strip()

    def copy_index(self, label="selected"):
        import shutil
        index = Path(self.git("rev-parse", "--path-format=absolute", "--git-path", "index"))
        copied = self.root.parent / (self.root.name + "-" + label + ".index")
        shutil.copyfile(index, copied)
        return str(copied)


def write_git_context_configuration(root):
    """Keep synthetic commits away from host identity and hook configuration."""
    root = Path(root)
    path = root / "synthetic.gitconfig"
    hooks = root / "empty-hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    path.write_text('[user]\n name = Fixture\n email = 12345678+Fixture@users.noreply.github.com\n'
                    '[core]\n hooksPath = "%s"\n' % hooks.as_posix(), encoding="utf-8")
    return path


def make_companion_context_fixture(root, refreshed):
    """Generate physical visibility controls and a separate invoking hook repository."""
    root = Path(root)
    configuration = write_git_context_configuration(root)
    repos = {}
    states = {"private": "PRIVATE", "public": "PUBLIC"}
    for label in ("private", "public", "unknown", "invoker"):
        repo = GitContextFixture(root / label, configuration)
        repo.git("remote", "add", "origin",
                 "https://github.com/example-owner/synthetic-%s.git" % label)
        write_record(repo.root, "archive/record.jsonl")
        repo.git("add", "--all")
        repo.git("commit", "-qm", "synthetic companion fixture")
        repos[label] = repo
    repos["private"].git("worktree", "add", "--detach", str(root / "linked"))
    repos["linked"] = GitContextFixture(root / "linked", configuration, initialize=False)
    receipt = write_visibility(root / "visibility.json", {
        "example-owner/synthetic-" + label: state for label, state in states.items()
    }, refreshed)
    return {"repos": repos, "receipt": receipt, "configuration": configuration}


def companion_environment_cases(fixture):
    """Return selectors and rewrites that must never lend PRIVATE identity to PUBLIC DATA."""
    private = fixture["repos"]["private"]
    gitdir = private.git("rev-parse", "--absolute-git-dir")
    public_url = "https://github.com/example-owner/synthetic-public.git"
    private_url = "https://github.com/example-owner/synthetic-private.git"
    rewrite = "url." + private_url + ".insteadOf"
    return {
        "git-dir": {"GIT_DIR": gitdir},
        "git-dir-and-worktree": {"GIT_DIR": gitdir, "GIT_WORK_TREE": str(private.root)},
        "common-dir": {"GIT_COMMON_DIR": gitdir},
        "worktree": {"GIT_WORK_TREE": str(private.root)},
        "command-config": {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": rewrite,
                           "GIT_CONFIG_VALUE_0": public_url},
        "config-parameters": {"GIT_CONFIG_PARAMETERS": "'" + rewrite + "=" + public_url + "'"},
        "copied-index": {"GIT_INDEX_FILE": private.copy_index("decoy")},
    }


def make_original_object_fixture(root, kind, blocked=True, custom_base=False):
    """Keep the original reachable from an ordinary ref while replacing its visible object."""
    root = Path(root)
    configuration = write_git_context_configuration(root)
    repo = GitContextFixture(root / "repo", configuration)
    token = synthetic_token("original-object-" + kind)
    sensitive = token if blocked else "synthetic original control"
    safe_blob = repo.git("hash-object", "-w", "--stdin", payload="synthetic clean replacement\n")
    original_blob = repo.git("hash-object", "-w", "--stdin",
                             payload=(sensitive if kind in {"blob", "commit-body", "ancestor"}
                                      else "synthetic original body") + "\n")
    original_name = sensitive + ".md" if kind == "tree-path" else "notes.md"

    def tree(blob, name="notes.md"):
        return repo.git("mktree", "-z", payload="100644 blob %s\t%s\0" % (blob, name))

    original_tree = tree(original_blob, original_name)
    clean_tree = tree(safe_blob)

    def commit(tree_id, message, parents=(), **identity):
        env = dict(repo.env, **identity)
        arguments = ["commit-tree", tree_id]
        for parent in parents:
            arguments.extend(["-p", parent])
        return repo.git(*arguments, payload=message + "\n", env=env)

    identity = {}
    if kind in {"author", "committer"} and blocked:
        identity["GIT_" + kind.upper() + "_EMAIL"] = "user1@example.com"
    original_commit = commit(original_tree, sensitive if kind == "message" else "synthetic original",
                             **identity)
    if kind == "ancestor":
        original_commit = commit(clean_tree, "synthetic descendant", [original_commit])
    replacement_commit = commit(clean_tree, "synthetic replacement")
    repo.git("update-ref", "refs/heads/main", original_commit)
    if kind in {"tag", "nested-tag"}:
        tag_data = ("object %s\ntype commit\ntag synthetic-inner\n"
                    "tagger Fixture <12345678+Fixture@users.noreply.github.com> 1700000000 +0000\n\n%s\n")
        original = repo.git("mktag", payload=tag_data % (original_commit, sensitive))
        replacement = repo.git("mktag", payload=tag_data % (replacement_commit, "synthetic clean tag"))
        if kind == "nested-tag":
            outer = repo.git("mktag", payload=(
                "object %s\ntype tag\ntag synthetic-outer\n"
                "tagger Fixture <12345678+Fixture@users.noreply.github.com> 1700000000 +0000\n\n"
                "synthetic wrapper\n") % original)
            repo.git("update-ref", "refs/tags/synthetic-outer", outer)
        else:
            repo.git("update-ref", "refs/tags/synthetic-original", original)
    elif kind == "tree-path":
        original, replacement = original_tree, clean_tree
        repo.git("update-ref", "refs/tags/synthetic-tree", original_tree)
        repo.git("update-ref", "refs/heads/main", replacement_commit)
    elif kind == "blob":
        original, replacement = original_blob, safe_blob
    else:
        original, replacement = original_commit, replacement_commit
    base = "refs/synthetic-replacements/" if custom_base else "refs/replace/"
    repo.git("update-ref", base + original, replacement)
    if custom_base:
        repo.env["GIT_REPLACE_REF_BASE"] = base
    # Explicitly materialize the original tree and a private index for every scan domain.
    repo.git("read-tree", original_tree, env=dict(repo.env, GIT_NO_REPLACE_OBJECTS="1"))
    repo.env["GIT_INDEX_FILE"] = repo.copy_index()
    return {"repo": repo, "token": token, "original": original, "replacement": replacement,
            "expected": "user1@example.com" if kind in {"author", "committer"} else token}


def make_selected_index_fixture(root, linked=False, blocked=True):
    """Generate distinct default and selected index content in ordinary or linked worktrees."""
    root = Path(root)
    configuration = write_git_context_configuration(root)
    repo = GitContextFixture(root / "main", configuration)
    write_encoded_record(repo.root, "notes.md", ["synthetic accepted seed"])
    repo.git("add", "notes.md")
    repo.git("commit", "-qm", "synthetic index control")
    if linked:
        repo.git("worktree", "add", "--detach", str(root / "linked"))
        repo = GitContextFixture(root / "linked", configuration, initialize=False)
    token = synthetic_token("selected-index")
    selected = repo.copy_index()
    blob = repo.git("hash-object", "-w", "--stdin",
                    payload=(token if blocked else "synthetic staged control") + "\n")
    repo.env.update(GIT_INDEX_FILE=selected, GIT_DIR=repo.git("rev-parse", "--absolute-git-dir"),
                    GIT_WORK_TREE=str(repo.root), GIT_PREFIX="")
    repo.git("update-index", "--add", "--cacheinfo", "100644", blob, "notes.md")
    return {"repo": repo, "token": token}


def configure_companion_context_fixture(fixture, variant):
    """Generate global settings and deliberately different companion/invoker indexes."""
    private = fixture["repos"]["private"]
    configuration = Path(fixture["configuration"])
    if variant == "global-ignore":
        relative = "archive/ignored.jsonl"
        write_record(private.root, relative)
        ignores = configuration.parent / "synthetic.ignore"
        ignores.write_text(relative + "\n", encoding="utf-8")
        with configuration.open("a", encoding="utf-8") as stream:
            stream.write('[core]\n excludesFile = "%s"\n longpaths = true\n' % ignores.as_posix())
    elif variant == "distinct-index":
        relative = "archive/invoker-only.jsonl"
        write_record(private.root, relative)
        invoker = fixture["repos"]["invoker"]
        write_record(invoker.root, relative)
        invoker.git("add", "--", relative)
    elif variant in {"missing", "global", "reset", "command"}:
        private.env["GIT_TEST_ASSUME_DIFFERENT_OWNER"] = "1"
        if variant in {"global", "reset"}:
            with configuration.open("a", encoding="utf-8") as stream:
                stream.write('[safe]\n directory = "%s"\n' % private.root.as_posix())
        if variant in {"reset", "command"}:
            private.env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="safe.directory",
                               GIT_CONFIG_VALUE_0=private.root.as_posix() if variant == "command" else "")
    else:
        raise ValueError("Unknown companion context control")
    return fixture


def make_repository_marker_fixture(root, kind):
    """Generate repository-marker layouts without consulting a host repository."""
    root = Path(root)
    tool = root / "tool"
    module = tool / "tools/datadir.py"
    module.parent.mkdir(parents=True)
    module.write_text("# synthetic installed module location\n", encoding="utf-8")
    git_marker = tool / ".git"
    common_marker = root / "git-admin/commondir"
    if kind == "directory":
        git_marker.mkdir()
    elif kind in {"gitfile", "linked"}:
        common_marker.parent.mkdir()
        git_marker.write_text("gitdir: ../git-admin\n", encoding="utf-8")
        if kind == "linked":
            common_marker.write_text("../synthetic-common\n", encoding="utf-8")
    elif kind != "exported":
        raise ValueError("Unknown synthetic repository-marker layout")
    inside, outside = tool / "archive", root / "private/archive"
    inside.mkdir()
    outside.mkdir(parents=True)
    return {"tool": tool, "module": module, "git": git_marker, "common": common_marker,
            "inside": inside, "outside": outside,
            "absent_parents": tuple(parent / ".git" for parent in tool.parents)}


def write_git_context_ci_suite(root, outcome):
    """Generate the one-test CI suite used to prove pass, failure and missing behavior."""
    path = Path(root) / "guards/tools/test_git_context.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    if outcome != "missing":
        path.write_text("def test_synthetic_git_context():\n    assert %r\n"
                        % (outcome == "pass"), encoding="utf-8")
    return path


def make_required_hook_tool_fixture(root, source, hook_name, selected_tool, state):
    """Generate a full hook kit with independently observable mandatory tools."""
    import os
    import shutil

    root = Path(root)
    configuration = write_git_context_configuration(root)
    repo = GitContextFixture(root / "repo", configuration)
    home = root / "hook-home"
    home.mkdir()
    receipt = root / "tool-calls.txt"
    repo.env.update(HOME=str(home), USERPROFILE=str(home),
                    FG_SYNTHETIC_RECEIPT=str(receipt))
    kit = root / "hook-kit"
    (kit / "hooks").mkdir(parents=True)
    (kit / "tools").mkdir()
    hook = kit / "hooks" / hook_name
    shutil.copyfile(Path(source) / "hooks" / hook_name, hook)
    shutil.copyfile(Path(source) / "tools/publication_guard.py", kit / "tools/publication_guard.py")
    for name in ("pii_guard.py", "data_boundary.py"):
        target = kit / "tools" / name
        if name == selected_tool and state == "empty":
            target.write_bytes(b"")
            continue
        status = 1 if name == selected_tool and state == "fail" else 0
        text = (
            "import os,sys\n"
            "class GitError(RuntimeError): pass\n"
            "def prove_private_companion(*args): raise GitError('synthetic UNKNOWN')\n"
            "if __name__ == '__main__':\n"
            "    with open(os.environ['FG_SYNTHETIC_RECEIPT'], 'a', encoding='utf-8') as stream:\n"
            "        stream.write(%r)\n"
            "    print(%r)\n"
            "    raise SystemExit(%d)\n"
        ) % (name + "\n", "synthetic tool ran: " + name, status)
        target.write_bytes(text.encode("utf-8"))
    return {"repo": repo, "hook": hook, "receipt": receipt, "kit": kit}


def make_policy_io_fixture(root, layer, present, canary, refreshed):
    """Generate private-policy loader inputs without consulting a host home."""
    root = Path(root)
    home = root / "policy-home"
    visibility = home / ".pii-guard/visibility.json"
    visibility.parent.mkdir(parents=True)
    denylist = root / "policy.json"
    token = synthetic_token("policy-io-protection")
    if layer != "denylist" or present:
        write_policy(denylist, token, canary)
    if layer != "visibility" or present:
        write_visibility(visibility, {"example-owner/synthetic-private-config": "PRIVATE"}, refreshed)
    repo = root / "policy-repo"
    repo.mkdir()
    return {"home": home, "denylist": denylist, "visibility": visibility,
            "target": denylist if layer == "denylist" else visibility,
            "repo": repo, "token": token, "cross_token": "synthetic-private-config"}


def object_batch_faults():
    """Malformed metadata and body responses for the synthetic two-blob graph."""
    return (
        "check-empty", "check-missing", "check-extra", "check-duplicate",
        "check-wrong-oid", "check-wrong-type", "check-negative-size",
        "check-nonnumeric-size", "check-no-newline", "check-nonascii",
        "batch-empty", "batch-missing-second", "batch-no-header-newline",
        "batch-short-body", "batch-no-delimiter", "batch-wrong-delimiter",
        "batch-extra", "batch-duplicate", "batch-wrong-type",
        "batch-size-mismatch", "batch-nonnumeric-size", "batch-negative-size",
    )


def make_object_batch_fixture(variant, limit):
    """Generate Git I/O transcripts; no object store or native Git is involved."""
    first, second, extra = ("1" * 40, "2" * 40, "3" * 40)
    token = synthetic_token("batch-body-protection")
    bodies = {first: b"synthetic clean body\n", second: (token + "\n").encode("ascii"),
              extra: b"synthetic unrequested body\n"}
    if variant == "binary":
        bodies[second] = b"\x00" * 32
    sizes = {oid: len(body) for oid, body in bodies.items()}
    if variant == "oversize":
        sizes[second] = limit + 1

    def metadata(oid, kind="blob", size=None):
        return ("%s %s %s\n" % (oid, kind, sizes[oid] if size is None else size)).encode("ascii")

    check = metadata(first) + metadata(second)
    if variant == "check-empty":
        check = b""
    elif variant == "check-missing":
        check = metadata(first)
    elif variant == "check-extra":
        check += metadata(extra)
    elif variant == "check-duplicate":
        check = metadata(first) * 2
    elif variant == "check-wrong-oid":
        check = metadata(first) + metadata(extra)
    elif variant == "check-wrong-type":
        check = metadata(first) + metadata(second, kind="unsupported")
    elif variant == "check-negative-size":
        check = metadata(first) + metadata(second, size=-1)
    elif variant == "check-nonnumeric-size":
        check = metadata(first) + metadata(second, size="invalid")
    elif variant == "check-no-newline":
        check = check[:-1]
    elif variant == "check-nonascii":
        check = metadata(first) + b"\xff blob 1\n"

    def batch(requested):
        records = [(metadata(oid, size=len(bodies[oid])) + bodies[oid] + b"\n"
                    if oid in bodies else (oid + " missing\n").encode("utf-8"))
                   for oid in requested]
        raw = b"".join(records)
        if variant == "batch-empty":
            return b""
        if variant == "batch-missing-second":
            return records[0]
        if variant == "batch-no-header-newline":
            return records[0] + metadata(second).rstrip(b"\n")
        if variant == "batch-short-body":
            return records[0] + metadata(second) + b"x"
        if variant == "batch-no-delimiter":
            return raw[:-1]
        if variant == "batch-wrong-delimiter":
            return raw[:-1] + b"x"
        if variant == "batch-extra":
            return raw + metadata(extra) + bodies[extra] + b"\n"
        if variant == "batch-duplicate":
            return records[0] * 2
        if variant == "batch-wrong-type":
            return records[0] + metadata(second, kind="tree") + bodies[second] + b"\n"
        if variant == "batch-size-mismatch":
            return records[0] + metadata(second, size=len(bodies[second]) - 1) + bodies[second] + b"\n"
        if variant == "batch-nonnumeric-size":
            return records[0] + metadata(second, size="invalid") + bodies[second] + b"\n"
        if variant == "batch-negative-size":
            return records[0] + metadata(second, size=-1) + bodies[second] + b"\n"
        return raw

    responses = {
        ("git", "for-each-ref", "--format=%(refname)"): "",
        ("git", "rev-list", "--all"): "",
        ("git", "log", "--all", "--format=%ae%n%ce"): "",
        ("git", "log", "--all", "--format=%s%n%b"): "",
        ("git", "log", "--format=%T", "--all"): "",
        ("git", "rev-parse", "--revs-only", "--all"): "",
        ("git", "rev-list", "--objects", "--no-object-names", "--all"): first + "\n" + second + "\n",
    }
    return {"token": token, "objects": [first, second], "responses": responses,
            "metadata": check, "batch": batch}


def make_reference_batch_fixture(variant):
    """Two refs may legitimately peel to the same tree object."""
    refs = ["4" * 40, "5" * 40]
    tree = "6" * 40
    row = ("%s tree 0\n" % tree).encode("ascii")
    targets = row * 2
    if variant == "missing":
        targets = row
    elif variant == "extra":
        targets += row
    elif variant == "bad-oid":
        targets = row + b"not-an-object tree 0\n"
    elif variant == "bad-type":
        targets = row + (tree + " unsupported 0\n").encode("ascii")
    responses = {
        ("git", "log", "--format=%T", "--all"): "",
        ("git", "rev-parse", "--revs-only", "--all"): "\n".join(refs) + "\n",
        ("git", "ls-tree", "-r", "-t", "-z", "--full-tree", tree): "",
        ("git", "ls-tree", "-r", "-t", "-z", "--full-tree", "not-an-object"): "",
        ("git", "rev-list", "--objects", "--no-object-names", "--all"): "",
    }
    return {"refs": refs, "targets": targets, "responses": responses}


def ssh_alias_cases():
    """Generate only synthetic static host and plausible-chain attestations."""
    safe = "Host synthetic-alias\n HostName github.com\n User git\n"
    return [
        {"id": name, "host": host, "configs": configs, "chains": chains, "allowed": allowed}
        for name, host, configs, chains, allowed in [
            ("canonical-absent", "github.com", [None, None], [[0, 1]], True),
            ("alias-explicit", "synthetic-alias", [safe, None], [[0, 1]], True),
            ("alias-system", "synthetic-alias", [None, safe], [[0, 1]], True),
            ("alias-pattern-uppercase", "synthetic-alias",
             [safe.replace("Host synthetic-alias", "Host SYNTHETIC-ALIAS"), None], [[0, 1]], False),
            ("alias-pattern-escape", "synthetic-alias",
             [safe.replace("Host synthetic-alias", "Host synthetic\\-alias"), None], [[0, 1]], False),
            ("alias-uppercase-negation", "synthetic-alias",
             [safe.replace("Host synthetic-alias", "Host * !SYNTHETIC-ALIAS"), None], [[0, 1]], True),
            ("alias-single-quoted-pattern", "synthetic-alias",
             [safe.replace("Host synthetic-alias", "Host 'synthetic-alias'"), None], [[0, 1]], True),
            ("alias-double-quoted-pattern", "synthetic-alias",
             [safe.replace("Host synthetic-alias", 'Host "synthetic-alias"'), None], [[0, 1]], True),
            ("alias-uppercase-user", "synthetic-alias",
             [safe.replace("User git", "User GIT"), None], [[0, 1]], False),
            ("alias-crlf", "synthetic-alias", [safe.replace("\n", "\r\n"), None], [[0, 1]], True),
            *[
                ("alias-nonlf-" + suffix, "synthetic-alias",
                 ["Host synthetic-alias" + separator + " HostName github.com\n", None], [[0, 1]], False)
                for suffix, separator in [
                    ("vertical-tab", "\v"), ("form-feed", "\f"), ("unicode-line", "\u2028"),
                    ("unicode-next-line", "\u0085"), ("carriage-return", "\r"),
                ]
            ],
            ("alias-split-chain", "synthetic-alias",
             ["Host synthetic-alias\n HostName github.com\n", "Host synthetic-alias\n User git\n"], [[0, 1]], True),
            ("alias-wildcard", "synthetic-alias", [safe.replace("synthetic-alias", "synthetic-*"), None], [[0, 1]], True),
            ("alias-missing-hostname", "synthetic-alias", ["Host synthetic-alias\n User git\n", None], [[0, 1]], False),
            ("alias-url-supplies-user", "synthetic-alias", ["Host synthetic-alias\n HostName github.com\n", None], [[0, 1]], True),
            ("alias-absent", "synthetic-alias", [None, None], [[0, 1]], False),
            ("alias-other-host", "synthetic-alias", [safe.replace("github.com", "example.com"), None], [[0, 1]], False),
            ("alias-other-user", "synthetic-alias", [safe.replace("User git", "User other"), None], [[0, 1]], False),
            ("alias-port", "synthetic-alias", [safe + " Port 443\n", None], [[0, 1]], False),
            ("alias-proxy", "synthetic-alias", [safe + " ProxyCommand synthetic-never-execute\n", None], [[0, 1]], False),
            ("alias-include", "synthetic-alias", [safe + "Include synthetic-no-read\n", None], [[0, 1]], False),
            ("alias-match", "synthetic-alias", [safe + 'Match exec "synthetic-never-execute"\n', None], [[0, 1]], False),
            ("alias-untrusted", "synthetic-alias", [safe + " StrictHostKeyChecking no\n", None], [[0, 1]], False),
            ("alias-trust-file", "synthetic-alias", [safe + " UserKnownHostsFile synthetic-no-read\n", None], [[0, 1]], False),
            ("alias-negated", "synthetic-alias", [safe.replace("Host synthetic-alias", "Host * !synthetic-alias"), None], [[0, 1]], False),
            ("alias-override-later", "synthetic-alias", [safe + "Host *\n HostName example.com\n", None], [[0, 1]], False),
            ("alias-only-unused-config", "synthetic-alias", [None, None, safe], [[0, 1]], False),
            ("alias-only-canonical-host-block", "synthetic-alias", [safe.replace("Host synthetic-alias", "Host github.com"), None], [[0, 1]], False),
            ("alias-one-plausible-home-missing", "synthetic-alias", [safe, None, None], [[0, 2], [1, 2]], False),
            ("alias-all-plausible-homes", "synthetic-alias", [safe, safe, None], [[0, 2], [1, 2]], True),
            ("alias-system-covers-missing-home", "synthetic-alias", [safe, None, safe], [[0, 2], [1, 2]], True),
            ("alias-selected-system-hostile", "synthetic-alias", [safe, safe.replace("github.com", "example.com")], [[0, 1]], False),
            ("alias-nonselected-system-hostile", "synthetic-alias", [safe, None, safe.replace("github.com", "example.com")], [[0, 1]], False),
            ("alias-no-chain-proof", "synthetic-alias", [safe, None], None, False),
            ("alias-unrelated-hostile", "synthetic-alias",
             [safe + "Host unrelated-host\n HostName example.com\n", None], [[0, 1]], True),
            ("alias-canonical-together", "synthetic-alias",
             [safe + "Host github.com\n HostName github.com\n User git\n", None], [[0, 1]], True),
        ]
    ]


def write_ssh_alias_case(root, case):
    from pathlib import Path
    root = Path(root)
    paths = [root / ("synthetic-config-" + str(index)) for index in range(len(case["configs"]))]
    root.mkdir(parents=True, exist_ok=True)
    for path, content in zip(paths, case["configs"]):
        if content is not None:
            path.write_text(content, encoding="utf-8")
    chains = None if case["chains"] is None else [[str(paths[index]) for index in chain] for chain in case["chains"]]
    return [str(path) for path in paths], chains


def ssh_alias_route_cases():
    """Every expected host remains distinct even when repository identities coincide."""
    repository = "example-owner/demo-config"
    canonical = "git@github.com:" + repository + ".git"
    first = "git@synthetic-first:" + repository + ".git"
    second = "ssh://git@synthetic-second/" + repository + ".git"
    return [
        {"id": name, "fetch": fetch, "push": push, "blocked_hosts": blocked,
         "visibility": visibility, "hosts": hosts, "allowed": allowed}
        for name, fetch, push, blocked, visibility, hosts, allowed in [
            ("alias-private", [first], [first], [], "PRIVATE", ["synthetic-first"], True),
            ("aliases-private", [first], [second], [], "PRIVATE", ["synthetic-first", "synthetic-second"], True),
            ("canonical-alias-private", [canonical], [first], [], "PRIVATE", ["github.com", "synthetic-first"], True),
            ("alias-canonical-private", [first], [canonical], [], "PRIVATE", ["synthetic-first", "github.com"], True),
            ("second-host-hostile", [first], [second], ["synthetic-second"], "PRIVATE", ["synthetic-first", "synthetic-second"], False),
            ("hostile-before-safe", [second], [first], ["synthetic-second"], "PRIVATE", ["synthetic-second", "synthetic-first"], False),
            ("multiple-fetch-urls", [first, second], [canonical], [], "PRIVATE",
             ["synthetic-first", "synthetic-second", "github.com"], True),
            ("canonical-then-hostile-alias", [canonical], [first], ["synthetic-first"], "PRIVATE", ["github.com", "synthetic-first"], False),
            ("alias-public", [first], [second], [], "PUBLIC", ["synthetic-first", "synthetic-second"], False),
            ("alias-unknown", [first], [second], [], "UNKNOWN", ["synthetic-first", "synthetic-second"], False),
            ("explicit-port", [first], [second.replace("synthetic-second/", "synthetic-second:22/")], [],
             "PRIVATE", ["synthetic-first"], False),
            ("password", [first], [second.replace("git@", "git:synthetic@")], [], "PRIVATE", ["synthetic-first"], False),
            ("query", [first], [second + "?synthetic"], [], "PRIVATE", ["synthetic-first"], False),
            ("unknown-transport", [first], ["file:///synthetic/no-repository"], [], "PRIVATE", ["synthetic-first"], False),
        ]
    ]


def write_windows_git_tls_fixture(root, launcher="cmd/git.exe"):
    """Generate a package-shaped Git installation; none of its files are executed."""
    root = Path(root)
    installation = root / "synthetic-git"
    executable = installation / launcher
    bundle = installation / "mingw64/etc/ssl/certs/ca-bundle.crt"
    custom = root / "custom-ca.pem"
    for path in (executable, bundle, custom):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic metadata fixture; never execute or use as TLS trust\n", encoding="utf-8")
    config = [("http.sslbackend", "openssl"), ("http.sslcainfo", str(bundle))]
    return {"executable": executable, "bundle": bundle, "custom": custom, "config": config}


def windows_git_tls_cases(fixture):
    """Pair ordinary package defaults with hostile or unproved transport settings."""
    defaults = fixture["config"]
    return [
        {"id": name, "config": config, "env": env, "allowed": allowed}
        for name, config, env, allowed in [
            ("openssl-package-defaults", defaults, {}, True),
            ("openssl-default-trust", [("http.sslbackend", "openssl")], {}, True),
            ("schannel-default-trust", [("http.sslbackend", "schannel")], {}, True),
            ("package-bundle-url-scope", [("http.sslbackend", "openssl"),
                ("http.https://github.com/.sslcainfo", str(fixture["bundle"]))], {}, True),
            ("unknown-backend", [("http.sslbackend", "synthetic-backend")], {}, False),
            ("custom-trust", [("http.sslbackend", "openssl"),
                ("http.sslcainfo", str(fixture["custom"]))], {}, False),
            ("relative-trust", [("http.sslcainfo", "ca-bundle.crt")], {}, False),
            ("disabled-verification", defaults + [("http.sslverify", "false")], {}, False),
            ("proxy", defaults + [("http.proxy", "http://proxy.example.invalid:8080")], {}, False),
            ("resolver", defaults + [("http.curloptresolve", "github.com:443:192.0.2.10")], {}, False),
            ("revocation-disabled", [("http.sslbackend", "schannel"),
                ("http.schannelcheckrevoke", "false")], {}, False),
            ("schannel-custom-trust", [("http.sslbackend", "schannel"),
                ("http.schannelusesslcainfo", "true")], {}, False),
            ("environment-trust", defaults, {"GIT_SSL_CAINFO": str(fixture["custom"])}, False),
            ("environment-backend", defaults, {"CURL_SSL_BACKEND": "synthetic-backend"}, False),
            ("custom-then-default", [("http.sslcainfo", str(fixture["custom"]))] + defaults, {}, False),
        ]
    ]


def make_native_git_tls_companion(root):
    """Retain installed Git configuration without inheriting a hook's repository."""
    import os
    import subprocess
    root = Path(root)
    root.mkdir()
    selectors = {
        "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_IMPLICIT_WORK_TREE",
        "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_GRAFT_FILE", "GIT_SHALLOW_FILE", "GIT_PREFIX", "GIT_INTERNAL_SUPER_PREFIX",
        "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_CONFIG",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() not in selectors}
    commands = [["init", "-q"], ["remote", "add", "origin", "https://github.com/example-owner/demo-config.git"]]
    for args in commands:
        subprocess.run(["git", "-C", str(root), *args], env=environment,
                       capture_output=True, text=True, check=True, **_no_window())
    return {"root": root, "visibility": {"example-owner/demo-config": "PRIVATE"},
            "env": environment,
            "disabled_verification": ["config", "http.sslVerify", "false"]}


def ssh_parser_boundary_cases():
    """Generate control-byte configurations that native C parsers can truncate."""
    return [
        {"id": "canonical-host-nul", "host": "github.com",
         "content": "Host github.com\x00ignored\n HostName elsewhere.example\n"},
        {"id": "alias-proxy-after-nul", "host": "synthetic-alias",
         "content": "Host synthetic-alias\n HostName github.com\nHost synthetic-alias\x00ignored\n ProxyCommand synthetic-never-execute\n"},
        {"id": "alias-comment-nul", "host": "synthetic-alias",
         "content": "Host synthetic-alias\n HostName github.com\n# synthetic\x00comment\n"},
    ]


def write_git_ssh_selection_case(root, location, launcher="cmd/git.exe"):
    """Place a generated alias in either possible client's system configuration."""
    layout = make_ssh_layout(root, bundled_client=True)
    layout["git-executable"] = layout["git-installation"] / launcher
    layout["git-executable"].parent.mkdir(parents=True, exist_ok=True)
    layout["git-executable"].write_text("synthetic launcher metadata; never execute\n", encoding="utf-8")
    safe = next(case for case in ssh_alias_cases() if case["id"] == "alias-explicit")["configs"][0]
    paths = {"system": layout["program-data"] / "ssh/ssh_config",
             "bundled": layout["git-installation"] / "etc/ssh/ssh_config"}
    for name, path in paths.items():
        if location in {name, "both"}:
            path.write_text(safe, encoding="utf-8")
    return layout


def make_native_git_tls_selector_case(root):
    """Generate a disposable hook caller whose Git selectors must not leak into setup."""
    root = Path(root)
    root.mkdir()
    configuration = write_git_context_configuration(root)
    decoy = GitContextFixture(root / "decoy", configuration)
    admin = decoy.git("rev-parse", "--absolute-git-dir")
    return {"decoy": decoy, "destination": root / "companion",
            "selectors": {"GIT_DIR": admin, "GIT_WORK_TREE": str(decoy.root),
                          "GIT_COMMON_DIR": admin, "GIT_INDEX_FILE": str(Path(admin) / "index")}}


def ssh_execution_environment_cases():
    """Generate Git tool-search overrides that can select an unproved SSH client."""
    return [{"env": {key: "synthetic-tools"} if key else {}, "allowed": not key,
             "url": "git@github.com:example-owner/demo-config.git"}
            for key in (None, "GIT_EXEC_PATH", "git_exec_path", "GiT_ExEc_PaTh")]


def make_native_hook_exec_path_fixture(root, source, transport, refreshed):
    """Run PRIVATE admission from a real Git hook using only synthetic repositories."""
    import shlex
    import sys

    root = Path(root)
    configuration = write_git_context_configuration(root)
    companion = GitContextFixture(root / "companion", configuration)
    invoker = GitContextFixture(root / "invoker", configuration)
    url = ("git@github.com:example-owner/synthetic-private.git" if transport == "ssh"
           else "https://github.com/example-owner/synthetic-private.git")
    companion.git("remote", "add", "origin", url)
    receipt = write_visibility(root / "visibility.json",
                               {"example-owner/synthetic-private": "PRIVATE"}, refreshed)
    report = root / "hook-report.json"
    ssh_config = root / "synthetic-ssh-config"
    ssh_config.write_text("", encoding="utf-8")
    script = root / "hook-probe.py"
    script.write_text('''import json, os, pathlib, sys
tools, companion, receipt, report, ssh_config = sys.argv[1:]
sys.path.insert(0, tools)
import data_boundary as boundary
# The real static SSH parser reads this empty fixture, never a user's SSH profile.
boundary._ssh_config_paths = lambda: [ssh_config]
before = dict(os.environ)
inherited = {key: value for key, value in before.items() if key.upper() == 'GIT_EXEC_PATH'}
assert len(inherited) == 1, 'Git did not supply a unique helper path to its hook'
try:
    proof = boundary.prove_private_companion(companion, receipt)
    result = {'allowed': True, 'repositories': list(proof.repositories)}
except boundary.GitError as error:
    result = {'allowed': False, 'error': str(error)}
result.update(exec_path_present=True, environment_preserved=before == dict(os.environ))
pathlib.Path(report).write_text(json.dumps(result), encoding='utf-8')
''', encoding="utf-8")
    hooks = root / "probe-hooks"
    hooks.mkdir()
    hook = hooks / "pre-commit"
    arguments = [sys.executable, "-I", script, Path(source) / "tools",
                 companion.root, receipt, report, ssh_config]
    hook.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(str(arg).replace("\\", "/"))
                                                 for arg in arguments) + "\n", encoding="utf-8")
    hook.chmod(0o755)
    invoker.git("config", "core.hooksPath", str(hooks))
    # Isolate transport policy from the invoking machine's proxy and trust settings.
    invoker.env = {key: value for key, value in invoker.env.items()
                   if key.upper().startswith("GIT_") or key.upper() in {
                       "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC", "LANG"}}
    custom = root / "custom-helpers"
    custom.mkdir()
    return {"invoker": invoker, "companion": companion, "report": report, "custom": custom}


def native_hook_transport_overrides():
    """Other transport overrides stay unproved even alongside Git's native helper path."""
    return [("ssh", "env", key, "synthetic-ssh")
            for key in ("GIT_SSH", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT")] + [
        ("ssh", "config", "core.sshCommand", "synthetic-ssh"),
        ("ssh", "config", "ssh.variant", "synthetic-ssh"),
        ("https", "env", "GIT_SSL_NO_VERIFY", "1"),
        ("https", "env", "CURL_CA_BUNDLE", "synthetic-ca.pem"),
        ("https", "config", "http.sslVerify", "false"),
    ]


def git_ssh_launcher_cases():
    """Generate the supported Git for Windows launcher locations."""
    return ["cmd/git.exe", "bin/git.exe", "mingw64/bin/git.exe", "mingw32/bin/git.exe",
            "mingw64/libexec/git-core/git.exe", "mingw32/libexec/git-core/git.exe"]


def invalid_windows_git_launchers(root):
    """Unrecognized package layouts cannot select a bundled client or trust bundle."""
    return [str(Path(root) / name) for name in (
        "libexec/git-core/git.exe", "mingw16/libexec/git-core/git.exe",
        "mingw64/libexec/other/git.exe", "mingw64/libexec/git-core/git.cmd",
        "bin/../git.exe")] + ["cmd/git.exe"]


def make_sized_history_fixture(repo, size):
    """Generate a reachable text record with a token at a specified byte size."""
    token = synthetic_token("sized-history")
    assert size >= len(token) + 2
    repo.write("sized-history.md", "s" * (size - len(token) - 2) + "\n" + token + "\n")
    repo.commit("synthetic sized history")
    return token


def owner_collision_cases():
    """Generate attributable foreign references and ambiguous own-name collisions."""
    cases = []
    own_owner, public_name = "example-owner-a", "public-research-tool"
    for suffix in ("", "-config", "-data", "-private", "-secrets"):
        name = public_name + suffix
        for foreign_owner in ("example-owner-b", "example-owner-b2"):
            own, foreign = own_owner + "/" + name, foreign_owner + "/" + name
            references = [
                ("own-bare", name, False), ("own-qualified", own, False),
                ("own-https", "https://github.com/" + own + ".git", False),
                ("own-scp", "git@github.com:" + own + ".git", False),
                ("foreign-qualified", foreign, True),
                ("foreign-https", "https://github.com/" + foreign + ".git", True),
                ("foreign-scp", "git@github.com:" + foreign + ".git", True),
                ("foreign-ssh", "ssh://git@github.com/" + foreign + ".git", True),
                ("foreign-upper", foreign.upper(), True),
                ("foreign-sentence", foreign + ".", True),
                ("longer-owner", "prefix-" + foreign, False),
                ("longer-repo", foreign + "-archive", False),
                ("dotted-repo", foreign + ".archive", False),
                ("longer-git-repo", foreign + ".git-archive", False),
            ]
            for index, (label, text, blocked) in enumerate(references):
                visibility = {own_owner + "/" + public_name: "PUBLIC", foreign: "PRIVATE",
                              "example-owner-c/unrelated-hidden-config": "PRIVATE"}
                if index % 2:
                    visibility[own] = "PRIVATE"
                if index % 3 == 0:
                    visibility = {key.upper(): value for key, value in reversed(list(visibility.items()))}
                cases.append({"id": suffix.lstrip("-") + "-" + foreign_owner + "-" + label,
                              "self_key": own_owner + "/" + public_name, "foreign": foreign,
                              "visibility": visibility, "text": text, "blocked": blocked})
    return cases


def owner_collision_policy_cases():
    """Keep each foreign owner's own witness, freshness and unrelated-name severity."""
    current = "example-owner-a/public-research-tool"
    companion = "public-research-tool-config"
    foreign = "example-owner-b/" + companion
    base = {current: "PUBLIC", "example-owner-a/" + companion: "PRIVATE", foreign: "PRIVATE",
            "example-owner-c/unrelated-hidden-config": "PRIVATE"}
    return [
        {"id": label, "self_key": current, "foreign": foreign, "text": text, "visibility": visibility,
         "stamp": stamp, "severity": severity, "secret": secret}
        for label, text, visibility, stamp, severity, secret in [
            ("foreign-linkage", foreign, base, None, "BLOCK", False),
            ("foreign-own-public-parent", foreign, dict(base, **{"example-owner-b/public-research-tool": "PUBLIC"}), None, "WARN", False),
            ("foreign-stale-parent", foreign, dict(base, **{"example-owner-b/public-research-tool": "PUBLIC"}), "2000-01-01T00:00:00Z", "BLOCK", False),
            ("unrelated-bare", "unrelated-hidden-config", base, None, "BLOCK", False),
            ("independent-secret", companion, base, None, "BLOCK", True),
        ]
    ]


def make_private_api_fixture(root, refreshed):
    """Generate a versioned companion and query targets for the supported proof API."""
    fixture = make_companion_context_fixture(root, refreshed)
    private = fixture["repos"]["private"]
    (private.root / ".gitignore").write_text("ignored-output/\n", encoding="utf-8")
    fixture.update(ignored="ignored-output/record.json", unignored="archive/next.json",
                   alternate_route="https://github.com/example-owner/synthetic-private",
                   sentinel=synthetic_token("private-api-environment"))
    return fixture


def private_api_forbidden_queries():
    """Only the documented local metadata reads belong to the public helper."""
    return [("status",), ("push",), ("config", "http.sslVerify", "false"),
            ("check-ignore", "--no-index", "-q", "--", "../outside.json"),
            ("check-ignore", "--no-index", "-q", "--", "..\\outside.json"),
            ("check-ignore", "--no-index", "-q", "--", "/outside.json"),
            ("check-ignore", "--no-index", "-q", "--", "C:\\outside.json"),
            ("check-ignore", "--no-index", "-q", "--", "nul\x00name"),
            ("check-ignore", "--no-index", "-q", "--", "archive/./record.json"),
            *(("check-ignore", "--no-index", "-q", "--", path)
              for path in ("./", "../", "archive//", "archive/../", "archive//nested/",
                           "archive/./", "/archive/", "C:/archive/", "archive/\0/"))]


def private_api_directory_queries():
    """Generate absent directory probes whose spelling changes native ignore semantics."""
    return [("ignored-output", 1), ("ignored-output/", 0),
            ("ignored-output/nested/", 0), ("pending/", 1), ("--synthetic/", 1)]


def private_api_remote_selection_cases():
    """Generate configured, local, absent, and case-distinct remote selectors."""
    return [(key, value, allowed)
            for key in ("remote.pushDefault", "branch.main.pushRemote", "branch.main.remote")
            for value, allowed in (("origin", True), ("Origin", False), (".", False),
                                   ("missing-remote", False), ("", False),
                                   ("https://github.com/example-owner/synthetic-private", False))]


def make_publication_fixture(root, source, state="PRIVATE", defect=None, refreshed=None):
    """Generate an isolated private/public hook repository and synthetic linkage evidence."""
    import shutil
    from pii_guard import _utcnow

    root, source = Path(root), Path(source)
    configuration = write_git_context_configuration(root)
    repo = GitContextFixture(root / "repository", configuration)
    home = root / "home"
    (home / ".pii-guard").mkdir(parents=True)
    repo.env = {key: value for key, value in repo.env.items() if not key.startswith("GITHUB_")}
    repo.env.update(HOME=str(home), USERPROFILE=str(home), PII_DENYLIST=str(home / "absent-policy.json"))
    url = "https://github.com/example-owner/synthetic-tool.git"
    repo.git("remote", "add", "origin", url)
    sibling = "example-owner/hidden-sibling-config"
    (repo.root / "notes.md").write_text("Synthetic sibling: " + sibling + "\n", encoding="utf-8")
    manifest = {"data": [], "fixture": [], "_audited": "synthetic publication fixture"}
    if defect in ("data", "sealed"):
        manifest["data" if defect == "data" else "data_sealed"] = ["private-store/"]
        write_record(repo.root, "private-store/record.json")
    if defect == "declaration":
        manifest["data"] = ["../outside/"]
    if defect == "fixture":
        manifest["fixture"] = ["record.json"]
        write_record(repo.root, "record.json")
    if defect != "missing-manifest":
        (repo.root / ".dataclass.json").write_text(json.dumps(manifest), encoding="utf-8")
    receipt = home / ".pii-guard/visibility.json"
    write_visibility(receipt, {"example-owner/synthetic-tool": state, sibling: "PRIVATE",
                              "example-owner/public-target": "PUBLIC"}, refreshed or _utcnow())
    (home / ".pii-guard/identities.conf").write_text(
        "example-owner|Fixture|12345678+Fixture@users.noreply.github.com\n", encoding="utf-8")
    repo.git("add", "--all")
    repo.git("commit", "-qm", "synthetic publication baseline")
    kit = root / "kit"
    for relative in ("tools/pii_guard.py", "tools/data_boundary.py", "tools/publication_guard.py",
                     "hooks/pre-commit", "hooks/pre-push"):
        target = kit / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, target)
        if relative.startswith("hooks/"):
            target.chmod(0o755)
    repo.git("config", "core.hooksPath", str(kit / "hooks"))
    return {"repo": repo, "kit": kit, "receipt": receipt, "url": url, "sibling": sibling,
            "token": synthetic_token("publication-api"), "unproved_exec": str(root / "unproved-helpers"),
            "public_url": "https://github.com/example-owner/public-target.git"}


def publication_metadata_cases():
    """Generate authoritative metadata and deliberately inconsistent counterparts."""
    repository = "example-owner/synthetic-tool"
    return [(repository, {"full_name": name, "private": private, "visibility": visibility}, expected)
            for name, private, visibility, expected in (
                (repository, True, "private", "PRIVATE"),
                (repository.upper(), True, "private", "PRIVATE"),
                (repository, False, "public", "PUBLIC"),
                (repository, True, "public", "UNKNOWN"),
                (repository, "true", "private", "UNKNOWN"),
                ("example-owner/different-tool", True, "private", None))]


def publication_nul_header():
    return ("http.extraheader", "Authorization: Basic c3ludGhldGlj\0")


def make_hook_helper_path_fixture(root, alias_kind):
    """Generate executable and helper-path topology without reading an installed binary."""
    import os

    root = Path(root)
    installation = root / "synthetic-git"
    (installation / "bin").mkdir(parents=True)
    executable = installation / "bin" / ("git.exe" if os.name == "nt" else "git")
    executable.write_text("synthetic executable identity; not executed\n", encoding="utf-8")
    default = installation / "libexec/git-core"
    default.mkdir(parents=True)
    actual = default
    if alias_kind == "helper":
        actual = make_install_alias(root / "helper-alias", default)
    elif alias_kind == "default-parent":
        default = make_install_alias(root / "installation-alias", installation) / "libexec/git-core"
        actual = default
    elif alias_kind == "executable-parent":
        executable = make_install_alias(root / "executable-alias", installation) / "bin" / executable.name
    elif alias_kind != "canonical":
        raise ValueError("Unknown synthetic helper topology")
    return {"executable": executable, "default": default, "actual": actual}


def publication_metadata_environment_cases():
    """Ambient trust and proxy controls are unproved before any metadata credential is sent."""
    return [{key: "synthetic-override"} for key in (
        "SSL_CERT_FILE", "ssl_cert_dir", "HTTPS_PROXY", "http_proxy", "All_Proxy",
        "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSLKEYLOGFILE")]


def publication_invalid_metadata_targets():
    return ["../synthetic-tool", "example-owner/..", "example-owner/tool?synthetic",
            "example-owner/tool#synthetic", "example-owner/tool/extra", "example-owner@host/tool"]


def publication_changed_response_urls():
    suffix = "/repos/example-owner/synthetic-tool"
    return ["http://api.github.com" + suffix, "https://api.github.com.example.invalid" + suffix,
            "https://api.github.com" + suffix + "/different"]


def make_fleet_visibility_fixture(root, all_routes=False):
    """Generate a fresh Actions home and all physical/effective publication routes."""
    root = Path(root)
    configuration = write_git_context_configuration(root)
    repo = GitContextFixture(root / "consumer", configuration)
    home = root / "home"
    home.mkdir()
    repo.env = {key: value for key, value in repo.env.items()
                if key in {"PATH", "LANG", "LC_ALL"} or key.startswith("GIT_")}
    repo.env.update(HOME=str(home), USERPROFILE=str(home), GITHUB_ACTIONS="true",
                    PII_DENYLIST=str(home / "absent-policy.json"))
    names = ["example-owner/synthetic-consumer"]
    repo.git("remote", "add", "origin", "https://github.com/" + names[0] + ".git")
    if all_routes:
        names += ["example-owner/synthetic-rewritten", "example-owner/synthetic-push-a",
                  "example-owner/synthetic-push-b"]
        for name in names[2:]:
            repo.git("config", "--add", "remote.origin.pushurl", "https://github.com/" + name + ".git")
        repo.env.update(GIT_CONFIG_COUNT="1",
            GIT_CONFIG_KEY_0="url.https://github.com/" + names[1] + ".insteadOf",
            GIT_CONFIG_VALUE_0="https://github.com/" + names[0])
    return {"repo": repo, "home": home, "receipt": home / ".pii-guard/visibility.json",
            "names": names, "token": synthetic_token("fleet-visibility"),
            "stale": {names[0]: "PUBLIC", "_refreshed": "2000-01-01T00:00:00Z"}}


def fleet_unknown_route():
    return "https://example.invalid/synthetic-consumer.git"


def fleet_visibility_payload(name, state):
    return {"full_name": name, "private": state == "PRIVATE", "visibility": state.lower()}


def make_fleet_receipt_alias(fixture, kind):
    """Create only synthetic aliases and an in-worktree home for denial controls."""
    import os

    home, receipt = fixture["home"], fixture["receipt"]
    receipt.parent.mkdir()
    receipt.write_text(json.dumps(fixture["stale"]), encoding="utf-8")
    if kind == "worktree":
        return fixture["repo"].root
    if kind == "home":
        alias = home.parent / "home-alias"
        alias.symlink_to(home, target_is_directory=True)
        return alias
    if kind == "directory":
        target = home / "receipt-directory"
        receipt.parent.rename(target)
        receipt.parent.symlink_to(target, target_is_directory=True)
    elif kind == "file":
        target = home / "original-receipt.json"
        receipt.rename(target)
        receipt.symlink_to(target)
    elif kind == "hardlink":
        os.link(receipt, home / "receipt-hardlink.json")
    else:
        raise ValueError("Unknown synthetic receipt topology")
    return home


def package_api_cases():
    """Generate synthetic package inputs; no operator data or ambient files are read."""
    shapes = [
        ("AKIA" + "A" * 16, "aws_access_key"),
        ("ASIA" + "A" * 16, "aws_access_key"),
        ("AGPA" + "A" * 16, "aws_access_key"),
        ("AIDA" + "A" * 16, "aws_access_key"),
        ("glpat-" + "A" * 24, "gitlab_token"),
        ("npm_" + "A" * 36, "npm_token"),
        ("sk-ant-" + "a" * 24, "anthropic_key"),
        ("sk-proj-" + "a" * 24, "openai_key"),
        ("sk-" + "a" * 12, "openai_key"),
        ("ghp_" + "A" * 12, "github_token"),
        ("ghs_" + "a._-" * 9, "github_token"),
        ("github_pat_" + "A" * 12, "github_pat_fine"),
        ("xoxb-" + "A" * 10, "slack_token"),
        ("AIza" + "A" * 30, "google_api_key"),
        ("sk_" + "test_" + "a" * 16, "stripe_key"),
        ("rk_" + "live_" + "a" * 16, "stripe_key"),
        ("mfa." + "A" * 20, "discord_bot_token"),
        ("A" * 24 + "." + "A" * 6 + "." + "A" * 27, "discord_bot_token"),
        ("eyJ" + "A" * 8 + "." + "A" * 8 + "." + "A" * 8, "jwt"),
        ("Bearer " + "short", "bearer_token"),
        ("https://discord.com/api/webhooks/123/" + "A" * 24, "discord_webhook"),
        ("https://ptb.discordapp.com/api/webhooks/123/" + "A" * 24, "discord_webhook"),
        ("https://hooks.slack.com/services/" + "A/B/C", "slack_webhook"),
        ("https://open.feishu.cn/open-apis/bot/v2/hook/" + "a" * 24, "feishu_webhook"),
        ("https://user1:synthetic-password@example.com/", "credential_uri"),
        ("postgresql://user1:p@example.com/db", "db_connection_string"),
        ("mongodb+srv://user1:p@example.com/db", "db_connection_string"),
        ("https://example.com/?token=short", "query_credential"),
        ("run --api-key short", "cli_credential"),
        ("run --password='synthetic password'", "cli_credential"),
        ('{"password": "synthetic-password"}', "credential_assignment"),
        ("refresh_token = synthetic-value", "credential_assignment"),
        ("private_key = synthetic-value", "credential_assignment"),
        ("access-key: synthetic-value", "credential_assignment"),
    ]
    return {
        "shapes": shapes,
        "safe": "synthetic public sentence",
        "large_prefix": "synthetic public sentence. " * 42000,
        "benign": ["synthetic public sentence", 'password = "${PASSWORD}"',
                   'token = "redacted"', "sk-your-synthetic-api-key"],
        "partial_templates": ['password = "${PASSWORD}suffix"',
                              'password = "redacted-but-a-value"'],
        "strict": ["SYNTHETIC_CANARY", "sk-your-synthetic-api-key",
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"],
        "invalid_budgets": [{"max_text_chars": value} for value in (0, -1, True, 2.5, 16 * 1024 * 1024 + 1)]
            + [{"seconds": value} for value in (0, -1, True, 31, float("nan"), float("inf"))],
        "cli": [(b"synthetic public sentence", 0, "clean"),
                (b"Bearer synthetic", 1, "findings"), (bytes([255]), 2, "scan_failed")],
        "payloads": [b"synthetic first content", b"synthetic replacement content"],
        "concurrent_payloads": [bytes([65 + n]) * 10000 for n in range(4)],
        "unsafe_paths": ["../escape", "stream:private", "NUL", "CON.txt", "trailing.", "trailing "],
    }


def make_storage_contract_fixture(root, refreshed):
    """Generate a source contract and a versioned private companion for admission tests."""
    root = Path(root)
    configuration = write_git_context_configuration(root)
    source = GitContextFixture(root / "source", configuration)
    companion = GitContextFixture(root / "companion", configuration)
    companion.git("remote", "add", "origin",
                  "https://github.com/example-owner/synthetic-private.git")
    (companion.root / ".gitignore").write_text(
        "cache/*.tmp\nignored-directory/\n", encoding="utf-8")
    companion.git("add", ".gitignore")
    companion.git("commit", "-qm", "synthetic storage companion")
    artifacts = []
    for identifier, pattern, retention in (
            ("status", "reports/status.json", "core"),
            ("cache", "cache/*.tmp", "rebuildable"),
            ("runs", "data/runs/*/**", "rebuildable"),
            ("ignored-directory", "ignored-directory/**", "rebuildable")):
        artifacts.append({
            "artifact_id": identifier, "path_pattern": pattern,
            "purpose": "Synthetic admission regression",
            "schema": "Synthetic byte sequence", "producer": "synthetic-test",
            "consumer_or_final_deliverable": "Synthetic result assertion",
            "retention_rule": {"class": retention, "rule": "Until the synthetic test completes"},
            "rebuild_or_restore": "Regenerate with make_storage_contract_fixture",
        })
    contract = {"schema_version": 1, "tool": "synthetic-tool", "artifacts": artifacts}
    (source.root / "storage.contract.json").write_text(
        json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    receipt = write_visibility(root / "visibility.json", {
        "example-owner/synthetic-private": "PRIVATE",
        "example-owner/synthetic-public": "PUBLIC",
    }, refreshed)
    return {"source": source, "companion": companion, "contract": contract,
            "configuration": configuration, "receipt": receipt}


def storage_literal_path_cases():
    """Synthetic archive names distinguish literal targets from declared pattern syntax."""
    return {
        "literal_paths": [
            "data/runs/acme/archive/general [700000000000000004].html",
            "data/runs/acme/archive/open [.html",
            "data/runs/acme/archive/close ].html",
        ],
        "wildcard_paths": ["data/runs/acme/archive/*.html", "data/runs/acme/archive/?.html"],
        "pattern_cases": [
            ("data/runs/acme/archive/a.html", "data/runs/*/archive/[ab].html", True),
            ("data/runs/acme/archive/c.html", "data/runs/*/archive/[ab].html", False),
        ],
        "payload": "synthetic bracketed artifact\n",
    }


def make_storage_short_name_fixture(layout, kind):
    """Construct NTFS aliases without reading or writing a real repository's files."""
    import ctypes
    companion = layout["companion"]
    if kind == "gitfile":
        root = companion.root.parent / "linked-companion"
        companion.git("worktree", "add", "--detach", str(root))
        target = root / ".git"
    else:
        root = companion.root
        target = root / "reports" / "long-synthetic-status-filename.json"
        target.parent.mkdir()
        target.write_text("{}\n", encoding="utf-8")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_short = kernel.GetShortPathNameW
    get_short.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    get_short.restype = ctypes.c_uint32
    needed = get_short(str(target), None, 0)
    if not needed:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(needed)
    if not get_short(str(target), buffer, needed):
        raise ctypes.WinError(ctypes.get_last_error())
    alias = target.with_name(Path(buffer.value).name)
    return root, target, alias.relative_to(root).as_posix()
