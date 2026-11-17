#!/usr/bin/env python3
"""
honeytrapper.py - canary / honey-token deployment and LOTL-access detection.

Plants decoy credentials and sensitive-looking files that no legitimate user
or process should ever touch, then detects:
  1. ACCESS  - a process opens a decoy (auditd, inotify, or Windows 4663)
  2. USE     - a decoy secret shows up in auth/web/cloud logs (hunt)
and classifies the accessing binary against living-off-the-land (LOTL)
tooling (cat/base64/curl/tar/python/certutil/powershell...).

Stdlib only. Linux + Windows (rule/script generation).

  sudo ./honeytrapper.py create --home /home/alice
  sudo ./honeytrapper.py rules --install          # auditd rules
  sudo ./honeytrapper.py monitor --mode audit     # or --mode inotify
  ./honeytrapper.py hunt /var/log/auth.log cloudtrail.json
  ./honeytrapper.py rules --sigma > honeytrapper.yml
  ./honeytrapper.py rules --windows > honeytrapper.ps1

Email alerts (monitor, hunt, test-email):
  export HONEYTRAPPER_SMTP_PASSWORD='app-password'      # never pass it on the CLI
  ./honeytrapper.py monitor --email-to soc@corp.com --smtp-host smtp.corp.com \\
        --smtp-user honeytrapper@corp.com
"""
import argparse, ctypes, ctypes.util, datetime, glob, hashlib, json, os, random
import re, secrets, socket, string, struct, sys, threading, time

VERSION = "1.0"
DEFAULT_REG = ("/var/lib/honeytrapper/registry.json" if os.name != "nt" and os.geteuid() == 0
               else os.path.expanduser("~/.honeytrapper/registry.json"))

# ----------------------------------------------------------------- LOTL intel
LOTL = {
    "exfil":   "curl wget scp sftp rsync nc ncat netcat socat ftp tftp ssh rclone "
               "certutil.exe bitsadmin.exe ftp.exe",
    "encode":  "base64 base32 xxd od hexdump openssl gpg uuencode certutil.exe",
    "archive": "tar zip gzip 7z 7za bzip2 xz zstd makecab.exe compact.exe",
    "interp":  "python python2 python3 perl ruby php node lua bash sh zsh dash ksh busybox "
               "powershell.exe pwsh.exe cmd.exe wscript.exe cscript.exe mshta.exe "
               "rundll32.exe regsvr32.exe msbuild.exe installutil.exe",
    "cloud":   "aws gcloud az kubectl terraform vault",
    "read":    "cat head tail less more strings dd cp mv vi vim nano grep egrep rg awk sed "
               "findstr.exe type.exe robocopy.exe xcopy.exe esentutl.exe",
    "recon":   "find locate ls stat file tree where.exe dir.exe forfiles.exe",
}
LOTL_MAP = {b: cat for cat, bins in LOTL.items() for b in bins.split()}
SEVERITY = {"exfil": "critical", "encode": "high", "interp": "high", "cloud": "high",
            "archive": "high", "read": "medium", "recon": "medium"}
# Benign scanners that legitimately walk the filesystem - tune for your fleet.
DEFAULT_ALLOW = {"updatedb", "updatedb.mlocat", "mlocate", "clamd", "clamscan",
                 "restic", "borg", "duplicity", "rsnapshot", "tracker-miner-f", "baloo_file"}


def classify(proc):
    name = os.path.basename(proc or "").lower()
    # strip version suffixes: python3.11 -> python3, perl5.36 -> perl
    candidates = [name, re.sub(r"[\d.]+$", "", name), name + ".exe"]
    for c in candidates:
        if c in LOTL_MAP:
            cat = LOTL_MAP[c]
            return cat, SEVERITY[cat]
    return "unknown", "high"   # any unexpected reader of a decoy is still bad


# ---------------------------------------------------------------- generators
def _rand(n, alphabet=string.ascii_letters + string.digits):
    return "".join(secrets.choice(alphabet) for _ in range(n))

def _pw():
    return _rand(6, string.ascii_uppercase) + _rand(4, string.digits) + "!" + _rand(5)

def _b64block(nbytes, width=64):
    import base64
    s = base64.b64encode(secrets.token_bytes(nbytes)).decode()
    return "\n".join(s[i:i + width] for i in range(0, len(s), width))


def t_aws():
    akid = "AKIA" + _rand(16, string.ascii_uppercase + "234567")
    sec = _rand(40, string.ascii_letters + string.digits + "+/")
    body = (f"[default]\nregion = us-east-1\n\n[prod-admin]\n"
            f"aws_access_key_id = {akid}\naws_secret_access_key = {sec}\nregion = us-east-1\n")
    return ".aws/credentials.bak", body, {"aws_access_key_id": akid, "secret": sec}

def t_ssh():
    body = ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + _b64block(1650, 70) +
            "\n-----END OPENSSH PRIVATE KEY-----\n")
    return ".ssh/id_rsa_prod_backup", body, {"note": "fake key material"}

def t_env():
    user, pw = "svc_billing", _pw()
    api = "live_" + _rand(32)
    body = (f"NODE_ENV=production\nDATABASE_URL=postgres://{user}:{pw}@db-prod-01.internal:5432/billing\n"
            f"REDIS_URL=redis://:{_pw()}@cache-prod-01.internal:6379/0\n"
            f"PAYMENTS_API_KEY={api}\nJWT_SECRET={_rand(48)}\n")
    return "projects/billing-api/.env", body, {"username": user, "password": pw, "api_key": api}

def t_kube():
    tok = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ij" + _rand(180, string.ascii_letters + string.digits + "-_")
    body = ("apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://k8s-prod.internal:6443\n"
            "    insecure-skip-tls-verify: true\n  name: prod\ncontexts:\n- context:\n    cluster: prod\n"
            "    user: cluster-admin\n  name: prod-admin\ncurrent-context: prod-admin\nusers:\n"
            f"- name: cluster-admin\n  user:\n    token: {tok}\n")
    return ".kube/config.old", body, {"token": tok}

def t_gitcreds():
    tok = "ghp_" + _rand(36)
    return ".git-credentials.bak", f"https://deploy-bot:{tok}@git.internal.corp\n", \
        {"username": "deploy-bot", "token": tok}

def t_passwords():
    pw1, pw2, pw3 = _pw(), _pw(), _pw()
    body = (f"# do not share\nvpn  - jsmith-adm / {pw1}\nesxi root - {pw2}\n"
            f"backup svc (svc_backup) - {pw3}\nwifi guest - Welcome2024!\n")
    return "Documents/passwords.txt", body, {"username": "svc_backup", "password": pw3,
                                             "password_vpn": pw1, "password_esxi": pw2}

def t_keepass():
    # KeePass 2.x magic header + random body: looks real to `file`, cracks to nothing.
    data = bytes.fromhex("03d9a29a67fb4bb5") + secrets.token_bytes(random.randint(9000, 30000))
    return "Documents/Passwords.kdbx", data, {}

TEMPLATES = {"aws": t_aws, "ssh": t_ssh, "env": t_env, "kube": t_kube,
             "gitcreds": t_gitcreds, "passwords": t_passwords, "keepass": t_keepass}


# ------------------------------------------------------------------ registry
def load_reg(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"version": VERSION, "tokens": {}}

def save_reg(path, reg):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(reg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ------------------------------------------------------------------- create
def cmd_create(a):
    reg = load_reg(a.registry)
    home = os.path.abspath(os.path.expanduser(a.home))
    kinds = TEMPLATES if a.types == "all" else {k: TEMPLATES[k] for k in a.types.split(",")}
    st_home = os.stat(home)
    for kind, fn in kinds.items():
        rel, content, secrets_ = fn()
        path = os.path.join(home, *rel.split("/"))
        if os.path.exists(path):
            print(f"[skip] {path} exists - never overwriting real files"); continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as f:
            f.write(content)
        os.chmod(path, 0o600)
        # age it so it doesn't stand out in `ls -lt`
        aged = time.time() - random.randint(30, 400) * 86400
        os.utime(path, (aged, aged))
        if os.name != "nt" and os.geteuid() == 0:
            os.chown(path, st_home.st_uid, st_home.st_gid)
        tid = secrets.token_hex(4)
        raw = content if isinstance(content, bytes) else content.encode()
        reg["tokens"][tid] = {
            "id": tid, "type": kind, "path": path, "host": socket.gethostname(),
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "sha256": hashlib.sha256(raw).hexdigest(), "secrets": secrets_,
            "audit_key": f"ht_{tid}"}
        print(f"[+] {kind:9} {tid}  {path}")
    save_reg(a.registry, reg)
    print(f"\nregistry: {a.registry}  (keep it OFF the decoy host's readable paths, mode 600)")
    print("next:     honeytrapper.py rules --install   then   honeytrapper.py monitor")


# -------------------------------------------------------------------- rules
def auditd_rules(reg):
    out = ["# honeytrapper decoy watches - generated " + datetime.date.today().isoformat()]
    for t in reg["tokens"].values():
        out.append(f"-w {t['path']} -p rwa -k {t['audit_key']}")
    return "\n".join(out) + "\n"

def sigma_rules(reg):
    toks = list(reg["tokens"].values())
    paths = "\n".join(f"            - '{t['path']}'" for t in toks) or "            - 'NONE'"
    lol = sorted(b for b in LOTL_MAP if b.endswith(".exe"))
    lol_y = "\n".join(f"            - '\\{b}'" for b in lol)
    return f"""title: Honeytoken Decoy Accessed (Linux auditd)
id: {secrets.token_hex(4)}-ht01-4c1a-9d1e-{secrets.token_hex(6)}
status: experimental
description: A process opened a planted decoy credential file. No legitimate use exists.
logsource:
    product: linux
    service: auditd
detection:
    selection:
        key|startswith: 'ht_'
    filter_benign:
        comm:
            - 'updatedb'
            - 'clamscan'
    condition: selection and not filter_benign
fields: [comm, exe, pid, ppid, auid, uid, key]
level: high
tags: [attack.credential_access, attack.t1552.001, attack.discovery, attack.t1083]
---
title: Honeytoken Decoy Accessed by LOLBin (Windows 4663)
id: {secrets.token_hex(4)}-ht02-4c1a-9d1e-{secrets.token_hex(6)}
status: experimental
description: Object-access auditing hit on a decoy; elevated when the reader is a LOLBin.
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4663
        ObjectName|endswith:
{paths}
    lolbin:
        ProcessName|endswith:
{lol_y}
    condition: selection
fields: [SubjectUserName, ProcessName, ObjectName, AccessMask]
level: high
tags: [attack.credential_access, attack.t1552.001, attack.t1218]
"""

def windows_ps(reg):
    paths = ",\n  ".join(f"'{t['path']}'" for t in reg["tokens"].values())
    lol = ",".join(f"'{b}'" for b in sorted(b for b in LOTL_MAP if b.endswith(".exe")))
    return f"""# honeytrapper.ps1 - run elevated. 1) enables object-access auditing + SACLs on decoys
#                                 2) watches Security 4663 and flags LOLBin readers
$Decoys = @(
  {paths}
)
$LOLBins = @({lol})

auditpol /set /subcategory:"File System" /success:enable | Out-Null
foreach ($p in $Decoys) {{
  if (-not (Test-Path $p)) {{ Write-Warning "missing $p"; continue }}
  $acl  = Get-Acl -Path $p -Audit
  $rule = New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','ReadData,Read,Write,Delete','Success')
  $acl.AddAuditRule($rule); Set-Acl -Path $p -AclObject $acl
  Write-Host "[+] SACL set: $p"
}}

$since = Get-Date
Write-Host "[*] watching 4663 for decoy access... (Ctrl-C to stop)"
while ($true) {{
  Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4663; StartTime=$since}} -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated | ForEach-Object {{
      $x = [xml]$_.ToXml(); $d = @{{}}
      $x.Event.EventData.Data | ForEach-Object {{ $d[$_.Name] = $_.'#text' }}
      if ($Decoys -contains $d.ObjectName) {{
        $exe = Split-Path $d.ProcessName -Leaf
        $sev = if ($LOLBins -contains $exe.ToLower()) {{ 'critical' }} else {{ 'high' }}
        [pscustomobject]@{{ time=$_.TimeCreated; severity=$sev; user="$($d.SubjectDomainName)\\$($d.SubjectUserName)";
          process=$d.ProcessName; pid=$d.ProcessId; decoy=$d.ObjectName; lolbin=($sev -eq 'critical') }} |
          ConvertTo-Json -Compress | Tee-Object -Append -FilePath "$env:ProgramData\\honeytrapper-alerts.jsonl"
      }}
      $script:since = $_.TimeCreated.AddMilliseconds(1)
    }}
  Start-Sleep -Seconds 2
}}
"""

def cmd_rules(a):
    reg = load_reg(a.registry)
    if not reg["tokens"]:
        sys.exit("no tokens in registry - run create first")
    if a.sigma:
        print(sigma_rules(reg)); return
    if a.windows:
        print(windows_ps(reg)); return
    rules = auditd_rules(reg)
    if a.install:
        dst = "/etc/audit/rules.d/honeytrapper.rules"
        with open(dst, "w") as f:
            f.write(rules)
        print(f"[+] wrote {dst}")
        rc = os.system("augenrules --load >/dev/null 2>&1 || auditctl -R " + dst + " >/dev/null")
        print("[+] rules loaded" if rc == 0 else "[!] load failed - run: augenrules --load")
    else:
        print(rules, end="")


# --------------------------------------------------------------------- email
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

class Mailer:
    """SMTP alerts, batched into digests so a burst (e.g. `tar` over a home
    directory) sends one email instead of fifty. Password comes from the
    HONEYTRAPPER_SMTP_PASSWORD env var so it never shows up in `ps` or shell history."""

    def __init__(self, a):
        self.a = a
        self.to = [x.strip() for x in a.email_to.split(",") if x.strip()]
        self.sender = a.email_from or f"honeytrapper@{socket.getfqdn()}"
        self.password = os.environ.get("HONEYTRAPPER_SMTP_PASSWORD")
        self.port = a.smtp_port or {"ssl": 465, "starttls": 587, "none": 25}[a.smtp_tls]
        self.min_rank = SEV_RANK[a.email_min_severity]
        self.q, self.lock = [], threading.Lock()
        if a.smtp_user and not self.password:
            print("[!] --smtp-user set but HONEYTRAPPER_SMTP_PASSWORD is empty", file=sys.stderr)
        if a.email_batch > 0:
            threading.Thread(target=self._loop, daemon=True).start()

    def add(self, ev):
        if SEV_RANK.get(ev.get("severity"), 2) < self.min_rank:
            return
        if self.a.email_batch <= 0:
            self._send([ev])
        else:
            with self.lock:
                self.q.append(ev)

    def _loop(self):
        while True:
            time.sleep(self.a.email_batch)
            self.flush()

    def flush(self):
        with self.lock:
            evs, self.q = self.q, []
        if evs:
            self._send(evs)

    @staticmethod
    def _summary(ev):
        who = os.path.basename(ev.get("process") or "") or "unattributed"
        if ev.get("alert") == "honeytoken_use":
            return f"decoy {ev['token_type']} secret ({ev['field']}) seen in {ev['log']}:{ev['line']}"
        return f"{who} [{ev.get('lotl_category')}] opened {ev['token_type']} decoy {ev.get('decoy')}"

    def _send(self, evs, subject=None):
        import smtplib, ssl
        from email.message import EmailMessage
        top = max(evs, key=lambda e: SEV_RANK.get(e.get("severity"), 2))
        host = top.get("host") or socket.gethostname()
        subject = subject or (f"[honeytrapper][{top.get('severity', 'high').upper()}] "
                              f"{len(evs)} alert(s) on {host}: {self._summary(top)}")[:200]
        lines = [f"Honeytrapper fired on {host}. Decoys have no legitimate use - treat as a",
                 "likely intrusion until proven otherwise.", ""]
        for i, ev in enumerate(evs, 1):
            lines.append(f"{i}. [{ev.get('severity', '?').upper()}] {self._summary(ev)}")
            for k in ("event_time", "ts", "pid", "uid", "auid", "cmdline", "parent_chain", "excerpt"):
                if ev.get(k):
                    lines.append(f"     {k:13}: {ev[k]}")
            lines.append("")
        lines += ["Triage: isolate host, pull process tree for the pid(s) above, check",
                  "for outbound connections, rotate nothing (secrets are fake) - but run",
                  "`honeytrapper.py hunt` against auth/cloud logs to see if they were USED.", "",
                  "--- raw JSON ---"] + [json.dumps(e) for e in evs]
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = subject, self.sender, ", ".join(self.to)
        msg["X-Priority"] = "1" if top.get("severity") == "critical" else "3"
        msg.set_content("\n".join(lines))
        ctx = ssl.create_default_context()
        for attempt in (1, 2):
            try:
                if self.a.smtp_tls == "ssl":
                    s = smtplib.SMTP_SSL(self.a.smtp_host, self.port, context=ctx, timeout=15)
                else:
                    s = smtplib.SMTP(self.a.smtp_host, self.port, timeout=15)
                    if self.a.smtp_tls == "starttls":
                        s.starttls(context=ctx)
                with s:
                    if self.a.smtp_user:
                        s.login(self.a.smtp_user, self.password or "")
                    s.send_message(msg)
                print(f"[+] emailed {len(evs)} alert(s) to {', '.join(self.to)}", file=sys.stderr)
                return True
            except Exception as e:
                print(f"[!] email attempt {attempt} failed: {e}", file=sys.stderr)
                time.sleep(3)
        return False


def cmd_test_email(a):
    if not a.email_to:
        sys.exit("--email-to is required")
    m = Mailer(a)
    ev = {"alert": "honeytoken_access", "severity": "high", "lotl_category": "read",
          "host": socket.gethostname(), "token_id": "test", "token_type": "test",
          "decoy": "/dev/null (test message)", "process": "/usr/bin/cat",
          "ts": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    ok = m._send([ev], subject=f"[honeytrapper] test email from {socket.gethostname()}")
    sys.exit(0 if ok else 1)


# ------------------------------------------------------------------ alerting
class Alerter:
    def __init__(self, a):
        self.mailer = Mailer(a) if a.email_to else None
        self.log = a.log
        self.webhook = a.webhook
        self.syslog = None
        if a.syslog and os.path.exists("/dev/log"):
            import logging, logging.handlers
            self.syslog = logging.getLogger("honeytrapper")
            self.syslog.addHandler(logging.handlers.SysLogHandler(address="/dev/log"))
            self.syslog.setLevel(logging.WARNING)
        self.allow = DEFAULT_ALLOW | set(filter(None, (a.allow or "").split(",")))
        self.seen = {}

    def emit(self, tok, proc=None, **ctx):
        if proc and os.path.basename(proc) in self.allow:
            return
        dedup = (tok["id"], ctx.get("pid"), proc)
        if time.time() - self.seen.get(dedup, 0) < 5:
            return
        self.seen[dedup] = time.time()
        cat, sev = classify(proc) if proc else ("unattributed", "high")
        ev = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "alert": "honeytoken_access", "severity": sev, "lotl_category": cat,
              "host": socket.gethostname(), "token_id": tok["id"], "token_type": tok["type"],
              "decoy": tok["path"], "process": proc, **{k: v for k, v in ctx.items() if v is not None}}
        line = json.dumps(ev)
        print(line, flush=True)
        if self.log:
            with open(self.log, "a") as f:
                f.write(line + "\n")
        if self.syslog:
            self.syslog.warning("honeytrapper: " + line)
        if self.mailer:
            self.mailer.add(ev)
        if self.webhook:
            try:
                import urllib.request
                req = urllib.request.Request(self.webhook, data=line.encode(),
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
            except Exception as e:
                print(f"[!] webhook failed: {e}", file=sys.stderr)


def proc_info(pid):
    """Best-effort process + parent-chain enrichment from /proc."""
    def rd(p):
        try:
            with open(p) as f:
                return f.read().strip()
        except OSError:
            return None
    chain, cur = [], str(pid)
    for _ in range(4):
        comm = rd(f"/proc/{cur}/comm")
        stat = rd(f"/proc/{cur}/stat")
        if not comm or not stat:
            break
        chain.append(comm)
        cur = stat.rsplit(")", 1)[1].split()[1]  # ppid
        if cur in ("0", "1"):
            break
    cmd = rd(f"/proc/{pid}/cmdline")
    return {"cmdline": cmd.replace("\x00", " ").strip() if cmd else None,
            "parent_chain": " <- ".join(chain[1:]) or None}


# ------------------------------------------------------------ monitor: audit
AUD_HDR = re.compile(r"type=(\w+) msg=audit\((\d+\.\d+):(\d+)\):")
AUD_KV = re.compile(r'(\w+)=("([^"]*)"|\S+)')

def parse_audit_line(line):
    m = AUD_HDR.search(line)
    if not m:
        return None
    kv = {k: (q if q else v) for k, v, q in AUD_KV.findall(line[m.end():])}
    kv["_type"], kv["_ts"], kv["_serial"] = m.group(1), float(m.group(2)), m.group(3)
    return kv

def monitor_audit(a, reg, alert):
    by_key = {t["audit_key"]: t for t in reg["tokens"].values()}
    path = a.audit_log
    f = open(path, errors="replace")
    if not a.from_start:
        f.seek(0, 2)
    ino = os.fstat(f.fileno()).st_ino
    print(f"[*] tailing {path} for {len(by_key)} decoy keys", file=sys.stderr)
    while True:
        line = f.readline()
        if not line:
            if a.from_start and a.once:
                return
            time.sleep(0.5)
            try:  # handle log rotation
                if os.stat(path).st_ino != ino:
                    f.close(); f = open(path, errors="replace"); ino = os.fstat(f.fileno()).st_ino
            except FileNotFoundError:
                pass
            continue
        r = parse_audit_line(line)
        if not r or r["_type"] != "SYSCALL" or r.get("key") not in by_key:
            continue
        pid = r.get("pid")
        enrich = proc_info(pid) if pid else {}
        alert.emit(by_key[r["key"]], proc=r.get("exe") or r.get("comm"), comm=r.get("comm"),
                   pid=pid, ppid=r.get("ppid"), uid=r.get("uid"), auid=r.get("auid"),
                   syscall=r.get("syscall"), success=r.get("success"), via="auditd",
                   event_time=datetime.datetime.fromtimestamp(r["_ts"], datetime.timezone.utc).isoformat(),
                   **enrich)


# ---------------------------------------------------------- monitor: inotify
IN_ACCESS, IN_MODIFY, IN_ATTRIB, IN_OPEN = 0x1, 0x2, 0x4, 0x20
IN_MOVE_SELF, IN_DELETE_SELF, IN_IGNORED = 0x800, 0x400, 0x8000

def find_openers(path):
    """Race-prone attribution: who has the decoy open right now?"""
    hits = []
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            if os.readlink(fd) == path:
                pid = fd.split("/")[2]
                if int(pid) != os.getpid():
                    hits.append(pid)
        except OSError:
            continue
    return sorted(set(hits))

def monitor_inotify(a, reg, alert):
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    ifd = libc.inotify_init1(0)
    if ifd < 0:
        sys.exit("inotify_init1 failed")
    wds = {}
    mask = IN_OPEN | IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF
    for t in reg["tokens"].values():
        wd = libc.inotify_add_watch(ifd, t["path"].encode(), mask)
        if wd < 0:
            print(f"[!] cannot watch {t['path']}: errno {ctypes.get_errno()}", file=sys.stderr)
        else:
            wds[wd] = t
    print(f"[*] inotify watching {len(wds)} decoys (attribution is best-effort; prefer auditd)",
          file=sys.stderr)
    names = {IN_OPEN: "open", IN_ACCESS: "read", IN_MODIFY: "modify", IN_ATTRIB: "attrib",
             IN_MOVE_SELF: "moved", IN_DELETE_SELF: "deleted"}
    while True:
        buf = os.read(ifd, 8192)
        off = 0
        while off < len(buf):
            wd, m, _cookie, ln = struct.unpack_from("iIII", buf, off)
            off += 16 + ln
            t = wds.get(wd)
            if not t or m & IN_IGNORED:
                continue
            if not m & (IN_OPEN | IN_MODIFY | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF):
                continue  # IN_ACCESS alone duplicates the IN_OPEN alert
            ops = [n for b, n in names.items() if m & b]
            pids = find_openers(t["path"])
            if not pids:
                alert.emit(t, op=",".join(ops), via="inotify")
            for pid in pids:
                exe = None
                try:
                    exe = os.readlink(f"/proc/{pid}/exe")
                except OSError:
                    pass
                alert.emit(t, proc=exe, pid=pid, op=",".join(ops), via="inotify", **proc_info(pid))
            if m & (IN_DELETE_SELF | IN_MOVE_SELF):
                print(f"[!] decoy {t['path']} removed/moved - re-run create", file=sys.stderr)


def cmd_monitor(a):
    reg = load_reg(a.registry)
    if not reg["tokens"]:
        sys.exit("no tokens in registry - run create first")
    alert = Alerter(a)
    mode = a.mode
    if mode == "auto":
        mode = "audit" if os.access(a.audit_log, os.R_OK) else "inotify"
    try:
        (monitor_audit if mode == "audit" else monitor_inotify)(a, reg, alert)
    except KeyboardInterrupt:
        pass
    finally:
        if alert.mailer:
            alert.mailer.flush()   # don't lose a pending digest on shutdown


# --------------------------------------------------------------------- hunt
def cmd_hunt(a):
    """Detect USE of decoy secrets: grep auth/web/CloudTrail/k8s audit logs."""
    reg = load_reg(a.registry)
    needles = {}
    for t in reg["tokens"].values():
        for k, v in t["secrets"].items():
            if isinstance(v, str) and len(v) >= 8 and k != "note":
                needles[v] = (t, k)
    if not needles:
        sys.exit("no huntable secrets in registry")
    pat = re.compile("|".join(re.escape(n) for n in sorted(needles, key=len, reverse=True)))
    hits, found = 0, []
    files = [p for g in a.logs for p in (glob.glob(g) or [g])]
    for path in files:
        opener = open
        if path.endswith(".gz"):
            import gzip; opener = gzip.open
        try:
            with opener(path, "rt", errors="replace") as f:
                for n, line in enumerate(f, 1):
                    for m in pat.finditer(line):
                        t, field = needles[m.group(0)]
                        hits += 1
                        ev = {"alert": "honeytoken_use", "severity": "critical",
                              "host": socket.gethostname(), "token_id": t["id"],
                              "token_type": t["type"], "field": field, "log": path,
                              "line": n, "excerpt": line.strip()[:300]}
                        found.append(ev)
                        print(json.dumps(ev))
        except OSError as e:
            print(f"[!] {path}: {e}", file=sys.stderr)
    print(f"[*] {hits} hit(s) across {len(files)} file(s)", file=sys.stderr)
    if found and a.email_to:
        Mailer(a)._send(found[:200])   # one digest per hunt run
    sys.exit(2 if hits else 0)


# ------------------------------------------------------------ status/remove
def cmd_status(a):
    reg = load_reg(a.registry)
    for t in reg["tokens"].values():
        # stat only - opening the file would trip our own tripwire
        try:
            st = os.stat(t["path"])
            state = f"present  size={st.st_size}"
        except FileNotFoundError:
            state = "MISSING"
        print(f"{t['id']}  {t['type']:9} {state:22} {t['path']}")

def cmd_remove(a):
    reg = load_reg(a.registry)
    for tid in list(reg["tokens"]):
        if a.id and tid not in a.id:
            continue
        t = reg["tokens"].pop(tid)
        try:
            os.remove(t["path"]); print(f"[-] removed {t['path']}")
        except FileNotFoundError:
            print(f"[-] already gone {t['path']}")
    save_reg(a.registry, reg)
    print("[*] regenerate rules (rules --install) to drop stale watches")


# --------------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser(description="Honey-token deployment + LOTL access detection")
    p.add_argument("--registry", default=DEFAULT_REG)
    s = p.add_subparsers(dest="cmd", required=True)

    em = argparse.ArgumentParser(add_help=False)
    eg = em.add_argument_group("email alerts (password via HONEYTRAPPER_SMTP_PASSWORD env)")
    eg.add_argument("--email-to", help="comma-separated recipients; enables email")
    eg.add_argument("--email-from")
    eg.add_argument("--smtp-host", default="localhost")
    eg.add_argument("--smtp-port", type=int, help="default 587/465/25 by --smtp-tls")
    eg.add_argument("--smtp-tls", choices=["starttls", "ssl", "none"], default="starttls")
    eg.add_argument("--smtp-user")
    eg.add_argument("--email-min-severity", choices=["medium", "high", "critical"],
                    default="medium")
    eg.add_argument("--email-batch", type=int, default=30,
                    help="seconds to collect alerts into one digest; 0 = send each now")

    c = s.add_parser("create", help="plant decoys")
    c.add_argument("--home", default="~")
    c.add_argument("--types", default="all", help="comma list: " + ",".join(TEMPLATES))
    c.set_defaults(fn=cmd_create)

    r = s.add_parser("rules", help="emit detection rules")
    g = r.add_mutually_exclusive_group()
    g.add_argument("--install", action="store_true", help="write+load auditd rules (root)")
    g.add_argument("--sigma", action="store_true")
    g.add_argument("--windows", action="store_true", help="PowerShell SACL+4663 watcher")
    r.set_defaults(fn=cmd_rules)

    m = s.add_parser("monitor", help="watch decoys and alert", parents=[em])
    m.add_argument("--mode", choices=["auto", "audit", "inotify"], default="auto")
    m.add_argument("--audit-log", default="/var/log/audit/audit.log")
    m.add_argument("--from-start", action="store_true", help="replay existing audit log")
    m.add_argument("--once", action="store_true", help="with --from-start: exit at EOF")
    m.add_argument("--log", help="append JSON alerts to file")
    m.add_argument("--syslog", action="store_true")
    m.add_argument("--webhook", help="POST each alert as JSON (Slack/Teams/SOAR)")
    m.add_argument("--allow", help="comma list of process names to ignore")
    m.set_defaults(fn=cmd_monitor)

    h = s.add_parser("hunt", help="find decoy secrets being USED in logs", parents=[em])
    h.add_argument("logs", nargs="+")
    h.set_defaults(fn=cmd_hunt)

    te = s.add_parser("test-email", help="send a test alert to verify SMTP settings",
                      parents=[em])
    te.set_defaults(fn=cmd_test_email)

    s.add_parser("status").set_defaults(fn=cmd_status)
    rm = s.add_parser("remove"); rm.add_argument("--id", nargs="*"); rm.set_defaults(fn=cmd_remove)

    a = p.parse_args()
    a.fn(a)

if __name__ == "__main__":
    main()
