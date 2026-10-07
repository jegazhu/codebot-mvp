# CodeBot v3.3 Core Auditor Engine
import subprocess, json, re, shutil, tempfile, urllib.parse
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass, asdict

@dataclass
class Finding:
    title: str
    severity: str          # Critical | High | Medium | Low | Info
    location: Optional[str]
    description: str
    recommendation: str
    skill_name: str
    confidence: float = 0.7
    evidence: str = ""

    def to_dict(self):
        return asdict(self)

SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".php", ".sh", ".c", ".cpp"}
ALL_EXTENSIONS = SOURCE_EXTENSIONS | {".env", ".json", ".yaml", ".yml", ".toml"}
IGNORED_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}

INFOSTEALER_SIGNATURES = {
    "SSH Keys Harvesting": (r"(\.ssh/id_rsa|\.ssh/known_hosts|\.ssh/id_ed25519)", 0.95),
    "Cloud Credentials Access": (r"(\.aws/credentials|\.config/gcloud/|\.azure/)", 0.95),
    "Crypto Wallet Harvesting": (r"(Metamask|Phantom|Rabby|solana_id|keystore\.json)", 0.90),
    "Browser Data Theft": (r"(Login Data|Cookies|Local Storage|Web Data)", 0.85),
    "Auth Tokens Harvesting": (r"(discord|telegram).*(token|api_key)", 0.80),
}

def sanitize_github_url(raw_url: str) -> str: 
    raw = raw_url.strip()
    if not (raw.startswith("http://") or raw.startswith("https://")):
        return raw
    parsed = urllib.parse.urlparse(raw)
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) >= 2:
        user, repo = parts[0], parts[1]
        repo = repo[:-4] if repo.endswith(".git") else repo
        return f"https://github.com/{user}/{repo}.git"
    return raw

def audit_node_lifecycle_scripts(repo_path: str) -> List[Finding]:
    findings = []
    pkg_file = Path(repo_path) / "package.json"
    if not pkg_file.exists():
        return findings
    try:
        data = json.loads(pkg_file.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return findings

    scripts = data.get("scripts", {})
    dangerous_hooks = ["preinstall", "install", "postinstall", "prepare", "build"]
    suspicious = [
        (r"curl", "Descarga de código externo vía curl"),
        (r"wget", "Descarga de archivos vía wget"),
        (r"powershell", "Invocación de PowerShell"),
        (r"base64", "Decodificación Base64 en instalación"),
        (r"eval|node\s+-e", "Ejecución dinámica de JS"),
        (r"\.(exe|sh|bat|ps1)", "Invocación directa de binario o script"),
    ]
    for hook in dangerous_hooks:
        if hook in scripts:
            cmd = str(scripts[hook])
            for pattern, desc in suspicious:
                if re.search(pattern, cmd, re.I):
                    findings.append(Finding(
                        title=f"Malicious lifecycle script in package.json [{hook}]",
                        severity="Critical",
                        location="package.json",
                        description=f"Automated execution risk ({desc}): \"{cmd}\"".strip(),
                        recommendation="DO NOT RUN 'npm install'. Review package.json manually.",
                        skill_name="lifecycle_script_audit",
                        confidence=0.98,
                        evidence=cmd[:100]
                    ))
    return findings

def detect_infostealer_behavior(repo_path: str) -> List[Finding]:
    findings = []
    root = Path(repo_path)
    for path in root.rglob("*"):
        if any(p in IGNORED_DIRS for p in path.parts) or not path.is_file():
            continue
        if path.suffix.lower() in SOURCE_EXTENSIONS:
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
                rel = str(path.relative_to(root))
                for idx, line in enumerate(lines, 1):
                    if line.strip().startswith(("#", "//", "/*")):
                        continue
                    for cat, (pattern, conf) in INFOSTEALER_SIGNATURES.items():
                        if re.search(pattern, line, re.I):
                            findings.append(Finding(
                                title=f"Infostealer pattern: {cat}",
                                severity="Critical",
                                location=f" {rel}:{idx}",
                                description=f"Attempt to access sensitive OS path",
                                recommendation="Isolate execution in sandbox.",
                                skill_name="infostealer_detection",
                                confidence=conf,
                                evidence=line.strip()[:90]
                            ))
            except Exception:
                pass
    return findings

def run_full_audit(source: str, min_confidence: float = 0.60) -> List[Finding]:
    source = source.strip()
    is_url = source.startswith("http://") or source.startswith("https://")

    if is_url:
        clean_url = sanitize_github_url(source)
        tmp_dir = tempfile.mkdtemp(prefix="codebot_")
        env = dict(subprocess.os.environ, GIT_TERMINAL_PROMPT="0")
        res = subprocess.run(["git", "clone", "--depth=1", clean_url, tmp_dir], capture_output=True, env=env)
        if res.returncode != 0:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return []
        repo_path = tmp_dir
        cleanup = True
    else:
        repo_path = source
        cleanup = False

    findings = []
    try:
        findings += audit_node_lifecycle_scripts(repo_path)
        findings += detect_infostealer_behavior(repo_path)
    finally:
        if cleanup:
            shutil.rmtree(repo_path, ignore_errors=True)

    return [f for f in findings if f.confidence >= min_confidence]
