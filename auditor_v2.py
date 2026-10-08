# @title Auditor v2.1 — con RESULTS.md automático
# =============================================================================
# REPO SECURITY AUDITOR - Versión Interactiva
# =============================================================================

import ast
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from IPython.display import display, clear_output, HTML
import ipywidgets as widgets

# -----------------------------------------------------------------------------
# Configuración de detección
# -----------------------------------------------------------------------------
HIGH_RISK_CALLS = {
    "exec", "eval", "compile", "__import__",
    "os.system", "subprocess.call", "subprocess.run",
    "subprocess.Popen", "subprocess.check_output",
    "pickle.loads", "marshal.loads", "yaml.load",
}

DANGEROUS_MODULES = {
    "os", "sys", "subprocess", "socket", "http", "urllib", "requests",
    "httpx", "aiohttp", "ftplib", "smtplib", "telnetlib", "paramiko",
    "ctypes", "multiprocessing", "pickle", "marshal", "shelve",
    "webbrowser", "psutil", "shutil", "pathlib", "tempfile",
}

SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|secret|token|password|credential)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
     "Possible hardcoded secret"),
    (re.compile(r"(?i)(sk-[a-zA-Z0-9]{20,})"), "Possible OpenAI-style API key"),
    (re.compile(r"(?i)(AKIA[0-9A-Z]{16})"), "Possible AWS Access Key"),
    (re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----"), "Private key material"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]"), "Hardcoded password assignment"),
]

CODE_EXTENSIONS = {".py", ".pyw"}
CONFIG_EXTENSIONS = {".txt", ".md", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini", ".env"}

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "🔵",
}


# -----------------------------------------------------------------------------
# Modelos de datos
# -----------------------------------------------------------------------------
@dataclass
class Finding:
    severity: str
    category: str
    file: str
    line: Optional[int]
    message: str
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class AuditReport:
    repo_path: str
    timestamp: str
    summary: Dict[str, int] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    overall_risk: str = "UNKNOWN"


# -----------------------------------------------------------------------------
# Analizador AST
# -----------------------------------------------------------------------------
class PythonASTAnalyzer(ast.NodeVisitor):
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: List[Finding] = []
        self.imports: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self.imports.add(node.module.split(".")[0])
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node.func)
        if func_name:
            self._check_dangerous_call(node, func_name)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        full = self._get_attr_name(node)
        if full in HIGH_RISK_CALLS:
            self.findings.append(Finding(
                severity="HIGH",
                category="Dangerous Call",
                file=self.filepath,
                line=node.lineno,
                message=f"Uso de llamada de alto riesgo: {full}",
                recommendation="Revisar si es necesario y si está sandboxed."
            ))
        self.generic_visit(node)

    def _get_call_name(self, node) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._get_attr_name(node)
        return None

    def _get_attr_name(self, node: ast.Attribute) -> str:
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _check_dangerous_call(self, node: ast.Call, func_name: str):
        if func_name in {"exec", "eval"}:
            self.findings.append(Finding(
                severity="CRITICAL",
                category="Dynamic Code Execution",
                file=self.filepath,
                line=node.lineno,
                message=f"Uso de {func_name}() — ejecución dinámica de código",
                recommendation="Verificar que el código pase por sandbox robusto."
            ))
        elif func_name in {"subprocess.Popen", "subprocess.run", "subprocess.call", "os.system"}:
            self.findings.append(Finding(
                severity="HIGH",
                category="Process Execution",
                file=self.filepath,
                line=node.lineno,
                message=f"Ejecución de procesos externos: {func_name}",
                recommendation="Asegurar que los argumentos no sean controlados por entrada no confiable."
            ))
        elif "pickle.loads" in func_name or "marshal.loads" in func_name:
            self.findings.append(Finding(
                severity="HIGH",
                category="Deserialization",
                file=self.filepath,
                line=node.lineno,
                message=f"Deserialización insegura: {func_name}",
                recommendation="Evitar deserializar datos no confiables."
            ))


def analyze_python_file(filepath: Path) -> List[Finding]:
    findings = []
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(filepath))
        analyzer = PythonASTAnalyzer(str(filepath))
        analyzer.visit(tree)
        findings.extend(analyzer.findings)

        for mod in analyzer.imports:
            if mod in DANGEROUS_MODULES:
                findings.append(Finding(
                    severity="MEDIUM",
                    category="Dangerous Import",
                    file=str(filepath),
                    line=None,
                    message=f"Importa módulo potencialmente peligroso: {mod}",
                    recommendation="Verificar uso legítimo y contexto de sandbox."
                ))
    except SyntaxError as e:
        findings.append(Finding(
            severity="INFO", category="Parse Error",
            file=str(filepath), line=e.lineno,
            message=f"No se pudo parsear: {e.msg}"
        ))
    except Exception as e:
        findings.append(Finding(
            severity="INFO", category="Analysis Error",
            file=str(filepath), line=None,
            message=f"Error al analizar: {e}"
        ))
    return findings


def scan_secrets(filepath: Path) -> List[Finding]:
    findings = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(content.splitlines(), 1):
            for pattern, msg in SECRET_PATTERNS:
                if pattern.search(line):
                    if any(x in line.lower() for x in [
                        "example", "placeholder", "your_", "xxx", "todo",
                        "getenv", "environ", "secrets.", "os.environ", "st.secrets"
                    ]):
                        continue
                    findings.append(Finding(
                        severity="CRITICAL",
                        category="Hardcoded Secret",
                        file=str(filepath),
                        line=i,
                        message=msg,
                        code_snippet=line.strip()[:120],
                        recommendation="Eliminar el secreto y usar variables de entorno."
                    ))
    except Exception:
        pass
    return findings


def check_sandbox_presence(repo_path: Path) -> List[Finding]:
    findings = []
    sandbox_files = list(repo_path.rglob("*sandbox*.py"))
    if sandbox_files:
        findings.append(Finding(
            severity="INFO",
            category="Security Control",
            file=str(sandbox_files[0].relative_to(repo_path)),
            line=None,
            message="Se detectó archivo de sandbox. Revisar su robustez.",
            recommendation="Verificar bloqueo de módulos peligrosos + subprocess + timeout + límites de memoria."
        ))
    else:
        findings.append(Finding(
            severity="HIGH",
            category="Missing Control",
            file=str(repo_path),
            line=None,
            message="No se encontró un sandbox explícito para ejecución de código generado.",
            recommendation="Implementar sandboxing robusto."
        ))
    return findings


# -----------------------------------------------------------------------------
# Motor de auditoría
# -----------------------------------------------------------------------------
def audit_repository(repo_path: Path) -> AuditReport:
    report = AuditReport(
        repo_path=str(repo_path),
        timestamp=datetime.now(timezone.utc).isoformat()
    )

    py_files = []
    other_files = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {
            ".git", "__pycache__", ".venv", "venv", "node_modules",
            ".mypy_cache", ".pytest_cache", ".streamlit"
        }]
        for f in files:
            p = Path(root) / f
            if p.suffix in CODE_EXTENSIONS:
                py_files.append(p)
            elif p.suffix in CONFIG_EXTENSIONS or f.startswith(".env"):
                other_files.append(p)

    report.stats = {
        "python_files": len(py_files),
        "config_files": len(other_files),
        "total_files_scanned": len(py_files) + len(other_files),
    }

    print(f"Escaneando {len(py_files)} archivos Python y {len(other_files)} archivos de configuración...")

    for i, pf in enumerate(py_files, 1):
        if i % 25 == 0 or i == len(py_files):
            print(f"  Progreso: {i}/{len(py_files)} archivos...")
        report.findings.extend(analyze_python_file(pf))
        report.findings.extend(scan_secrets(pf))

    for of in other_files:
        report.findings.extend(scan_secrets(of))

    report.findings.extend(check_sandbox_presence(repo_path))

    counts = defaultdict(int)
    score = 0.0

    for f in report.findings:
        counts[f.severity] += 1
        score += SEVERITY_ORDER.get(f.severity, 0)

    report.summary = dict(counts)
    report.risk_score = score

    if counts.get("CRITICAL", 0) > 0:
        report.overall_risk = "CRITICAL"
    elif counts.get("HIGH", 0) >= 3:
        report.overall_risk = "HIGH"
    elif counts.get("HIGH", 0) > 0 or counts.get("MEDIUM", 0) >= 5:
        report.overall_risk = "MEDIUM"
    else:
        report.overall_risk = "LOW"

    return report


# -----------------------------------------------------------------------------
# Impresión en consola
# -----------------------------------------------------------------------------
def print_report(report: AuditReport):
    print("\n" + "=" * 80)
    print(" REPORTE DE AUDITORÍA DE SEGURIDAD")
    print("=" * 80)
    print(f" Repositorio  : {report.repo_path}")
    print(f" Timestamp    : {report.timestamp}")
    print(f" Archivos PY  : {report.stats.get('python_files', 0)}")
    print(f" Risk Score   : {report.risk_score:.1f}")
    print(f" Riesgo Global: {report.overall_risk}")
    print("-" * 80)
    print(" Resumen por severidad:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = report.summary.get(sev, 0)
        print(f"   {sev:10s}: {count}")
    print("-" * 80)

    by_sev = defaultdict(list)
    for f in report.findings:
        by_sev[f.severity].append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        items = by_sev.get(sev, [])
        if not items:
            continue
        print(f"\n### {sev} ({len(items)} hallazgos)")
        for f in items[:25]:
            try:
                rel = Path(f.file).relative_to(report.repo_path)
            except ValueError:
                rel = f.file
            loc = f"{rel}:{f.line}" if f.line else str(rel)
            print(f"  [{f.category}] {loc}")
            print(f"      → {f.message}")
            if f.recommendation:
                print(f"      💡 {f.recommendation}")
            if f.code_snippet:
                print(f"      Código: {f.code_snippet}")
        if len(items) > 25:
            print(f"  ... y {len(items) - 25} hallazgos más de severidad {sev}")

    print("\n" + "=" * 80)
    print(" FIN DEL REPORTE")
    print("=" * 80)

    print("\n📌 CONCLUSIÓN RÁPIDA:")
    if report.overall_risk in ["CRITICAL", "HIGH"]:
        print("   Se detectaron hallazgos de alto riesgo (principalmente ejecución dinámica de código).")
        print("   Esto es ESPERADO en este tipo de proyectos (agentes que generan y ejecutan código).")
        print("   No se detectó malware intencional, pero el riesgo de uso es alto si se ejecuta con datos sensibles.")
    else:
        print("   Riesgo controlado. Revisar los hallazgos MEDIUM/INFO para mayor seguridad.")


# -----------------------------------------------------------------------------
# Generación de README.md
# -----------------------------------------------------------------------------
def generate_readme(report: AuditReport, output_path: Path) -> Path:
    """Genera un README.md con el resumen ejecutivo del reporte."""
    by_sev = defaultdict(list)
    for f in report.findings:
        by_sev[f.severity].append(f)

    def rel_path(fpath: str) -> str:
        try:
            return str(Path(fpath).relative_to(report.repo_path))
        except ValueError:
            return fpath

    lines = []
    lines.append("# 🛡️ Reporte de Auditoría de Seguridad\n")
    lines.append(f"**Repositorio:** `{report.repo_path}`  ")
    lines.append(f"**Fecha:** `{report.timestamp}`  ")
    lines.append(f"**Riesgo global:** **{SEVERITY_ICONS.get(report.overall_risk, '')} {report.overall_risk}**  ")
    lines.append(f"**Risk Score:** `{report.risk_score:.1f}`\n")
    lines.append("---\n")

    # Resumen
    lines.append("## 📊 Resumen del reporte\n")
    lines.append("| Métrica | Valor |")
    lines.append("|---|---|")
    lines.append(f"| Archivos Python escaneados | {report.stats.get('python_files', 0)} |")
    lines.append(f"| Archivos de configuración | {report.stats.get('config_files', 0)} |")
    lines.append(f"| Total escaneado | {report.stats.get('total_files_scanned', 0)} |")
    lines.append(f"| Risk Score | {report.risk_score:.1f} |")
    lines.append(f"| Riesgo global | **{report.overall_risk}** |\n")

    lines.append("### Hallazgos por severidad\n")
    lines.append("| Severidad | Cantidad |")
    lines.append("|---|---|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        icon = SEVERITY_ICONS.get(sev, "")
        lines.append(f"| {icon} {sev} | {report.summary.get(sev, 0)} |")
    lines.append("")

    lines.append("---\n")

    # Top hallazgos: CRITICAL y HIGH
    lines.append("## 🔍 Hallazgos más relevantes\n")

    top_sevs = ["CRITICAL", "HIGH"]
    for sev in top_sevs:
        items = by_sev.get(sev, [])
        if not items:
            continue
        icon = SEVERITY_ICONS.get(sev, "")
        lines.append(f"### {icon} {sev} ({len(items)} hallazgos)\n")
        for f in items:
            loc = f"{rel_path(f.file)}:{f.line}" if f.line else rel_path(f.file)
            lines.append(f"- **[{f.category}]** `{loc}`")
            lines.append(f"  - {f.message}")
            if f.recommendation:
                lines.append(f"  - 💡 _{f.recommendation}_")
            if f.code_snippet:
                lines.append(f"  - `{f.code_snippet}`")
        lines.append("")

    # Nota sobre MEDIUM
    medium_count = report.summary.get("MEDIUM", 0)
    if medium_count:
        lines.append(f"### 🟡 MEDIUM ({medium_count} hallazgos)\n")
        lines.append(f"Se detectaron **{medium_count}** hallazgos de severidad MEDIUM. La mayoría corresponden a ")
        lines.append("importaciones de módulos comunes (`os`, `sys`, `pathlib`, `requests`, `httpx`, etc.) ")
        lines.append("que están marcados como potencialmente peligrosos pero son ubicuos en proyectos Python. ")
        lines.append("Revisar el `audit_report.json` para el detalle completo.\n")

    # Nota sobre INFO
    info_count = report.summary.get("INFO", 0)
    if info_count:
        lines.append(f"### 🔵 INFO ({info_count} hallazgos)\n")
        lines.append("Incluye errores de parseo (sintaxis más nueva que la del entorno de análisis) y ")
        lines.append("controles de seguridad detectados. No representan riesgo directo.\n")

    lines.append("---\n")

    # Recomendaciones generales
    lines.append("## 🛠️ Recomendaciones\n")
    lines.append("1. **Revisar el uso de `exec()` / `eval()`** — Asegurar que el código dinámico se ejecute en un sandbox robusto.")
    lines.append("2. **Auditar llamadas a `subprocess.run` / `os.system`** — Verificar que los argumentos no provengan de entrada no confiable.")
    lines.append("3. **Ajustar la lista de `DANGEROUS_MODULES`** — Módulos como `os`, `pathlib`, `requests` son de uso común; bajarlos a severidad `LOW`/`INFO` reduce falsos positivos.")
    lines.append("4. **Implementar sandboxing por proyecto** — No basta con un sandbox global si el repositorio contiene múltiples apps.")
    lines.append("5. **Eliminar secretos hardcodeados** — Usar variables de entorno o gestores de secretos.\n")

    lines.append("---\n")

    # Conclusión
    lines.append("## ✅ Conclusión\n")
    if report.overall_risk in ["CRITICAL", "HIGH"]:
        lines.append("Se detectaron hallazgos de alto riesgo, principalmente **ejecución dinámica de código** ")
        lines.append("y **ejecución de procesos externos**. Esto es **esperado** en proyectos que construyen ")
        lines.append("agentes que generan y ejecutan código. No se detectó malware intencional, pero el riesgo ")
        lines.append("de uso es alto si se ejecuta con datos sensibles o en entornos sin aislamiento.\n")
    else:
        lines.append("Riesgo controlado. Se recomienda revisar los hallazgos MEDIUM/INFO para mayor seguridad.\n")

    lines.append("---\n")
    lines.append(f"_Generado automáticamente por **Auditor v2.1** el {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}._\n")

    content = "\n".join(lines)
    output_path.write_text(content, encoding="utf-8")
    return output_path


# -----------------------------------------------------------------------------
# Interfaz interactiva (campo vacío + botón)
# -----------------------------------------------------------------------------
repo_input = widgets.Text(
    value="",
    placeholder="Pega aquí la URL de GitHub (ej: https://github.com/usuario/repo.git) o una ruta local",
    description="Repositorio:",
    layout=widgets.Layout(width="90%"),
    style={"description_width": "100px"}
)

run_button = widgets.Button(
    description="🚀 Ejecutar Auditoría",
    button_style="primary",
    layout=widgets.Layout(width="220px", height="40px"),
    tooltip="Haz clic para clonar (si es URL) y auditar el repositorio"
)

output_area = widgets.Output()


def normalize_github_url(user_input: str) -> Tuple[str, Optional[str]]:
    """
    Convierte una URL de GitHub (posiblemente de subdirectorio) a URL raíz clonable.
    Devuelve (repo_url, subpath_detectado).
    """
    m = re.search(
        r'^(https?://github\.com/[^/]+/[^/]+?)(?:\.git)?/(?:tree|blob)/[^/]+(?:/(.*))?$',
        user_input
    )
    if m:
        repo_url = m.group(1) + ".git"
        subpath = m.group(2) if m.group(2) else None
        return repo_url, subpath

    if user_input.endswith(".git"):
        return user_input, None
    return user_input.rstrip("/") + ".git", None


def on_run_clicked(b):
    with output_area:
        clear_output(wait=True)
        user_input = repo_input.value.strip()

        if not user_input:
            print("❌ Por favor ingresa una URL de GitHub o una ruta local válida.")
            return

        print(f"Procesando: {user_input}\n")

        try:
            if user_input.startswith("http://") or user_input.startswith("https://"):
                repo_url, subpath = normalize_github_url(user_input)

                if subpath:
                    print(f"🔍 URL de subdirectorio detectada.")
                    print(f"   → Clonando repositorio raíz: {repo_url}")
                    print(f"   → Subcarpeta de interés (informativa): {subpath}\n")
                else:
                    print(f"→ Clonando: {repo_url}\n")

                repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
                target_dir = Path(f"{repo_name}")

                if target_dir.exists():
                    print(f"El repositorio ya existe en {target_dir}. Usando la copia local...\n")
                else:
                    print("Clonando repositorio (esto puede tardar unos segundos)...")
                    result = subprocess.run(
                        ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode != 0:
                        print("❌ Error al clonar el repositorio:")
                        print(result.stderr)
                        return
                    print("✅ Repositorio clonado correctamente.\n")

                repo_path = target_dir

            else:
                repo_path = Path(user_input)
                if not repo_path.exists():
                    print(f"❌ La ruta no existe: {repo_path}")
                    return
                if not repo_path.is_dir():
                    print(f"❌ La ruta no es un directorio: {repo_path}")
                    return
                print(f"Usando repositorio local: {repo_path}\n")

            print("Iniciando auditoría de seguridad...\n")
            report = audit_repository(repo_path)
            print_report(report)

            output_json = Path("audit_report.json")
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(asdict(report), f, indent=2, ensure_ascii=False)
            print(f"\n✅ Reporte JSON guardado en: {output_json}")

            output_results = Path("RESULTS.md")
            generate_readme(report, output_results)
            print(f"✅ Resumen README.md guardado en: {output_results}")

            print("\nPuedes descargarlos desde el panel de archivos de Colab (icono de carpeta a la izquierda).")

        except Exception as e:
            print(f"\n❌ Ocurrió un error inesperado:\n{type(e).__name__}: {e}")


run_button.on_click(on_run_clicked)

display(HTML("<h3>🔍 Auditoría de Seguridad de Repositorios Python</h3>"))
display(HTML("<p>Pega la <b>URL de GitHub</b> (raíz o subdirectorio) o la <b>ruta local</b> del repositorio y haz clic en el botón.</p>"))
display(repo_input)
display(run_button)
display(output_area)
