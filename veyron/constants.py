"""Central constants for the VEYRON application."""

from pathlib import Path

APP_NAME = "veyron"
APP_DISPLAY_NAME = "VEYRON"
APP_DESCRIPTION = (
    "AI-assisted application security assessment and vulnerability research engine"
)

# Default directories used at runtime.
DEFAULT_CONFIG_DIR = Path.home() / ".veyron"
DEFAULT_DATA_DIR = Path.home() / ".veyron" / "data"
DEFAULT_REPORTS_DIR = Path.home() / ".veyron" / "reports"
DEFAULT_CACHE_DIR = Path.home() / ".veyron" / "cache"

# Configuration / environment keys.
ENV_PREFIX = "VEYRON_"

# Default timeouts and limits.
DEFAULT_SCANNER_TIMEOUT_SECONDS = 600
DEFAULT_MAX_FILE_SIZE_BYTES = 2_000_000
DEFAULT_AI_TIMEOUT_SECONDS = 60
DEFAULT_AI_MAX_RETRIES = 2

# Directories that are never assessed or indexed (cached/binaries/build artefacts).
DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "env3",
        "node_modules",
        "bower_components",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        "dist",
        "build",
        "site-packages",
        ".gradle",
        ".idea",
        ".vscode",
        "target",
        "bin",
        "obj",
        "out",
        ".next",
        "coverage",
        ".nyc_output",
    }
)

# File extensions that VEYRON inspects during discovery. Other file types are
# recorded as "unsupported" so coverage claims stay honest.
DEFAULT_SUPPORTED_EXTENSIONS = frozenset(
    {
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".go",
        ".java",
        ".kt",
        ".rs",
        ".rb",
        ".php",
        ".cs",
        ".c",
        ".cpp",
        ".cc",
        ".h",
        ".hpp",
        ".swift",
        ".scala",
        ".clj",
        ".ex",
        ".exs",
        ".erl",
        ".dart",
        ".m",
        ".mm",
        ".pl",
        ".r",
        ".lua",
    }
)

# Dependency manifests / lockfiles VEYRON recognises for SCA.
SUPPORTED_MANIFEST_FILES = frozenset(
    {
        "requirements.txt",
        "setup.py",
        "setup.cfg",
        "pyproject.toml",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "Gemfile",
        "Gemfile.lock",
        "composer.json",
        "composer.lock",
    }
)

# Finding validation states (see SPEC section 6.9).
FINDING_STATES = {
    "DETECTED",
    "ANALYSED",
    "CORROBORATED",
    "VALIDATED",
    "FALSE_POSITIVE",
    "INCONCLUSIVE",
}

# Severity levels used for normalisation.
SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info", "unknown")

# Confidence levels used for normalisation.
CONFIDENCE_LEVELS = ("high", "medium", "low", "unknown")

# SARIF rule / level mapping.
SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "warning",
    "info": "note",
    "unknown": "note",
}

# Default dashboard bind address (localhost only).
DEFAULT_DASHBOARD_HOST = "127.0.0.1"
DEFAULT_DASHBOARD_PORT = 8732

# Report directory names.
REPORT_FORMATS = ("markdown", "json", "sarif")
