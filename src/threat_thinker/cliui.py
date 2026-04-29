"""
Modern CLI UI components for Threat Thinker
"""

import sys
import time
import threading
from typing import Optional, List, Dict, Any
from enum import Enum


_DEFAULT_LOCALE = "en"
_CLI_TEXT = {
    "en": {
        "step": "Step",
        "analysis_complete": "Analysis Complete!",
        "identified_threats": "Identified {count} threats",
        "processing_time": "Processing time: {seconds}s",
        "parsing_metrics": "Parsing metrics:",
        "file_size": "File size: {size_kb:.1f} KB",
        "processed_lines": "Processed {count} lines",
        "found_nodes": "Found {count} nodes",
        "found_edges": "Found {count} edges",
        "success_rate": "Success rate: {rate}%",
        "metrics_details": "Metrics details",
        "ai_is_analyzing": "AI is analyzing",
        "no_threats": "No threats identified",
        "preview_threats": "Preview of identified threats (showing {shown} of {total}):",
        "score": "Score",
        "more_threats": "... and {count} more threats",
    },
    "ja": {
        "step": "ステップ",
        "analysis_complete": "分析が完了しました",
        "identified_threats": "{count} 件の脅威を特定しました",
        "processing_time": "処理時間: {seconds}秒",
        "parsing_metrics": "解析メトリクス:",
        "file_size": "ファイルサイズ: {size_kb:.1f} KB",
        "processed_lines": "{count} 行を処理しました",
        "found_nodes": "{count} 個のノードを検出しました",
        "found_edges": "{count} 本のエッジを検出しました",
        "success_rate": "成功率: {rate}%",
        "metrics_details": "メトリクス詳細",
        "ai_is_analyzing": "AI が分析中",
        "no_threats": "脅威は特定されませんでした",
        "preview_threats": "特定された脅威のプレビュー ({total} 件中 {shown} 件を表示):",
        "score": "スコア",
        "more_threats": "... 他 {count} 件の脅威",
    },
}


def _normalize_locale(locale: Optional[str]) -> str:
    return "ja" if (locale or "").strip().lower().startswith("ja") else _DEFAULT_LOCALE


def _t(locale: Optional[str], key: str, **kwargs) -> str:
    template = _CLI_TEXT[_normalize_locale(locale)][key]
    return template.format(**kwargs) if kwargs else template


class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    THINKING = "thinking"


class Colors:
    """ANSI color codes for terminal output"""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Basic colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"


class ProgressBar:
    """Simple progress bar for CLI"""

    def __init__(
        self, total: int, width: int = 40, fill_char: str = "█", empty_char: str = "░"
    ):
        self.total = total
        self.current = 0
        self.width = width
        self.fill_char = fill_char
        self.empty_char = empty_char
        self.start_time = time.time()

    def update(self, amount: int = 1):
        """Update progress by amount"""
        self.current = min(self.current + amount, self.total)
        self._draw()

    def set_progress(self, current: int):
        """Set absolute progress"""
        self.current = min(current, self.total)
        self._draw()

    def _draw(self):
        """Draw the progress bar"""
        if self.total == 0:
            percent = 100
        else:
            percent = (self.current / self.total) * 100

        filled_width = int(self.width * self.current // self.total)
        empty_width = self.width - filled_width

        bar = self.fill_char * filled_width + self.empty_char * empty_width

        elapsed = time.time() - self.start_time

        sys.stdout.write(
            f"\r{Colors.CYAN}[{bar}]{Colors.RESET} {percent:6.1f}% ({self.current}/{self.total}) {elapsed:.1f}s"
        )
        sys.stdout.flush()

    def finish(self):
        """Complete the progress bar"""
        self.current = self.total
        self._draw()
        print()  # New line


class ThinkingIndicator:
    """Animated thinking indicator for AI operations"""

    def __init__(self, message: str = "Thinking"):
        self.message = message
        self.is_running = False
        self.thread = None
        self.frames = ["🤔", "💭", "🧠", "⚡"]
        self.current_frame = 0

    def start(self):
        """Start the thinking animation"""
        if self.is_running:
            return

        self.is_running = True
        self.thread = threading.Thread(target=self._animate)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        """Stop the thinking animation"""
        self.is_running = False
        if self.thread:
            self.thread.join()
        # Clear the line
        sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")
        sys.stdout.flush()

    def _animate(self):
        """Animation loop"""
        while self.is_running:
            frame = self.frames[self.current_frame]
            sys.stdout.write(
                f"\r{Colors.YELLOW}{frame} {self.message}...{Colors.RESET}"
            )
            sys.stdout.flush()

            self.current_frame = (self.current_frame + 1) % len(self.frames)
            time.sleep(0.5)


class ModernCLI:
    """Modern CLI interface for Threat Thinker"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.current_step = 0
        self.total_steps = 0
        self.locale = _DEFAULT_LOCALE

    def set_locale(self, locale: str):
        """Set locale for CLI display strings."""
        self.locale = _normalize_locale(locale)

    def set_total_steps(self, total: int):
        """Set total number of steps for progress tracking"""
        self.total_steps = total
        self.current_step = 0

    def step(self, title: str):
        """Move to next step"""
        self.current_step += 1
        self._print_step_header(title)

    def _print_step_header(self, title: str):
        """Print step header with progress"""
        if self.total_steps > 0:
            progress = f"({self.current_step}/{self.total_steps})"
        else:
            progress = f"({self.current_step})"

        step_label = _t(self.locale, "step")
        print(
            f"\n{Colors.BOLD}{Colors.BLUE}▶ {step_label} {progress}: {title}{Colors.RESET}"
        )

    def log(self, level: LogLevel, message: str, details: Optional[str] = None):
        """Log a message with appropriate styling"""
        icon, color = self._get_log_style(level)

        if level == LogLevel.DEBUG and not self.verbose:
            return

        print(f"{color}{icon} {message}{Colors.RESET}")

        if details and (self.verbose or level in [LogLevel.ERROR, LogLevel.WARNING]):
            for line in details.split("\n"):
                if line.strip():
                    print(f"  {Colors.DIM}{line}{Colors.RESET}")

    def _get_log_style(self, level: LogLevel) -> tuple[str, str]:
        """Get icon and color for log level"""
        styles = {
            LogLevel.DEBUG: ("🔍", Colors.DIM),
            LogLevel.INFO: ("ℹ️", Colors.BLUE),
            LogLevel.SUCCESS: ("✅", Colors.GREEN),
            LogLevel.WARNING: ("⚠️", Colors.YELLOW),
            LogLevel.ERROR: ("❌", Colors.RED),
            LogLevel.THINKING: ("🤔", Colors.YELLOW),
        }
        return styles.get(level, ("•", Colors.RESET))

    def success(self, message: str, details: Optional[str] = None):
        """Log success message"""
        self.log(LogLevel.SUCCESS, message, details)

    def info(self, message: str, details: Optional[str] = None):
        """Log info message"""
        self.log(LogLevel.INFO, message, details)

    def warning(self, message: str, details: Optional[str] = None):
        """Log warning message"""
        self.log(LogLevel.WARNING, message, details)

    def error(self, message: str, details: Optional[str] = None):
        """Log error message"""
        self.log(LogLevel.ERROR, message, details)

    def debug(self, message: str, details: Optional[str] = None):
        """Log debug message"""
        self.log(LogLevel.DEBUG, message, details)

    def thinking(self, message: str, details: Optional[str] = None):
        """Log thinking message"""
        self.log(LogLevel.THINKING, message, details)

    def show_banner(self):
        """Show application banner"""
        banner = f"""
{Colors.BOLD}{Colors.CYAN}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                               Threat Thinker 🤔                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)

    def show_summary(self, threats_count: int, processing_time: float):
        """Show final summary"""
        print(
            f"\n{Colors.BOLD}{Colors.GREEN}🎯 {_t(self.locale, 'analysis_complete')}{Colors.RESET}"
        )
        print(
            f"  {Colors.CYAN}•{Colors.RESET} "
            f"{_t(self.locale, 'identified_threats', count=f'{Colors.BOLD}{threats_count}{Colors.RESET}')}"
        )
        print(
            f"  {Colors.CYAN}•{Colors.RESET} "
            f"{_t(self.locale, 'processing_time', seconds=processing_time).replace(f'{processing_time:.1f}', f'{Colors.BOLD}{processing_time:.1f}{Colors.RESET}', 1)}"
        )

    def show_metrics_summary(self, metrics: Dict[str, Any]):
        """Show parsing metrics in a user-friendly way"""
        self.info(_t(self.locale, "parsing_metrics"))

        # Handle different metric types
        if hasattr(metrics, "total_lines"):
            total_lines = metrics.total_lines

            # For image files, total_lines represents file size
            if total_lines > 10000:  # Likely file size in bytes
                self.debug(_t(self.locale, "file_size", size_kb=total_lines / 1024))
            else:
                print(
                    f"  {Colors.CYAN}•{Colors.RESET} "
                    f"{_t(self.locale, 'processed_lines', count=f'{Colors.BOLD}{total_lines}{Colors.RESET}')}"
                )

            # Show parsing success rates if available
            if hasattr(metrics, "nodes_parsed"):
                print(
                    f"  {Colors.CYAN}•{Colors.RESET} "
                    f"{_t(self.locale, 'found_nodes', count=f'{Colors.BOLD}{metrics.nodes_parsed}{Colors.RESET}')}"
                )
            if hasattr(metrics, "edges_parsed"):
                print(
                    f"  {Colors.CYAN}•{Colors.RESET} "
                    f"{_t(self.locale, 'found_edges', count=f'{Colors.BOLD}{metrics.edges_parsed}{Colors.RESET}')}"
                )
            if hasattr(metrics, "import_success_rate"):
                rate = metrics.import_success_rate * 100
                color = (
                    Colors.GREEN
                    if rate > 80
                    else Colors.YELLOW
                    if rate > 60
                    else Colors.RED
                )
                print(
                    f"  {Colors.CYAN}•{Colors.RESET} "
                    f"{_t(self.locale, 'success_rate', rate=f'{color}{Colors.BOLD}{rate:.1f}{Colors.RESET}')}"
                )
        elif isinstance(metrics, dict):
            # Handle dict-type metrics
            if "total_lines" in metrics:
                lines = metrics["total_lines"]
                if lines > 10000:
                    self.debug(_t(self.locale, "file_size", size_kb=lines / 1024))
                else:
                    print(
                        f"  {Colors.CYAN}•{Colors.RESET} "
                        f"{_t(self.locale, 'processed_lines', count=f'{Colors.BOLD}{lines}{Colors.RESET}')}"
                    )
        else:
            self.debug(_t(self.locale, "metrics_details"), str(metrics))

    def create_progress_bar(self, total: int) -> ProgressBar:
        """Create a new progress bar"""
        return ProgressBar(total)

    def create_thinking_indicator(
        self, message: Optional[str] = None
    ) -> ThinkingIndicator:
        """Create a new thinking indicator"""
        return ThinkingIndicator(message or _t(self.locale, "ai_is_analyzing"))

    def show_threats_preview(self, threats: List[Any], max_show: int = 3):
        """Show a preview of the first few threats"""
        if not threats:
            self.warning(_t(self.locale, "no_threats"))
            return

        self.info(
            _t(
                self.locale,
                "preview_threats",
                shown=min(len(threats), max_show),
                total=len(threats),
            )
        )

        for i, threat in enumerate(threats[:max_show]):
            severity_color = self._get_severity_color(threat.severity)
            print(
                f"  {Colors.BOLD}{i + 1}.{Colors.RESET} {severity_color}{threat.severity}{Colors.RESET} - {threat.title}"
            )
            if hasattr(threat, "score"):
                print(
                    f"     {_t(self.locale, 'score')}: {Colors.BOLD}{threat.score:.1f}{Colors.RESET}"
                )

        if len(threats) > max_show:
            remaining = len(threats) - max_show
            print(
                f"  {Colors.DIM}{_t(self.locale, 'more_threats', count=remaining)}{Colors.RESET}"
            )

    def _get_severity_color(self, severity: str) -> str:
        """Get color for threat severity"""
        severity_lower = severity.lower()
        if severity_lower in ["critical", "high"]:
            return Colors.RED
        elif severity_lower == "medium":
            return Colors.YELLOW
        elif severity_lower == "low":
            return Colors.GREEN
        else:
            return Colors.RESET


# Global CLI instance
ui = ModernCLI()


def set_verbose(verbose: bool):
    """Set verbose mode globally"""
    global ui
    ui.verbose = verbose


def set_locale(locale: str):
    """Set locale globally for think/diff CLI output."""
    global ui
    ui.set_locale(locale)
