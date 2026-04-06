"""TUI theme configuration for Spider security scanner."""

from typing import ClassVar

from rich.style import Style


class ColorPalette:
    """Core color definitions for the Spider TUI."""

    def __init__(self) -> None:
        self.primary = "#00D4FF"
        self.secondary = "#8B5CF6"
        self.accent = "#10B981"
        self.warning = "#F59E0B"
        self.danger = "#EF4444"
        self.critical = "#FF0000"
        self.info = "#3B82F6"
        self.success = "#22C55E"
        self.muted = "#6B7280"
        self.dim = "#4B5563"
        self.bright = "#F9FAFB"
        self.surface = "#111827"
        self.surface_high = "#1F2937"
        self.border = "#374151"
        self.border_bright = "#4B5563"


class SpiderTheme:
    """Theme configuration for the Spider TUI.

    Provides Rich Style objects for consistent styling across all TUI
    components. Inspired by terminal security tools -- dark background,
    high-contrast accents.
    """

    _cache: ClassVar[dict[str, "SpiderTheme"]] = {}

    def __init__(self) -> None:
        self.palette = ColorPalette()
        self.title = Style(color="#00D4FF", bold=True)
        self.subtitle = Style(color="#8B5CF6", bold=True)
        self.header = Style(color="#00D4FF", bold=True)
        self.header_row = Style(color="#1F2937", bgcolor="#00D4FF")
        self.footer = Style(color="#6B7280", italic=True)
        self.status_running = Style(color="#F59E0B", bold=True)
        self.status_complete = Style(color="#22C55E", bold=True)
        self.status_error = Style(color="#EF4444", bold=True)
        self.status_idle = Style(color="#6B7280")
        self.severity_critical = Style(
            color="#FF0000", bold=True, reverse=True
        )
        self.severity_high = Style(color="#EF4444", bold=True)
        self.severity_medium = Style(color="#F59E0B", bold=True)
        self.severity_low = Style(color="#3B82F6")
        self.severity_info = Style(color="#6B7280", italic=True)
        self.nav_active = Style(color="#00D4FF", bold=True)
        self.nav_inactive = Style(color="#9CA3AF")
        self.nav_disabled = Style(color="#4B5563", dim=True)
        self.border_primary = "#00D4FF"
        self.border_warning = "#F59E0B"
        self.border_error = "#EF4444"
        self.border_success = "#22C55E"
        self.panel_border = "#374151"
        self.panel_title = Style(color="#00D4FF", bold=True)
        self.panel_subtitle = Style(color="#8B5CF6")
        self.table_header = Style(
            color="#111827", bgcolor="#00D4FF", bold=True
        )
        self.table_row_alt = Style(color="#E5E7EB", bgcolor="#1F2937")
        self.progress_bar = "#00D4FF"
        self.progress_complete = "#22C55E"
        self.progress_failed = "#EF4444"
        self.spinner_frames = [
            "\u280b", "\u2819", "\u2839", "\u2838", "\u283c",
            "\u2834", "\u2836", "\u2827", "\u2807", "\u280f",
        ]
        self.spinner_text = Style(color="#00D4FF", bold=True)

    @classmethod
    def dark(cls) -> "SpiderTheme":
        """Dark terminal-optimized theme."""
        if "dark" not in cls._cache:
            cls._cache["dark"] = cls()
        return cls._cache["dark"]

    @classmethod
    def high_contrast(cls) -> "SpiderTheme":
        """High contrast theme for accessibility."""
        if "high_contrast" not in cls._cache:
            palette = ColorPalette()
            palette.primary = "#FFFFFF"
            palette.secondary = "#FFFF00"
            palette.accent = "#00FF00"
            palette.danger = "#FF0000"
            palette.surface = "#000000"
            palette.border = "#FFFFFF"
            inst = cls()
            inst.palette = palette
            inst.title = Style(color="#FFFFFF", bold=True)
            inst.subtitle = Style(color="#FFFF00", bold=True)
            inst.header = Style(
                color="#000000", bgcolor="#FFFFFF", bold=True
            )
            inst.border_primary = "#FFFFFF"
            cls._cache["high_contrast"] = inst
        return cls._cache["high_contrast"]


THEME = SpiderTheme.dark()
