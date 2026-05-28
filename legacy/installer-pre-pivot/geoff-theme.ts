/**
 * Geoff Theme - Custom UI theme for Geoff AI Assistant
 * Based on OpenClaw TUI with Geoff branding
 */

import type {
  EditorTheme,
  MarkdownTheme,
  SelectListTheme,
  SettingsListTheme,
} from "@mariozechner/pi-tui";
import chalk from "chalk";
import { highlight, supportsLanguage } from "cli-highlight";
import type { SearchableSelectListTheme } from "./searchable-select-list.js";

// Geoff Brand Colors
const GEOFF_PRIMARY = "#3B82F6";      // Blue - Geoff's main color
const GEOFF_SECONDARY = "#10B981";    // Green - success/accent
const GEOFF_ACCENT = "#F59E0B";       // Amber - highlights
const GEOFF_DARK = "#1E293B";         // Slate 800 - dark backgrounds
const GEOFF_TEXT = "#F1F5F9";         // Slate 100 - light text
const GEOFF_DIM = "#94A3B8";          // Slate 400 - muted text

const DARK_TEXT = "#F1F5F9";
const LIGHT_TEXT = "#1E293B";

// Geoff Dark Palette (default)
export const geoffDarkPalette = {
  text: GEOFF_TEXT,
  dim: GEOFF_DIM,
  accent: GEOFF_PRIMARY,
  accentSoft: GEOFF_SECONDARY,
  border: "#334155",
  userBg: "#0F172A",
  userText: GEOFF_TEXT,
  systemText: GEOFF_DIM,
  toolPendingBg: "#1E293B",
  toolSuccessBg: "#064E3B",
  toolErrorBg: "#450A0A",
  toolTitle: GEOFF_ACCENT,
  toolOutput: GEOFF_TEXT,
  quote: "#60A5FA",
  quoteBorder: GEOFF_PRIMARY,
  code: "#34D399",
  codeBlock: "#0F172A",
  codeBorder: "#334155",
  link: GEOFF_SECONDARY,
  error: "#EF4444",
  success: GEOFF_SECONDARY,
  geoffBlue: GEOFF_PRIMARY,
  geoffGreen: GEOFF_SECONDARY,
  geoffAmber: GEOFF_ACCENT,
} as const;

// Geoff Light Palette
export const geoffLightPalette = {
  text: "#1E293B",
  dim: "#64748B",
  accent: "#2563EB",
  accentSoft: "#059669",
  border: "#CBD5E1",
  userBg: "#F1F5F9",
  userText: "#1E293B",
  systemText: "#64748B",
  toolPendingBg: "#EFF6FF",
  toolSuccessBg: "#ECFDF5",
  toolErrorBg: "#FEF2F2",
  toolTitle: "#D97706",
  toolOutput: "#374151",
  quote: "#2563EB",
  quoteBorder: "#3B82F6",
  code: "#059669",
  codeBlock: "#F8FAFC",
  codeBorder: "#059669",
  link: "#059669",
  error: "#DC2626",
  success: "#059669",
  geoffBlue: "#2563EB",
  geoffGreen: "#059669",
  geoffAmber: "#D97706",
} as const;

export const geoffPalette = geoffDarkPalette;

const fg = (hex: string) => (text: string) => chalk.hex(hex)(text);
const bg = (hex: string) => (text: string) => chalk.bgHex(hex)(text);

// Geoff ASCII Art Header
export const geoffHeader = `
${fg(GEOFF_PRIMARY)("  ╔═══════════════════════════════════════╗")}
${fg(GEOFF_PRIMARY)("  ║")}  ${fg(GEOFF_TEXT)("   ___")}                                 ${fg(GEOFF_PRIMARY)("║")}
${fg(GEOFF_PRIMARY)("  ║")}  ${fg(GEOFF_TEXT)("  / _ |")} ${fg(GEOFF_DIM)("__ ___________ _")}                   ${fg(GEOFF_PRIMARY)("║")}
${fg(GEOFF_PRIMARY)("  ║")}  ${fg(GEOFF_TEXT)(" / __ |")} ${fg(GEOFF_DIM)("/ // / __/ __/ // /")}                   ${fg(GEOFF_PRIMARY)("║")}
${fg(GEOFF_PRIMARY)("  ║")}  ${fg(GEOFF_TEXT)("/_/ |_|")} ${fg(GEOFF_DIM)("\\_,_/_/  \\__/\\_,_/")}                   ${fg(GEOFF_PRIMARY)("║")}
${fg(GEOFF_PRIMARY)("  ║")}                                       ${fg(GEOFF_PRIMARY)("║")}
${fg(GEOFF_PRIMARY)("  ╚═══════════════════════════════════════╝")}
${fg(GEOFF_DIM)("        AI Assistant - Local & Private")}
`;

// Geoff Welcome Message
export const geoffWelcome = `
${fg(GEOFF_PRIMARY)("Welcome to Geoff!")}

${fg(GEOFF_TEXT)("I'm Geoff, your local AI assistant. I run entirely on your machine")}
${fg(GEOFF_TEXT)("using Ollama, so your conversations stay private.")}

${fg(GEOFF_DIM)("Type /help for available commands")}
${fg(GEOFF_DIM)("Press Ctrl+C to exit")}
`;

export const geoffTheme = {
  fg: fg(geoffPalette.text),
  assistantText: (text: string) => text,
  dim: fg(geoffPalette.dim),
  accent: fg(geoffPalette.accent),
  accentSoft: fg(geoffPalette.accentSoft),
  success: fg(geoffPalette.success),
  error: fg(geoffPalette.error),
  header: (text: string) => chalk.bold(fg(geoffPalette.accent)(text)),
  system: fg(geoffPalette.systemText),
  userBg: bg(geoffPalette.userBg),
  userText: fg(geoffPalette.userText),
  toolTitle: fg(geoffPalette.toolTitle),
  toolOutput: fg(geoffPalette.toolOutput),
  toolPendingBg: bg(geoffPalette.toolPendingBg),
  toolSuccessBg: bg(geoffPalette.toolSuccessBg),
  toolErrorBg: bg(geoffPalette.toolErrorBg),
  border: fg(geoffPalette.border),
  bold: (text: string) => chalk.bold(text),
  italic: (text: string) => chalk.italic(text),
  geoffBlue: fg(geoffPalette.geoffBlue),
  geoffGreen: fg(geoffPalette.geoffGreen),
  geoffAmber: fg(geoffPalette.geoffAmber),
};

export const geoffMarkdownTheme: MarkdownTheme = {
  heading: (text) => chalk.bold(fg(geoffPalette.accent)(text)),
  link: (text) => fg(geoffPalette.link)(text),
  linkUrl: (text) => chalk.dim(text),
  code: (text) => fg(geoffPalette.code)(text),
  codeBlock: (text) => fg(geoffPalette.code)(text),
  codeBlockBorder: (text) => fg(geoffPalette.codeBorder)(text),
  quote: (text) => fg(geoffPalette.quote)(text),
  quoteBorder: (text) => fg(geoffPalette.quoteBorder)(text),
  hr: (text) => fg(geoffPalette.border)(text),
  listBullet: (text) => fg(geoffPalette.accentSoft)(text),
  bold: (text) => chalk.bold(text),
  italic: (text) => chalk.italic(text),
  strikethrough: (text) => chalk.strikethrough(text),
  underline: (text) => chalk.underline(text),
  highlightCode: (code: string) => code.split("\n"),
};
