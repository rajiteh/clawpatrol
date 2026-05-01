// Brand logos from iconify CDN (same source as slop.dev). Inline OS
// icons stay local.

const ICON_BASE = "https://api.iconify.design/simple-icons:";

export function ClaudeLogo({ className = "" }: { className?: string }) {
  return (
    <img
      src={ICON_BASE + "claude.svg?color=%23d97706"}
      className={className}
      alt="Claude"
      draggable={false}
    />
  );
}

export function OpenAILogo({ className = "" }: { className?: string }) {
  return (
    <img
      src={ICON_BASE + "openai.svg"}
      className={className}
      alt="OpenAI"
      draggable={false}
    />
  );
}

export function GithubLogo({ className = "" }: { className?: string }) {
  return (
    <img
      src={ICON_BASE + "github.svg"}
      className={className}
      alt="GitHub"
      draggable={false}
    />
  );
}

export function ShellGlyph({ className = "" }: { className?: string }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="#7c3aed" className={className}>
      <path d="M4 17l6-6-6-6m8 14h8" stroke="#7c3aed" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function IntegrationIcon({ id, className = "" }: { id: string; className?: string }) {
  if (id === "claude") return <ClaudeLogo className={className} />;
  if (id === "codex") return <OpenAILogo className={className} />;
  if (id === "github") return <GithubLogo className={className} />;
  return <span className={className} />;
}

// ── device / OS icons (kept local) ─────────────────────────────────

type IconProps = { className?: string };
const baseProps = { viewBox: "0 0 24 24", fill: "currentColor", xmlns: "http://www.w3.org/2000/svg" };

function MacIcon({ className = "" }: IconProps) {
  return (
    <svg className={className} {...baseProps} aria-label="macOS">
      <path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z" />
    </svg>
  );
}

function LinuxIcon({ className = "" }: IconProps) {
  // Generic terminal/server glyph. Tux looks weird at small sizes;
  // we don't have distro info to show Ubuntu/Debian/Arch logos
  // (would need /etc/os-release reported from the client).
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-label="Linux"
    >
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M7 9l3 3-3 3M13 15h4" />
    </svg>
  );
}

function WindowsIcon({ className = "" }: IconProps) {
  return (
    <svg className={className} {...baseProps} aria-label="Windows">
      <path d="M0 3.449L9.75 2.1V11.551H0M10.95 1.949L24 0V11.4H10.95M0 12.6H9.75V22.051L0 20.701M10.95 12.752H24V24L10.95 22.051" />
    </svg>
  );
}

function DesktopIcon({ className = "" }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" xmlns="http://www.w3.org/2000/svg">
      <rect width="20" height="14" x="2" y="3" rx="2" />
      <line x1="8" x2="16" y1="21" y2="21" />
      <line x1="12" x2="12" y1="17" y2="21" />
    </svg>
  );
}

export function DeviceIcon({
  os,
  hostname,
  ua,
  className = "",
}: {
  os?: string;
  hostname?: string;
  ua?: string;
  className?: string;
}) {
  const s = ((os || "") + " " + (hostname || "") + " " + (ua || "")).toLowerCase();
  if (/mac|darwin|os x|macbook|imac/.test(s)) return <MacIcon className={className} />;
  if (/linux|ubuntu|debian|fedora|arch|rocky|alpine|nixos/.test(s)) return <LinuxIcon className={className} />;
  if (/windows|win\b|win32/.test(s)) return <WindowsIcon className={className} />;
  return <DesktopIcon className={className} />;
}
