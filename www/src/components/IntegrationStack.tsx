import { IntegrationIcon } from "./Logos";

const PRETTY: Record<string, string> = {
  claude: "Claude",
  codex: "Codex",
  github: "GitHub",
};

// Overlapping circles a la GitHub avatar stack.
export function IntegrationStack({ ids, size = 20 }: { ids: string[]; size?: number }) {
  if (!ids?.length) return <span className="text-[10px] text-[#a3a3a3]">—</span>;
  const inner = Math.round(size * 0.6);
  return (
    <div className="flex items-center">
      {ids.map((id, i) => (
        <span
          key={id}
          title={PRETTY[id] ?? id}
          className="rounded-full bg-white border border-[#e5e5e5] flex items-center justify-center overflow-hidden"
          style={{
            width: size,
            height: size,
            marginLeft: i === 0 ? 0 : -size * 0.35,
            zIndex: ids.length - i,
          }}
        >
          <span style={{ width: inner, height: inner, display: "inline-flex", color: "#171717" }}>
            <IntegrationIcon id={id} className="w-full h-full" />
          </span>
        </span>
      ))}
    </div>
  );
}
