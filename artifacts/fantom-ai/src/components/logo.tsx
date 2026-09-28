/**
 * fantom.ai brand mark: an asymmetric "squircle" (three rounded corners, one
 * near-sharp) with a faint offset echo behind it, suggesting a phantom
 * presence that leaves a trace as it becomes visible — plus a small signal
 * dot marking the point where a risk surfaces. Colour comes from
 * `currentColor` so the mark adapts to whichever surface it sits on; the
 * signal dot stays fixed to the brand's teal accent.
 */
const SQUIRCLE_PATH = 'M12 4H20A8 8 0 0 1 28 12V20A8 8 0 0 1 20 28H6A2 2 0 0 1 4 26V12A8 8 0 0 1 12 4Z';

type MarkProps = { size?: number; className?: string; echo?: boolean };

export function FantomMark({ size = 29, className, echo = true }: MarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      className={className}
      role="img"
      aria-label="fantom.ai"
    >
      {echo && (
        <path
          d={SQUIRCLE_PATH}
          transform="translate(-3 -3)"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.4}
          opacity={0.35}
        />
      )}
      <path d={SQUIRCLE_PATH} fill="currentColor" />
      <circle cx={25.5} cy={8} r={2.2} fill="var(--teal)" />
    </svg>
  );
}

export function FantomLogo({ className }: { className?: string }) {
  return (
    <div className={className ? `brand ${className}` : 'brand'}>
      <FantomMark className="brand-mark" />
      <span>
        fantom<span style={{ color: 'var(--teal)' }}>.ai</span>
      </span>
    </div>
  );
}
