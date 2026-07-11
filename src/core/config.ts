export type SentinelMode = 'simulated' | 'real';

export interface ScanLimits {
  /** Maximum directory depth walked below the mount root. */
  readonly maxDepth: number;
  /** Maximum number of files included in a manifest. */
  readonly maxFiles: number;
  /** Bytes sampled per file for hashing + entropy. */
  readonly sampleBytes: number;
}

export interface AnalysisConfig {
  /** Try the Claude Code CLI first; fall back to heuristics when absent. */
  readonly preferClaude: boolean;
  readonly timeoutMs: number;
}

export interface FirewallConfig {
  /** When false (default) rulesets are generated + logged, never applied. */
  readonly enforce: boolean;
  /** Unmount volumes that get a malicious verdict. */
  readonly quarantine: boolean;
  /** pf anchor name sentinel rules live under. */
  readonly anchor: string;
  /** Auto-revert enforced rules after this many ms even without detach. */
  readonly revertTtlMs: number;
}

export interface SentinelConfig {
  readonly mode: SentinelMode;
  readonly scan: ScanLimits;
  readonly analysis: AnalysisConfig;
  readonly firewall: FirewallConfig;
}

const DEFAULT_CONFIG: SentinelConfig = {
  mode: 'simulated',
  scan: {
    maxDepth: 6,
    maxFiles: 500,
    sampleBytes: 64 * 1024,
  },
  analysis: {
    preferClaude: true,
    timeoutMs: 90_000,
  },
  firewall: {
    enforce: false,
    quarantine: false,
    anchor: 'usb.sentinel',
    revertTtlMs: 10 * 60 * 1000,
  },
};

function flagValue(argv: readonly string[], name: string): string | null {
  const prefix = `--${name}=`;
  const match = argv.find((arg) => arg.startsWith(prefix));
  return match ? match.slice(prefix.length) : null;
}

function hasFlag(argv: readonly string[], name: string): boolean {
  return argv.includes(`--${name}`);
}

/**
 * Build the runtime config from CLI args. Fails fast on invalid input —
 * a security daemon must never guess what it was told to do.
 */
export function loadConfig(argv: readonly string[]): SentinelConfig {
  const modeArg = flagValue(argv, 'mode') ?? DEFAULT_CONFIG.mode;
  if (modeArg !== 'simulated' && modeArg !== 'real') {
    throw new Error(`Invalid --mode "${modeArg}" (expected: simulated | real)`);
  }

  return {
    ...DEFAULT_CONFIG,
    mode: modeArg,
    analysis: {
      ...DEFAULT_CONFIG.analysis,
      preferClaude: !hasFlag(argv, 'no-claude'),
    },
    firewall: {
      ...DEFAULT_CONFIG.firewall,
      enforce: hasFlag(argv, 'enforce'),
      quarantine: hasFlag(argv, 'quarantine'),
    },
  };
}
