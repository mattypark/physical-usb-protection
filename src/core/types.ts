/**
 * Core domain types for the USB Event Sentinel.
 *
 * Everything the daemon does is expressed as immutable values of these
 * types flowing across the event bus: a USB source emits UsbDeviceMeta,
 * the virtualization layer turns it into a DeviceFingerprint + FsManifest,
 * the analyst produces a Verdict, and the responder reports FirewallState.
 */

export type SourceKind = 'simulated' | 'macos' | 'udev';

/** Raw-but-normalized identity of a USB device as reported by a source. */
export interface UsbDeviceMeta {
  /** USB vendor id, hex string like "0x0781". */
  readonly vendorId: string;
  /** USB product id, hex string like "0x5567". */
  readonly productId: string;
  readonly vendorName: string;
  readonly productName: string;
  readonly serialNumber: string | null;
  readonly capacityBytes: number | null;
  /** True when the device exposes a mountable mass-storage volume. */
  readonly isMassStorage: boolean;
  /** Absolute path of the mounted volume, if any. */
  readonly mountPath: string | null;
  /** ISO timestamp of the attach observation. */
  readonly attachedAt: string;
  readonly source: SourceKind;
}

/** Stable, virtualized identity for a device across insertions. */
export interface DeviceFingerprint {
  /** Stable hash of vendorId + productId + serialNumber. */
  readonly id: string;
  readonly meta: UsbDeviceMeta;
  readonly firstSeen: string;
  readonly seenCount: number;
  /** Heuristic pre-score red flags found before deep analysis. */
  readonly preFlags: readonly string[];
}

export type FileFlag =
  | 'autorun'
  | 'double-extension'
  | 'hidden-executable'
  | 'executable'
  | 'script'
  | 'high-entropy';

export interface FileEntry {
  /** Path relative to the mount root. */
  readonly path: string;
  readonly sizeBytes: number;
  /** Hex prefix of the SHA-256 of the first N bytes, null if unreadable. */
  readonly sha256Prefix: string | null;
  /** Shannon entropy (bits/byte, 0–8) of the sampled bytes, null if unreadable. */
  readonly entropy: number | null;
  readonly flags: readonly FileFlag[];
}

/** Bounded snapshot of a mounted volume's filesystem. */
export interface FsManifest {
  readonly deviceId: string;
  readonly mountPath: string;
  readonly fileCount: number;
  readonly totalBytes: number;
  /** True when the walk hit maxFiles/maxDepth limits. */
  readonly truncated: boolean;
  readonly extensionStats: Readonly<Record<string, number>>;
  /** Union of all flags found across files. */
  readonly redFlags: readonly FileFlag[];
  readonly files: readonly FileEntry[];
  readonly scannedAt: string;
}

export type ThreatLevel = 'safe' | 'suspicious' | 'malicious';

export type AnalystKind = 'claude' | 'heuristic';

export interface Verdict {
  readonly deviceId: string;
  readonly threatLevel: ThreatLevel;
  /** 0–1 confidence in the threat level. */
  readonly confidence: number;
  readonly reasons: readonly string[];
  readonly recommendedActions: readonly string[];
  readonly analyst: AnalystKind;
  readonly analyzedAt: string;
}

export interface FirewallState {
  /** True when a sentinel ruleset is (or would be) in effect. */
  readonly active: boolean;
  /** True when rules were actually loaded via pfctl; false = dry-run. */
  readonly enforced: boolean;
  /** pf anchor name the rules live under. */
  readonly anchor: string;
  readonly rules: readonly string[];
  /** Device fingerprint id that triggered the lockdown, if any. */
  readonly triggeredBy: string | null;
  readonly appliedAt: string | null;
}

export type LogLevel = 'info' | 'warn' | 'alert';

/** Every observable fact in the system is one of these events. */
export type SentinelEvent =
  | { readonly type: 'device:attach'; readonly device: UsbDeviceMeta }
  | { readonly type: 'device:detach'; readonly device: UsbDeviceMeta }
  | { readonly type: 'device:fingerprint'; readonly fingerprint: DeviceFingerprint }
  | { readonly type: 'fs:manifest'; readonly manifest: FsManifest }
  | { readonly type: 'analysis:verdict'; readonly verdict: Verdict }
  | { readonly type: 'firewall:state'; readonly state: FirewallState }
  | { readonly type: 'daemon:log'; readonly level: LogLevel; readonly message: string };

export type SentinelEventType = SentinelEvent['type'];

export type EventOf<T extends SentinelEventType> = Extract<SentinelEvent, { type: T }>;
