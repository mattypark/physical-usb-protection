import { loadConfig } from './core/config.ts';
import { EventBus } from './core/event-bus.ts';
import type { SentinelEvent } from './core/types.ts';

const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';

const BANNER = `
${CYAN}${BOLD}  ┌─────────────────────────────────────────────┐
  │   USB EVENT SENTINEL                        │
  │   physical hardware threat interceptor      │
  └─────────────────────────────────────────────┘${RESET}
`;

function timestamp(): string {
  return new Date().toISOString().slice(11, 19);
}

function renderEvent(event: SentinelEvent): string {
  switch (event.type) {
    case 'daemon:log': {
      const color = event.level === 'alert' ? RED : event.level === 'warn' ? YELLOW : DIM;
      return `${color}[${event.level}]${RESET} ${event.message}`;
    }
    case 'device:attach':
      return `${GREEN}[attach]${RESET} ${event.device.vendorName} ${event.device.productName}`;
    case 'device:detach':
      return `${YELLOW}[detach]${RESET} ${event.device.vendorName} ${event.device.productName}`;
    case 'device:fingerprint':
      return `${CYAN}[fingerprint]${RESET} ${event.fingerprint.id}`;
    case 'fs:manifest':
      return `${CYAN}[manifest]${RESET} ${event.manifest.fileCount} files on ${event.manifest.mountPath}`;
    case 'analysis:verdict':
      return `${BOLD}[verdict]${RESET} ${event.verdict.threatLevel} (${event.verdict.analyst})`;
    case 'firewall:state':
      return `${RED}[firewall]${RESET} active=${event.state.active} enforced=${event.state.enforced}`;
  }
}

function main(): void {
  const config = loadConfig(process.argv.slice(2));
  const bus = new EventBus();

  console.log(BANNER);
  console.log(`${DIM}  mode        ${RESET}${BOLD}${config.mode}${RESET}`);
  console.log(
    `${DIM}  firewall    ${RESET}${config.firewall.enforce ? `${RED}ENFORCE (pfctl live)${RESET}` : `${GREEN}dry-run${RESET}`}`,
  );
  console.log(`${DIM}  quarantine  ${RESET}${config.firewall.quarantine ? 'on' : 'off'}`);
  console.log(`${DIM}  analyst     ${RESET}${config.analysis.preferClaude ? 'claude → heuristic fallback' : 'heuristic only'}`);
  console.log('');

  bus.onAny((event) => {
    console.log(`${DIM}${timestamp()}${RESET} ${renderEvent(event)}`);
  });

  bus.log('info', 'sentinel online — waiting for USB events');
  bus.log('info', `capture sources arrive in Stage 2 (${config.mode} mode configured)`);

  const shutdown = (): void => {
    bus.log('info', 'sentinel shutting down');
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // Keep the daemon alive; sources will own real work from Stage 2 on.
  setInterval(() => {}, 60_000);
}

main();
