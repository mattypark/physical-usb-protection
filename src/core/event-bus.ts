import type { EventOf, SentinelEvent, SentinelEventType } from './types.ts';

type AnyHandler = (event: SentinelEvent) => void;

/**
 * Typed pub/sub spine of the daemon.
 *
 * Sources, the analysis pipeline, responders, and both UIs communicate
 * exclusively through this bus — no component holds a reference to
 * another, which is what lets simulated/real layers swap freely.
 */
export class EventBus {
  private readonly handlers = new Map<SentinelEventType, Set<AnyHandler>>();
  private readonly wildcardHandlers = new Set<AnyHandler>();

  /** Subscribe to one event type. Returns an unsubscribe function. */
  on<T extends SentinelEventType>(type: T, handler: (event: EventOf<T>) => void): () => void {
    const set = this.handlers.get(type) ?? new Set<AnyHandler>();
    set.add(handler as AnyHandler);
    this.handlers.set(type, set);
    return () => set.delete(handler as AnyHandler);
  }

  /** Subscribe to every event (used by UIs and the ws broadcaster). */
  onAny(handler: AnyHandler): () => void {
    this.wildcardHandlers.add(handler);
    return () => this.wildcardHandlers.delete(handler);
  }

  emit(event: SentinelEvent): void {
    for (const handler of this.handlers.get(event.type) ?? []) {
      this.dispatch(handler, event);
    }
    for (const handler of this.wildcardHandlers) {
      this.dispatch(handler, event);
    }
  }

  /** Convenience for the ubiquitous log event. */
  log(level: 'info' | 'warn' | 'alert', message: string): void {
    this.emit({ type: 'daemon:log', level, message });
  }

  private dispatch(handler: AnyHandler, event: SentinelEvent): void {
    try {
      handler(event);
    } catch (error) {
      // A broken subscriber must never take down the daemon or
      // starve other subscribers of events.
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[event-bus] handler failed on ${event.type}: ${message}`);
    }
  }
}
