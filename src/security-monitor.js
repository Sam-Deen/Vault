export class SecurityMonitor {
  constructor({ windowSeconds, thresholds }) {
    this.windowSeconds = windowSeconds;
    this.thresholds = thresholds;
    this.events = new Map();
  }

  inspect(event) {
    const threshold = this.thresholds[event.event];
    if (threshold === undefined) return;
    const userId = event.userId ?? null;
    const organizationId = event.organizationId ?? null;
    const key = JSON.stringify([event.event, organizationId, userId]);
    const time = Date.parse(event.timestamp);
    const recent = (this.events.get(key) ?? []).filter(previous => time - Date.parse(previous.timestamp) < this.windowSeconds * 1000);
    recent.push({ timestamp: event.timestamp, requestId: event.requestId });
    this.events.set(key, recent);
    if (recent.length !== threshold + 1) return;
    return {
      timestamp: event.timestamp, event: 'security.alert', sourceEvent: event.event,
      userId, organizationId, count: recent.length, threshold, windowSeconds: this.windowSeconds,
      requestId: event.requestId, requestIds: recent.map(previous => previous.requestId),
    };
  }
}
