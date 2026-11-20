/**
 * Per-tenant fair-share scheduler. Each tenant may run at most `perTenant` jobs concurrently and the
 * pool at most `global`; waiting jobs are dispatched round-robin across tenants so one tenant's
 * backlog cannot starve the others.
 */
export class FairShareScheduler {
  private active = new Map<string, number>();
  private totalActive = 0;
  private queues = new Map<string, Array<() => void>>();
  private order: string[] = [];

  constructor(private readonly perTenant: number, private readonly global: number = Number.POSITIVE_INFINITY) {
    if (perTenant < 1) throw new Error('perTenant must be >= 1');
  }

  async run<T>(tenantId: string, fn: () => Promise<T>): Promise<T> {
    await this.acquire(tenantId);
    try {
      return await fn();
    } finally {
      this.release(tenantId);
    }
  }

  private canStart(t: string): boolean {
    return (this.active.get(t) ?? 0) < this.perTenant && this.totalActive < this.global;
  }

  private start(t: string): void {
    this.active.set(t, (this.active.get(t) ?? 0) + 1);
    this.totalActive++;
  }

  private acquire(t: string): Promise<void> {
    if (this.canStart(t) && !this.queues.get(t)?.length) {
      this.start(t);
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      let q = this.queues.get(t);
      if (!q) this.queues.set(t, (q = []));
      if (!this.order.includes(t)) this.order.push(t);
      q.push(resolve);
    });
  }

  private release(t: string): void {
    this.active.set(t, (this.active.get(t) ?? 1) - 1);
    this.totalActive--;
    this.drain();
  }

  private drain(): void {
    let progressed = true;
    while (progressed && this.totalActive < this.global) {
      progressed = false;
      for (let i = 0; i < this.order.length; ) {
        const t = this.order[i];
        const q = this.queues.get(t);
        if (!q?.length) {
          this.queues.delete(t);
          this.order.splice(i, 1);
          continue;
        }
        if (this.totalActive < this.global && this.canStart(t)) {
          this.start(t);
          q.shift()!();
          progressed = true;
          // Served tenant goes to the back so the next free slot is offered to others first.
          this.order.splice(i, 1);
          this.order.push(t);
          continue;
        }
        i++;
      }
    }
  }

  stats(): { active: number; queued: number } {
    let queued = 0;
    for (const q of this.queues.values()) queued += q.length;
    return { active: this.totalActive, queued };
  }
}
