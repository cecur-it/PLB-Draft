export function resolveTrustProxyHops(value = process.env.CS3_TRUST_PROXY_HOPS): number {
  if (value === undefined || value.trim() === '') return 0;
  const hops = Number(value);
  if (!Number.isInteger(hops) || hops < 0 || hops > 5) {
    throw new Error('CS3_TRUST_PROXY_HOPS must be an integer between 0 and 5');
  }
  return hops;
}
