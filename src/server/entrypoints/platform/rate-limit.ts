// Gobierna: ADR-010 rev. 5 §5.4 (P-49, P-50; G-6, Carlos 2026-10-15), §5.2 paso 1, F-PR6-15, F-PR6-31. Limitadores EN MEMORIA del proceso platform (nada se persiste: ni la IP, ni completa ni
// truncada; la IP solo es clave de un contador que vive en RAM). Al excederse: rechazo temporal; el evento lo registra el llamador SIN IP (platform.record_limit_event), una vez por clave y ventana.
// Limitacion documentada (P-49): detras de NAT o de una VPN que haga NAT, todos los operadores comparten la IP de origen y el contador es compartido (un operador puede bloquear a los demas);
// mitigacion: clave = direccion interna que la VPN asigna a cada cliente (prefijo /32), configurable con CNS_PLATFORM_P49_IPV4_PREFIX. P-48 es el limite principal de identidad.
// Tambien: allowlist de origen (CIDR) configurable. La restriccion "solo red privada/VPN en staging" es de INFRAESTRUCTURA (firewall del host); esto es defensa en profundidad, no la reemplaza.

import { isIP } from "node:net";

export interface LimiterDecision {
  readonly allowed: boolean;
  /** true solo en la primera denegacion de una clave dentro de su ventana (el llamador registra UN evento). */
  readonly firstDenial: boolean;
}

export interface SlidingLimiter {
  hit(key: string): LimiterDecision;
  /** Cantidad de claves vivas (tests / tope de memoria). */
  size(): number;
}

/** Contador de ventana deslizante por clave. maxKeys acota la memoria: al llegar al tope se purgan las claves vencidas y, si sigue lleno, se deniega (fail-closed). */
export function createSlidingLimiter(options: { max: number; windowMs: number; now?: () => number; maxKeys?: number }): SlidingLimiter {
  const { max, windowMs } = options;
  if (!Number.isSafeInteger(max) || max < 1 || !Number.isSafeInteger(windowMs) || windowMs < 1) throw new Error("limitador: max y windowMs deben ser enteros positivos");
  const now = options.now ?? Date.now;
  const maxKeys = options.maxKeys ?? 100_000;
  const hits = new Map<string, { times: number[]; denied: boolean }>();
  const prune = (t: number): void => {
    for (const [k, v] of hits) {
      const fresh = v.times.filter((x) => x > t - windowMs);
      if (fresh.length === 0) hits.delete(k);
      else v.times = fresh;
    }
  };
  return {
    hit(key: string): LimiterDecision {
      const t = now();
      let entry = hits.get(key);
      if (entry === undefined) {
        if (hits.size >= maxKeys) prune(t);
        if (hits.size >= maxKeys) return { allowed: false, firstDenial: false };
        entry = { times: [], denied: false };
        hits.set(key, entry);
      }
      entry.times = entry.times.filter((x) => x > t - windowMs);
      if (entry.times.length >= max) {
        const first = !entry.denied;
        entry.denied = true;
        return { allowed: false, firstDenial: first };
      }
      entry.denied = false;
      entry.times.push(t);
      return { allowed: true, firstDenial: false };
    },
    size: () => hits.size,
  };
}

/** Clave de P-49: IPv4 truncada al prefijo (default /24) e IPv6 a /48; solo en memoria. */
export function truncateIp(address: string, ipv4Prefix = 24, ipv6Prefix = 48): string {
  const mapped = address.startsWith("::ffff:") && isIP(address.slice(7)) === 4 ? address.slice(7) : address;
  if (isIP(mapped) === 4) {
    const n = mapped.split(".").reduce((acc, o) => (acc << 8n) | BigInt(Number(o)), 0n);
    const masked = ipv4Prefix === 0 ? 0n : (n >> BigInt(32 - ipv4Prefix)) << BigInt(32 - ipv4Prefix);
    return `v4:${masked}/${ipv4Prefix}`;
  }
  if (isIP(mapped) === 6) {
    const n = ipv6ToBigInt(mapped);
    const masked = ipv6Prefix === 0 ? 0n : (n >> BigInt(128 - ipv6Prefix)) << BigInt(128 - ipv6Prefix);
    return `v6:${masked}/${ipv6Prefix}`;
  }
  return "unknown";
}

function ipv6ToBigInt(address: string): bigint {
  const [head = "", tail] = address.split("::");
  const h = head === "" ? [] : head.split(":");
  const t = tail === undefined || tail === "" ? [] : tail.split(":");
  const groups = tail === undefined ? h : [...h, ...Array<string>(8 - h.length - t.length).fill("0"), ...t];
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g === "" ? "0" : g, 16)), 0n);
}

export interface Cidr { readonly family: 4 | 6; readonly base: bigint; readonly prefix: number }

export function parseCidr(text: string): Cidr {
  const [addr = "", pfx] = text.trim().split("/");
  const family = isIP(addr);
  if (family !== 4 && family !== 6) throw new Error(`CIDR invalido: ${text}`);
  const bits = family === 4 ? 32 : 128;
  const prefix = pfx === undefined ? bits : Number(pfx);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) throw new Error(`CIDR invalido: ${text}`);
  const n = family === 4 ? addr.split(".").reduce((acc, o) => (acc << 8n) | BigInt(Number(o)), 0n) : ipv6ToBigInt(addr);
  const shift = BigInt(bits - prefix);
  return { family, base: (n >> shift) << shift, prefix };
}

export function ipInCidrs(address: string, cidrs: readonly Cidr[]): boolean {
  const mapped = address.startsWith("::ffff:") && isIP(address.slice(7)) === 4 ? address.slice(7) : address;
  const family = isIP(mapped);
  if (family !== 4 && family !== 6) return false;
  const bits = family === 4 ? 32 : 128;
  const n = family === 4 ? mapped.split(".").reduce((acc, o) => (acc << 8n) | BigInt(Number(o)), 0n) : ipv6ToBigInt(mapped);
  return cidrs.some((c) => {
    if (c.family !== family) return false;
    const shift = BigInt(bits - c.prefix);
    return (n >> shift) << shift === c.base;
  });
}
