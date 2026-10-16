// Gobierna: ADR-010 rev. 4 §7 fila PR-6 ("unidades en infra/ (ADR-003); pools por rol"), INV-DBR-02, ADR-003 rev. 7 (host dedicado, sin proveedor cloud; sin deploy).
// TEST-CNS-1400: las unidades de servicio de infra/systemd/ son un ARTEFACTO coherente: un usuario de SO por proceso (distintos), una EnvironmentFile por proceso, ExecStart al entrypoint
// de ese proceso, rol de Postgres de la plantilla = rol del proceso (INV-DBR-02), endurecimiento minimo, sin salidas a internet (IPAddressDeny=any), sin proveedor cloud ni secretos.

import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { RUNTIME_PROCESS_ROLES } from "../../../src/infra/adapters/postgres/runtime-process.ts";
import type { RuntimeProcess } from "../../../src/infra/adapters/postgres/runtime-process.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PROCESSES = Object.keys(RUNTIME_PROCESS_ROLES) as RuntimeProcess[];
const read = (rel: string): string => readFileSync(join(ROOT, rel), "utf8");
const directive = (text: string, key: string): string | undefined => new RegExp(`^${key}=(.*)$`, "m").exec(text)?.[1]?.trim();

test("TEST-CNS-1400 infra/systemd: una unidad por proceso con usuario de SO propio, EnvironmentFile propia y ExecStart al entrypoint de su proceso", () => {
  const users = new Set<string>();
  const envFiles = new Set<string>();
  for (const p of PROCESSES) {
    const unit = `infra/systemd/consent-${p}.service`;
    assert.ok(existsSync(join(ROOT, unit)), `${unit} existe`);
    assert.ok(existsSync(join(ROOT, `src/server/entrypoints/${p}/main.ts`)), `entrypoint de ${p}`);
    const text = read(unit);
    const user = directive(text, "User");
    assert.equal(user, `consent-${p}`, `${p}: User`);
    assert.equal(directive(text, "Group"), user, `${p}: Group`);
    assert.equal(directive(text, "EnvironmentFile"), `/etc/consent/${p}.env`, `${p}: EnvironmentFile`);
    assert.equal(directive(text, "ExecStart"), `/usr/bin/node /opt/consent-app/src/server/entrypoints/${p}/main.ts`, `${p}: ExecStart`);
    users.add(user!);
    envFiles.add(directive(text, "EnvironmentFile")!);
  }
  assert.equal(users.size, PROCESSES.length, "un usuario de SO por proceso, todos distintos");
  assert.equal(envFiles.size, PROCESSES.length, "una EnvironmentFile por proceso");
});

test("TEST-CNS-1400 infra/systemd: endurecimiento minimo y sin salidas a internet; la plantilla de entorno de cada proceso usa SU rol de Postgres (INV-DBR-02)", () => {
  for (const p of PROCESSES) {
    const text = read(`infra/systemd/consent-${p}.service`);
    for (const key of ["NoNewPrivileges", "PrivateTmp", "ProtectHome", "RestrictSUIDSGID", "LockPersonality"]) assert.equal(directive(text, key), "true", `${p}: ${key}`);
    assert.equal(directive(text, "ProtectSystem"), "strict", `${p}: ProtectSystem`);
    for (const key of ["ProtectClock", "ProtectHostname", "RestrictRealtime", "RemoveIPC"]) assert.equal(directive(text, key), "true", `${p}: ${key}`);
    assert.equal(directive(text, "ProtectProc"), "invisible", `${p}: ProtectProc`);
    assert.equal(directive(text, "ProcSubset"), "pid", `${p}: ProcSubset`);
    assert.equal(directive(text, "SystemCallFilter"), "@system-service", `${p}: SystemCallFilter`);
    assert.match(text, /root:root, modo 0600/, `${p}: EnvironmentFile root:root 0600 documentado`);
    assert.equal(directive(text, "CapabilityBoundingSet"), "", `${p}: sin capacidades`);
    assert.equal(directive(text, "IPAddressDeny"), "any", `${p}: sin egress`);
    assert.equal(directive(text, "IPAddressAllow"), "localhost", `${p}: solo loopback (el egress del verifier espera P-45)`);

    const envText = read(`infra/systemd/${p}.env.example`);
    const url = directive(envText, "CNS_DATABASE_URL");
    assert.ok(url !== undefined, `${p}: CNS_DATABASE_URL en la plantilla`);
    assert.equal(new URL(url!.replace("<SECRETO>", "x").replace("<host>", "h").replace("<db>", "d")).username, RUNTIME_PROCESS_ROLES[p], `${p}: rol de la plantilla`);
    assert.ok(url!.includes("<SECRETO>"), `${p}: la plantilla no lleva credencial real`);
    assert.equal(directive(envText, "CNS_ENVIRONMENT"), "LOCAL", `${p}: IT0 solo LOCAL`);
  }
});

test("TEST-CNS-1400 infra/systemd: ni proveedor cloud ni secretos en las unidades y plantillas", () => {
  const forbidden = /\b(aws|amazon|azure|gcp|google cloud|cloudflare|digitalocean|heroku|vercel|ec2|s3:\/\/)\b/i;
  for (const p of PROCESSES) {
    for (const rel of [`infra/systemd/consent-${p}.service`, `infra/systemd/${p}.env.example`]) {
      const text = read(rel);
      assert.ok(!forbidden.test(text), `${rel}: sin proveedor cloud`);
      assert.ok(!/(password|secret|token)\s*=\s*[^<\s]/i.test(text.replace(/CNS_VERIFIER_SUB_HMAC_KEY_HEX=<[^>]*>/, "")), `${rel}: sin secretos`);
    }
  }
});

// ADR-010 rev. 6 §3 fila PR-6f (C12, C3), D-3, SEC-06-6: unidades del chain-verifier.
test("TEST-CNS-1746 infra/systemd: consent-chain-verifier.service es oneshot, sin Restart, con OnFailure a su alerta, usuario de SO propio distinto de consent-verifier, EnvironmentFile propia y sin red salvo localhost", () => {
  const text = read("infra/systemd/consent-chain-verifier.service");
  assert.equal(directive(text, "Type"), "oneshot");
  assert.equal(directive(text, "Restart"), undefined);
  assert.equal(directive(text, "SuccessExitStatus"), undefined);
  assert.equal(directive(text, "OnFailure"), "consent-chain-verifier-alert.service");
  assert.equal(directive(text, "User"), "consent-chain-verifier");
  assert.equal(directive(text, "Group"), "consent-chain-verifier");
  const verifier = read("infra/systemd/consent-verifier.service");
  assert.notEqual(directive(text, "User"), directive(verifier, "User"), "SEC-06-6: uid distinto del verifier OIDC");
  assert.equal(directive(text, "EnvironmentFile"), "/etc/consent/chain-verifier.env");
  assert.notEqual(directive(text, "EnvironmentFile"), directive(verifier, "EnvironmentFile"));
  assert.equal(directive(text, "NoNewPrivileges"), "true");
  assert.equal(directive(text, "IPAddressDeny"), "any");
  assert.equal(directive(text, "IPAddressAllow"), "localhost");
  assert.equal(directive(text, "CapabilityBoundingSet"), "");
  assert.equal(directive(text, "ExecStart"), "/usr/bin/node /opt/consent-app/src/server/entrypoints/chain-verifier/main.ts");
  const alert = read("infra/systemd/consent-chain-verifier-alert.service");
  assert.equal(directive(alert, "Type"), "oneshot");
  assert.equal(directive(alert, "User"), "consent-chain-verifier");
  assert.equal(directive(alert, "RestrictAddressFamilies"), "AF_UNIX");
  assert.equal(directive(alert, "IPAddressDeny"), "any");
});

test("TEST-CNS-1746 infra/systemd: consent-chain-verifier.timer es hourly (D-3), persistente y dispara solo su servicio", () => {
  const timer = read("infra/systemd/consent-chain-verifier.timer");
  assert.equal(directive(timer, "OnCalendar"), "hourly");
  assert.equal(directive(timer, "Persistent"), "true");
  assert.equal(directive(timer, "Unit"), "consent-chain-verifier.service");
  assert.equal(directive(timer, "WantedBy"), "timers.target");
});

test("TEST-CNS-1746 infra/systemd: chain-verifier.env.example solo activa CNS_ENVIRONMENT y CNS_DATABASE_URL (rol integrity_chain_verifier, sin credencial real); ni CNS_VERIFIER_* ni K_sub", () => {
  const env = read("infra/systemd/chain-verifier.env.example");
  const active = env.split("\n").filter((l) => l.trim() !== "" && !l.trimStart().startsWith("#"));
  assert.deepEqual(active.map((l) => l.split("=")[0]), ["CNS_ENVIRONMENT", "CNS_DATABASE_URL"]);
  assert.ok(directive(env, "CNS_DATABASE_URL")!.includes("<SECRETO>"));
  for (const l of env.split("\n").filter((x) => x.startsWith("# CNS_"))) assert.match(l, /^# CNS_CHAIN_VERIFIER_[A-Z_]+=/);
  assert.ok(!/CNS_VERIFIER_/.test(active.join("\n")));
  assert.ok(!/K_sub|SUB_HMAC|HMAC_KEY/i.test(active.join("\n")));
});

test("TEST-CNS-1756 trip-wire C3: consent-chain-verifier.service no permite nada distinto de localhost; consent-verifier.service se rige por P-45 y no se evalua aqui", () => {
  const text = read("infra/systemd/consent-chain-verifier.service");
  assert.deepEqual([...text.matchAll(/^IPAddressAllow=(.*)$/gm)].map((m) => m[1]!.trim()), ["localhost"]);
  assert.equal(directive(text, "IPAddressDeny"), "any");
  assert.ok(!/^Environment=.*PROXY/im.test(text));
  assert.ok(!/PROXY=/i.test(read("infra/systemd/chain-verifier.env.example")));
});
