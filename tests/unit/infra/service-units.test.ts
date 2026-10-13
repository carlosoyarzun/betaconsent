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
