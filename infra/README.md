# infra/

Infraestructura como código (despliegue, ambientes, CI/CD).

Gobierna: `API-CNS-###`, `SEC-CNS-###`.

Estado (2026-10-08): vacía. IT0 cerró como EXIT-LOCAL (Carlos, 2026-10-06/07; solo datos sintéticos) sin infraestructura provisionada; staging se difiere a IT0b. El CI vigente está en `.github/workflows/`.

## systemd/ (ADR-010 PR-6a)

Unidades de servicio como artefacto (sin deploy, sin proveedor cloud; ADR-003 host dedicado): `consent-{web,platform,worker,verifier}.service` y plantillas `*.env.example`. Un usuario de SO y un rol LOGIN de Postgres por proceso (INV-DBR-02: app_rw, platform_rw, worker, integrity_verifier); sin egress (IPAddressDeny=any; el egress del verifier espera P-45). Verificado por TEST-CNS-1400.

ADR-010 rev. 5 PR-6e (G-9, F-PR6-29): se suma `consent-reconciler.service` (Type=oneshot, rol `integrity_reconciler`, solo lectura, sin egress; exit 0 conciliado, 2 divergencias, 1 error) y `consent-reconciler.timer` (frecuencia `hourly` PENDING de Carlos). Ya son 5 unidades de proceso (web, platform, worker, verifier, reconciler). Verificado por TEST-CNS-1400.

ADR-010 rev. 5 PR-6b (G-6): el proceso `platform` exige fuera de LOCAL un bind explicito (IP concreta) y una allowlist de origen (CIDR), mas P-49..P-51 y P-53 (ver `infra/systemd/platform.env.example`). **La restriccion "solo red privada o VPN en staging" es de infraestructura (firewall del host y `IPAddressAllow` de la unidad) y NO esta implementada ni verificada en este repo**: queda como condicion previa a habilitar STAGING (datos de infraestructura de studio pendientes). P-49 detras de NAT/VPN: contador compartido (limitacion aceptada en IT0b; P-48 es el limite principal).

Supuesto de despliegue de `platform` (seguridad PR-6b): **un solo proceso y ningun proxy/balanceador delante**. P-49 (en memoria) y la allowlist de origen usan `socket.remoteAddress` y nunca `X-Forwarded-For`; con un proxy delante todo parece venir de el, y con varias instancias cada una llevaria su propio contador. Fuera de LOCAL `CNS_PLATFORM_P49_IPV4_PREFIX` es obligatorio y la allowlist no admite prefijos mas amplios que /8 (IPv4 e IPv6).

