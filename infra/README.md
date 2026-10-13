# infra/

Infraestructura como código (despliegue, ambientes, CI/CD).

Gobierna: `API-CNS-###`, `SEC-CNS-###`.

Estado (2026-10-08): vacía. IT0 cerró como EXIT-LOCAL (Carlos, 2026-10-06/07; solo datos sintéticos) sin infraestructura provisionada; staging se difiere a IT0b. El CI vigente está en `.github/workflows/`.

## systemd/ (ADR-010 PR-6a)

Unidades de servicio como artefacto (sin deploy, sin proveedor cloud; ADR-003 host dedicado): `consent-{web,platform,worker,verifier}.service` y plantillas `*.env.example`. Un usuario de SO y un rol LOGIN de Postgres por proceso (INV-DBR-02: app_rw, platform_rw, worker, integrity_verifier); sin egress (IPAddressDeny=any; el egress del verifier espera P-45). Verificado por TEST-CNS-1400.
