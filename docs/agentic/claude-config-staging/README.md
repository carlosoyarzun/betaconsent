# Instalación pendiente (requiere acción humana)

Los hooks y `settings.json` no pudieron instalarse automáticamente: el clasificador de
auto mode de Claude Code bloquea que la sesión modifique su propia configuración de hooks.

Instalar con:

```bash
mkdir -p .claude/hooks && cp docs/agentic/claude-config-staging/.claude/hooks/*.sh .claude/hooks/ && chmod +x .claude/hooks/*.sh && cp docs/agentic/claude-config-staging/.claude/settings.json .claude/settings.json && rm -rf docs/agentic/claude-config-staging
```

Ya instalados: `.claude/agents/*.md` (11 subagentes) y `agent/agents.yaml`.
