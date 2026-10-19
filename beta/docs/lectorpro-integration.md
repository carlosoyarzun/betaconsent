# Integración de LectorPro con la API de autorización (API-CNS-001)

Gobierna: plan v2 H1-08; DEC-BR-022 rev. 2. Contrato: `beta/contracts/lectorpro-authorization.openapi.yaml`.

- **Cliente de referencia**: `beta/src/client/lectorpro-authorization-client.ts` (TS puro, sin dependencias). `isAuthorized(studentRef)` devuelve `boolean`.
- **Cuándo llamar**: antes de iniciar CADA lectura (DEC-BR-022 (b)). No cachear el resultado entre lecturas ni entre estudiantes. Sin "ventana de gracia".
- **Fail-closed (c)**: cualquier error, timeout (3 s), 401, 429, 503 o respuesta mal formada devuelve `false`: la lectura NO empieza. El cliente emite un evento
  de log sin PII (`authorization_denied_fail_closed` con un código de motivo); no registre el `studentRef` junto con el secreto ni la firma.
- **Un estudiante desconocido** responde `NOT_AUTHORIZED` (200), igual que declinado o revocado: LectorPro no puede inferir existencia.
- **Firma `hmac-v1`**: cabeceras `X-CNS-Key-Id`, `X-CNS-Timestamp` (unix s, ±60 s: sincronizar el reloj por NTP), `X-CNS-Nonce` (16+ bytes aleatorios
  base64url, uno nuevo por llamada) y `X-CNS-Signature` = base64url(HMAC-SHA256(secreto, `GET\n<path>\n<ts>\n<nonce>\nSHA256(cuerpo vacío en hex)`)).
- **Rotación de claves** (`CNS_API_KEYS=keyId:secreto[,keyId2:secreto2]`, secreto de >= 32 bytes, base64/base64url): (1) Consent App activa la clave nueva junto a la
  vieja; (2) LectorPro cambia a la nueva (`keyId` nuevo); (3) se retira la vieja y deja de aceptarse (401). El secreto solo vive en variables de entorno, nunca en logs ni repos.
- **Rate limit**: 60 solicitudes por minuto por `keyId` (429). Una consulta por lectura iniciada debe bastar.
- **Revocación durante una lectura ya activa**: este contrato solo cubre el INICIO de lectura. Qué hacer con una lectura en curso cuando el apoderado revoca
  (opción A o B de DEC-BR-022 §5) es **decisión de Carlos** y no está implementada ni asumida aquí.
