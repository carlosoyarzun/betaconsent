// Gobierna: CA-125 (API-CNS-105/110/111/112, consola STAFF) + aprobación de Carlos 2026-10-01:
// pantalla mínima del colegio, SOLO LOCAL, para crear y enviar invitaciones sin terminal.
// Herramienta de desarrollo (no UI de producto; sin diseño Figma de staff). Gating idéntico a los
// demás /__dev/*: fuera de environment=LOCAL (o sin fixture inyectado) la ruta no existe (404).
//
// No duplica dominio: el login reutiliza handleDevStaffConsoleLogin y el envío encadena los
// handlers HTTP existentes (handleOpenEnrollment -> handleCreateInvitation -> handleMarkInvitationReady
// -> handleSendInvitation) con la sesión y el CSRF del navegador (cookie staff + campo oculto como
// cabecera double-submit). Así valida, autoriza, aplica CSRF/Origin, idempotencia y saca el
// tenant de la sesión exactamente igual que la API; el formulario NO transporta tenant.
// Limitación de dev (documentada, sin cambiar dominio): si un paso falla a mitad de la cadena (I1/I2/I3) el
// enrollment ya creado queda activo y reintentar con el mismo alumno da ENROLLMENT_ALREADY_ACTIVE (elegir otro alumno).
// La Idempotency-Key de I1 es determinista (`dev-console-${enrollmentRef}`).
// Cero PII: solo datos sintéticos; el correo del apoderado nunca se registra en logs ni se refleja.

import { DomainError } from "../../modules/common/errors.ts";
import { assertCsrfAndOrigin } from "../../modules/common/guards.ts";
import { isReservedEmail } from "../../modules/common/synthetic-recipient.ts";
import type { StaffIdentityPort } from "../../ports/staff-identity.port.ts";
import type { InvitationLinkMessage } from "../../ports/invitation-link-channel.port.ts";
import type { RightsCaseHttpConfig } from "./config.ts";
import { parseCookies } from "./cookies.ts";
import type { HttpResult, RawConsentRequest } from "./consent-flow.handler.ts";
import {
  authenticateStaffSession,
  handleCreateInvitation,
  handleDevStaffConsoleLogin,
  handleMarkInvitationReady,
  handleOpenEnrollment,
  handleSendInvitation,
  type StaffConsolePorts,
} from "./staff-console.handler.ts";
import { renderDevStaffConsolePage, type DevStaffConsoleFormView, type DevStaffConsoleView } from "./dev-staff-console-page.ts";

export const DEV_STAFF_CONSOLE_PATH = "/__dev/staff-console";

/** Datos sintéticos precargados (los del banner de dev.ts); inyectados por dev.ts/tests. */
export interface DevStaffConsoleFixture {
  readonly principalRef: string;
  /** Alumnos sintéticos seleccionables; subject y participación SIEMPRE salen de aquí, nunca del form. */
  readonly students: readonly { readonly label: string; readonly subjectRef: string; readonly participationRef: string }[];
  readonly contextRef: string;
  readonly consentVersion: string;
}

export interface DevStaffConsoleDeps {
  readonly environment: string | undefined;
  readonly fixture: DevStaffConsoleFixture | undefined;
  readonly staffIdentity: StaffIdentityPort;
  readonly staffConsole: StaffConsolePorts;
  readonly config: RightsCaseHttpConfig;
  readonly staffSessionKey: Buffer;
}

export interface DevStaffConsoleRequest {
  readonly method: string;
  readonly path: string;
  readonly originHeader: string | undefined;
  readonly cookieHeader: string | undefined;
  /** Cuerpo application/x-www-form-urlencoded ya leído (vacío en GET). */
  readonly formBody: string;
}

export interface DevStaffConsoleResponse {
  readonly status: number;
  readonly html: string;
  readonly setCookies?: readonly string[];
  readonly location?: string;
}

/** ¿Esta ruta pertenece a la consola dev? (el ruteo decide con esto; el gating real está en `handle`). */
export function isDevStaffConsolePath(path: string): boolean {
  return path === DEV_STAFF_CONSOLE_PATH || path.startsWith(`${DEV_STAFF_CONSOLE_PATH}/`);
}

const NOT_FOUND: DevStaffConsoleResponse = { status: 404, html: "" };

function page(status: number, view: DevStaffConsoleView): DevStaffConsoleResponse {
  return { status, html: renderDevStaffConsolePage(view) };
}

/** Mensaje en lenguaje claro por paso/código de error del dominio (sin reflejar datos del form). */
function describeFailure(step: "EN0" | "I1" | "I2" | "I3", result: HttpResult): string {
  const code = (result.body as { code?: unknown } | undefined)?.code;
  if (result.status === 404) return "No hay una sesión de administrador vigente, o el alumno/participación no existe en este colegio. Entra de nuevo e inténtalo otra vez.";
  if (code === "CSRF_REJECTED") return "El formulario no pasó la verificación de seguridad (CSRF/origen). Recarga la página e inténtalo de nuevo.";
  if (code === "ACTOR_NOT_ALLOWED") return "Este usuario no tiene permiso para crear invitaciones (solo administrador del colegio).";
  if (code === "ENROLLMENT_ALREADY_ACTIVE") return "Este alumno de prueba ya tiene una participación activa (ya se le creó una invitación). Elige otro alumno de la lista.";
  if (code === "INVITATION_ALREADY_ACTIVE") return "Ya existe una invitación vigente para este alumno de prueba.";
  if (code === "INVITER_NOT_PARTICIPATING" || code === "ENROLLMENT_NOT_ACTIVE" || code === "CONTEXT_NOT_ACTIVE") return "La participación del alumno de prueba no está activa o el contexto del estudio no está vigente.";
  if (step === "I2" && result.status === 422) return "El correo del apoderado fue rechazado: en esta etapa solo se aceptan correos inventados de dominio reservado (por ejemplo apoderado1@example.invalid).";
  if (code === "GUARD_EVALUATOR_UNAVAILABLE") return "La política de emisión de invitaciones no está configurada en este servidor.";
  if (result.status === 422) return "Los datos enviados no son válidos.";
  return "La operación no se pudo completar (resultado no esperado del dominio).";
}

function ok(result: HttpResult): boolean {
  return result.status >= 200 && result.status < 300;
}

export async function handleDevStaffConsole(req: DevStaffConsoleRequest, deps: DevStaffConsoleDeps, invitationSent: () => readonly InvitationLinkMessage[]): Promise<DevStaffConsoleResponse> {
  // GRD-CM-13 fail-closed: fuera de LOCAL (o sin fixture) la consola no existe.
  if (deps.environment !== "LOCAL" || !deps.fixture) return NOT_FOUND;
  const { fixture, config } = deps;
  const cookies = parseCookies(req.cookieHeader);
  const csrfCookie = cookies[config.staffCsrfCookieName];
  // CA-138: "con sesion" = sesion valida en servidor (firma, exp, no revocada, inactividad), no solo una cookie con firma correcta.
  // CA-140 (GRD-SE-08): en POST el CSRF ligado al sid se valida antes del touch (una cookie robada sin CSRF valido no prolonga la inactividad).
  const auth = await authenticateStaffSession(req.cookieHeader, deps.staffConsole, config, deps.staffSessionKey, req.method === "POST" ? { value: csrfCookie } : undefined).catch(() => null);
  const loggedIn = auth !== null && auth.ok && csrfCookie !== undefined && csrfCookie.length > 0;
  const formView = (extra: Partial<DevStaffConsoleFormView> = {}): DevStaffConsoleFormView => ({
    kind: "form",
    loggedIn,
    csrfToken: loggedIn ? (csrfCookie as string) : "",
    students: fixture.students.map((st) => ({ label: st.label, subjectRef: st.subjectRef })),
    contextRef: fixture.contextRef,
    ...extra,
  });

  if (req.method === "GET" && req.path === DEV_STAFF_CONSOLE_PATH) return page(200, formView());
  if (req.method !== "POST") return NOT_FOUND;

  const form = new URLSearchParams(req.formBody);

  if (req.path === `${DEV_STAFF_CONSOLE_PATH}/login`) {
    // Sin sesión previa no hay token CSRF: solo se exige Origin exacto (los navegadores lo envían en todo POST).
    if (req.originHeader !== config.allowedOrigin) return page(403, formView({ error: "Origen no permitido para este formulario." }));
    const loginRequest: RawConsentRequest = { originHeader: req.originHeader, csrfHeaderToken: undefined, cookieHeader: req.cookieHeader, body: { principalRef: fixture.principalRef } };
    const result = await handleDevStaffConsoleLogin(loginRequest, "LOCAL", deps.staffConsole, config, deps.staffSessionKey);
    if (result.status !== 200 || !result.setStaffSessionCookie || !result.setStaffCsrfCookie) {
      return page(422, formView({ error: "No se pudo entrar: el administrador sintético no está en el roster de este servidor." }));
    }
    return { status: 303, html: "", location: DEV_STAFF_CONSOLE_PATH, setCookies: [result.setStaffSessionCookie, result.setStaffCsrfCookie] };
  }

  if (req.path === `${DEV_STAFF_CONSOLE_PATH}/invite`) {
    const csrfField = form.get("csrf_token") ?? undefined;
    // GRD-CM-10 con el mismo guard de dominio, ANTES de cualquier otra validación o efecto.
    try {
      assertCsrfAndOrigin({ originHeader: req.originHeader, allowedOrigin: config.allowedOrigin, csrfHeaderToken: csrfField, csrfCookieToken: csrfCookie });
    } catch (err) {
      if (err instanceof DomainError && err.code === "ERR-CM-09") {
        return page(403, formView({ error: "El formulario no pasó la verificación de seguridad (CSRF/origen). Recarga la página e inténtalo de nuevo." }));
      }
      throw err;
    }
    const student = fixture.students.find((st) => st.subjectRef === form.get("student"));
    if (!student) return page(422, formView({ error: "Elige uno de los alumnos de prueba de la lista." }));
    const email = (form.get("guardian_email") ?? "").trim();
    // Pre-chequeo con la MISMA regla de dominio que I2 (isReservedEmail), para no dejar un enrollment
    // huérfano si el correo es inválido. I2 la vuelve a aplicar de forma autoritativa.
    if (email.length === 0 || email.length > 254 || !isReservedEmail(email)) {
      return page(422, formView({ selectedSubjectRef: student.subjectRef, error: "El correo del apoderado fue rechazado: en esta etapa solo se aceptan correos inventados de dominio reservado (por ejemplo apoderado1@example.invalid). No se creó ninguna invitación." }));
    }

    const base = { originHeader: req.originHeader, csrfHeaderToken: csrfField, cookieHeader: req.cookieHeader };
    const fail = (step: "EN0" | "I1" | "I2" | "I3", result: HttpResult, completed: string): DevStaffConsoleResponse => {
      const status = result.status === 404 ? 401 : result.status;
      return page(status, formView({ selectedSubjectRef: student.subjectRef, error: describeFailure(step, result), ...(completed ? { progress: completed } : {}) }));
    };

    const en0 = await handleOpenEnrollment({ ...base, body: { subjectRef: student.subjectRef, participationRef: student.participationRef } }, deps.staffConsole, config, deps.staffSessionKey);
    if (!ok(en0)) return fail("EN0", en0, "");
    const enrollmentRef = (en0.body as { enrollmentRef: string }).enrollmentRef;

    const i1 = await handleCreateInvitation(
      { ...base, idempotencyKeyHeader: `dev-console-${enrollmentRef}`, body: { subjectRef: student.subjectRef, enrollmentRef, participationRef: student.participationRef, contextRef: fixture.contextRef } },
      deps.staffConsole,
      config,
      deps.staffSessionKey,
    );
    if (!ok(i1)) return fail("I1", i1, "Participación creada (EN0).");
    const invitationRef = (i1.body as { invitationRef: string }).invitationRef;

    const i2 = await handleMarkInvitationReady(
      { ...base, body: { consentVersion: fixture.consentVersion, recipientBinding: "RECIPIENT_CHANNEL", recipientChannelRef: email } },
      invitationRef,
      deps.staffConsole,
      config,
      deps.staffSessionKey,
    );
    if (!ok(i2)) return fail("I2", i2, "Participación e invitación en borrador creadas (EN0, I1).");

    const i3 = await handleSendInvitation({ ...base, body: {} }, invitationRef, deps.staffConsole, config, deps.staffSessionKey);
    if (!ok(i3)) return fail("I3", i3, "Participación e invitación creadas y marcada lista (EN0, I1, I2).");

    const message = invitationSent().find((m) => m.invitationRef === invitationRef);
    return page(200, {
      kind: "sent",
      ...(message ? { invitationPath: message.invitationPath } : {}),
      otpSinkPath: "/__dev/otp-sink",
      consolePath: DEV_STAFF_CONSOLE_PATH,
    });
  }

  return NOT_FOUND;
}
