// Helpers sobre los sinks LOCAL de dev.ts (GET /__dev/*; solo existen con CNS_ENVIRONMENT=LOCAL).
// El "buzón sintético" es en memoria: no hay SMTP ni salida de red (DEC-BR-014).
// Contrato de equivalencia: la SPA se sirve desde el mismo dev.ts, por lo que estos helpers no cambian.

export interface OtpMessage { readonly channelRef: string; readonly verificationRef: string; readonly code: string }
export interface GuestMsg { readonly kind: string; readonly recipientChannelRef: string; readonly subject: string; readonly text: string; readonly html: string }

async function getJson<T>(baseURL: string, path: string): Promise<T> {
  const res = await fetch(`${baseURL}${path}`);
  if (res.status !== 200) throw new Error(`GET ${path} -> ${res.status}`);
  return (await res.json()) as T;
}

export async function readOtps(baseURL: string): Promise<OtpMessage[]> {
  return (await getJson<{ sent: OtpMessage[] }>(baseURL, "/__dev/otp-sink")).sent;
}

/** Último OTP emitido (código en claro, solo en el sink LOCAL). */
export async function readLatestOtp(baseURL: string): Promise<string> {
  const sent = await readOtps(baseURL);
  const last = sent.at(-1);
  if (!last) throw new Error("otp-sink vacío: no se ha emitido ningún OTP");
  return last.code;
}

export async function readRecoveryPaths(baseURL: string): Promise<string[]> {
  return (await getJson<{ sent: { recoveryPath: string }[] }>(baseURL, "/__dev/recovery-sink")).sent.map((m) => m.recoveryPath);
}

export async function readGuestMessages(baseURL: string): Promise<GuestMsg[]> {
  return (await getJson<{ sent: GuestMsg[] }>(baseURL, "/__dev/message-sink")).sent;
}

/** Cookie jar mínimo para el flujo STAFF (login dev -> enrollment -> invitación -> sink). */
class Jar {
  private readonly cookies = new Map<string, string>();
  absorb(res: Response): void {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = pair!.indexOf("=");
      this.cookies.set(pair!.slice(0, eq), pair!.slice(eq + 1));
    }
  }
  header(): string { return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "); }
  get(name: string): string | undefined { return this.cookies.get(name); }
}

const STAFF_ADMIN = "18c54cb1-9df4-4d4d-b371-b606e4c3b8e6"; // TENANT_ADMIN sintético (dev-local-config.ts)
const CONTEXT_REF = "BETA_2026_01";
// Alumnos sintéticos del catálogo LOCAL (dev-local-config.ts LOCAL_ONLY_DEV_STAFF_STUDENTS; refs UUIDv4, cero PII).
const STAFF_STUDENTS = [
  { subjectRef: "b7c3d1e5-2a48-4f96-8d10-6e9f0a2c4b73", participationRef: "d4f8a2c6-7b13-4e59-a8c2-0f3d5b7e9a14" },
  { subjectRef: "e74bb5c4-bc34-4f14-b773-ed7be16c7eab", participationRef: "9bd69327-dcfb-476e-b638-439f138dafe9" },
  { subjectRef: "cbd3aca8-1fd0-4ce5-aeaf-6ccf4c8d9bd4", participationRef: "3f529dbe-d674-4e2e-bda8-b8548ab5a0ed" },
  { subjectRef: "7ac9347f-c8ce-4de6-94ac-30ad4bb19c99", participationRef: "a5197e72-eee4-4784-8e2e-aa225e037977" },
  { subjectRef: "b07be7e0-88b9-4233-807c-ae6263b45aa7", participationRef: "4a54ce87-8bff-4487-8f5b-2f620867768e" },
  { subjectRef: "9467c808-e8d3-486d-a73a-87a6cfdc02ef", participationRef: "74a01146-1bf6-4d67-bffe-bd72c89332dc" },
] as const;

/**
 * Crea una invitación nueva por el flujo STAFF real (login dev -> EN0 -> I1 -> I2 -> I3) y devuelve la ruta
 * `/i/<token>` leída del invitation-sink. Hay 6 alumnos sintéticos por arranque (una invitación por alumno);
 * `student` es el índice 0..5.
 */
export async function createInvitation(baseURL: string, student = 0): Promise<string> {
  const who = STAFF_STUDENTS[student];
  if (!who) throw new Error(`alumno sintético ${student} fuera de 0..5`);
  const jar = new Jar();
  const login = await fetch(`${baseURL}/__dev/staff-login`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ principalRef: STAFF_ADMIN }),
  });
  if (login.status >= 300) throw new Error(`staff-login -> ${login.status}`);
  jar.absorb(login);
  const csrf = jar.get("__Host-cns-staff-csrf");
  if (!csrf) throw new Error("sin cookie __Host-cns-staff-csrf tras el login dev");
  const post = async (path: string, body: unknown, extra: Record<string, string> = {}): Promise<Record<string, unknown>> => {
    const res = await fetch(`${baseURL}${path}`, {
      method: "POST",
      headers: { cookie: jar.header(), origin: baseURL, "x-csrf-token": csrf, "content-type": "application/json", ...extra },
      body: JSON.stringify(body),
    });
    jar.absorb(res);
    if (res.status >= 300) throw new Error(`POST ${path} -> ${res.status}`);
    return (await res.json()) as Record<string, unknown>;
  };
  const enrollment = await post("/staff/enrollments", { subjectRef: who.subjectRef, participationRef: who.participationRef });
  const enrollmentRef = String(enrollment.enrollmentRef);
  const invitation = await post(
    "/staff/invitations",
    { subjectRef: who.subjectRef, enrollmentRef, participationRef: who.participationRef, contextRef: CONTEXT_REF },
    { "idempotency-key": `e2e-inv-${student}-${Date.now().toString(36)}-aaaa` },
  );
  const invitationRef = String(invitation.invitationRef);
  await post(`/staff/invitations/${invitationRef}/ready`, { consentVersion: "v1-dev", recipientBinding: "RECIPIENT_CHANNEL", recipientChannelRef: "staff-recipient@example.invalid" });
  await post(`/staff/invitations/${invitationRef}/send`, {});
  const sink = await getJson<{ sent: { invitationPath?: string; path?: string }[] }>(baseURL, "/__dev/invitation-sink");
  const last = sink.sent.at(-1);
  const path = last?.invitationPath ?? last?.path;
  if (!path) throw new Error("invitation-sink sin enlace");
  return path;
}
