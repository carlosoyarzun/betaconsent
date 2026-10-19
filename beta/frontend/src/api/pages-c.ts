// Gobierna: ADR-001 F1 (fase C). Llamadas de /manage/verify, /manage/revocation/verify, /manage/revocation/confirm y
// /recovery/confirm; equivalen a los postJson de assets/{verify,revocation,recovery}.js (mismo método, ruta, cabeceras
// y cuerpo). Todo pasa por `postJson` (CSRF double-submit); aquí no hay fetch directo ni estado.
import { postJson, type ApiResult } from "./client.ts";

export interface OtpSubmitBody { readonly code?: string; readonly result?: string; readonly scope?: string }
export interface RevocationConfirmBody { readonly revocationRef?: string }
export interface RecoveryRevokeBody { readonly state?: string; readonly revocationRef?: string; readonly result?: string }

/** V3 (POST /otp/submit): `{ code }`. */
export const submitOtp = (code: string): Promise<ApiResult<OtpSubmitBody>> => postJson<OtpSubmitBody>("/otp/submit", { code });
/** V1 repetido (POST /otp/request): "Solicitar nuevo código" (GRD-OT-08). */
export const requestOtp = (): Promise<ApiResult<unknown>> => postJson("/otp/request");
/** V2r (POST /otp/resend). */
export const resendOtp = (): Promise<ApiResult<unknown>> => postJson("/otp/resend");
/** RV0 fuente BEARER (POST /manage/recovery-link, API-CNS-134): sin canal en el cuerpo (GRD-RV-17). */
export const sendRecoveryLink = (): Promise<ApiResult<unknown>> => postJson("/manage/recovery-link");
/** R2 (POST /manage/revocation/verify), idempotente si ya VERIFIED. */
export const verifyRevocation = (): Promise<ApiResult<unknown>> => postJson("/manage/revocation/verify");
/** R3 + R4 (POST /manage/revocation/confirm). */
export const confirmRevocation = (): Promise<ApiResult<RevocationConfirmBody>> => postJson<RevocationConfirmBody>("/manage/revocation/confirm");
/** R8 (POST /manage/revocation/withdraw). */
export const withdrawRevocation = (): Promise<ApiResult<unknown>> => postJson("/manage/revocation/withdraw");
/** API-CNS-135 (POST /recovery/revoke): R1r+R2r+R3r, R10+R3r o R11 NOOP; decide el servidor. */
export const recoveryRevoke = (): Promise<ApiResult<RecoveryRevokeBody>> => postJson<RecoveryRevokeBody>("/recovery/revoke", { confirmTotalWithdrawal: true });
