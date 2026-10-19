// origen: src/server/entrypoints/http/guest-messages.ts@9345b78 (textos, marcadores legales y estructura de tablas/estilos inline)
// Copy de TODAS las plantillas: BORRADOR. El copy legal final es LEGAL DECISION de Carlos (no se redacta aquí).

export const DRAFT_MARK = "BORRADOR";
export const STUDY_NAME = "Estudio Beta de LectorPro";
export const RECEIPT_WATERMARK = "BORRADOR · datos sintéticos";
export const RECEIPT_NO_LINK_NOTE =
  "Este mensaje no incluye el enlace para gestionar tu decisión: ese enlace se envía solo a este mismo correo, en un mensaje aparte.";
export const LEGAL_HOW_TO_REVOKE = "[LEGAL DECISION — cómo retirar tu consentimiento: copy pendiente de aprobación de Carlos]";
export const LEGAL_HOW_TO_EXERCISE_RIGHTS = "[LEGAL DECISION — cómo ejercer tus derechos: copy pendiente de aprobación de Carlos]";
export const LEGAL_INVITATION_BODY = "[LEGAL DECISION — texto de la invitación y del aviso de privacidad: copy pendiente de aprobación de Carlos]";

// Asuntos: fijos, sin nombre ni correo del destinatario (ni del estudiante).
export const SUBJECTS = {
  invitation: `[${DRAFT_MARK}] Invitación al ${STUDY_NAME}`,
  otp: `[${DRAFT_MARK}] Tu código de verificación — ${STUDY_NAME}`,
  receipt_granted: `[${DRAFT_MARK}] Comprobante de tu decisión — ${STUDY_NAME}`,
  receipt_declined: `[${DRAFT_MARK}] Comprobante de tu decisión — ${STUDY_NAME}`,
  receipt_revoked: `[${DRAFT_MARK}] Comprobante de retiro de consentimiento — ${STUDY_NAME}`,
  management_link: `[${DRAFT_MARK}] Enlace para gestionar tu decisión — ${STUDY_NAME}`,
} as const;
