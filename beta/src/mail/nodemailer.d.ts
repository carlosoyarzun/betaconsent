// Declaración ambiente MÍNIMA de "nodemailer" 10.1.7 (sin @types/nodemailer; mismo criterio que src/db/pg.d.ts).
declare module "nodemailer" {
  export interface TransportOptions {
    host: string;
    port: number;
    secure: boolean;
    requireTLS?: boolean;
    ignoreTLS?: boolean;
    auth?: { user: string; pass: string };
    tls?: { minVersion?: string; servername?: string };
    connectionTimeout?: number;
    greetingTimeout?: number;
    socketTimeout?: number;
  }
  export interface MailMessage {
    from: string;
    to: string;
    subject: string;
    text: string;
    html: string;
  }
  export interface SentInfo {
    messageId?: string;
  }
  export interface Transporter {
    sendMail(message: MailMessage): Promise<SentInfo>;
    close(): void;
  }
  export function createTransport(options: TransportOptions): Transporter;
  const nodemailer: { createTransport: typeof createTransport };
  export default nodemailer;
}
