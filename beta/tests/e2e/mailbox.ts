// Gobierna: plan v2 H1-11. Buzón de correo del E2E: Mailpit real si MAILPIT_SMTP_URL y MAILPIT_API_URL están definidas (CI);
// si no, un receptor SMTP mínimo en el propio test (el proceso real usa igualmente SmtpMailer/nodemailer sobre TCP; no se toca main.ts).
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";

export interface Mail {
  readonly to: string;
  readonly subject: string;
  readonly text: string;
}

export interface Mailbox {
  readonly kind: "mailpit" | "smtp-sink";
  readonly smtpUrl: string;
  /** Todos los correos recibidos en orden cronológico. */
  list(): Promise<Mail[]>;
  clear(): Promise<void>;
  close(): Promise<void>;
}

function decodeQuotedPrintable(s: string): Buffer {
  const joined = s.replace(/=\r?\n/g, "");
  const bytes: number[] = [];
  for (let i = 0; i < joined.length; i += 1) {
    const c = joined[i]!;
    if (c === "=" && /^[0-9A-Fa-f]{2}$/.test(joined.slice(i + 1, i + 3))) {
      bytes.push(parseInt(joined.slice(i + 1, i + 3), 16));
      i += 2;
    } else bytes.push(...Buffer.from(c, "utf8"));
  }
  return Buffer.from(bytes);
}

function decodeBody(body: string, encoding: string): string {
  const enc = encoding.trim().toLowerCase();
  if (enc === "quoted-printable") return decodeQuotedPrintable(body).toString("utf8");
  if (enc === "base64") return Buffer.from(body.replace(/\s+/g, ""), "base64").toString("utf8");
  return body;
}

function splitHeaders(raw: string): { headers: Map<string, string>; body: string } {
  const idx = raw.search(/\r?\n\r?\n/);
  const head = idx === -1 ? raw : raw.slice(0, idx);
  const body = idx === -1 ? "" : raw.slice(idx).replace(/^\r?\n\r?\n/, "");
  const headers = new Map<string, string>();
  for (const line of head.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/)) {
    const c = line.indexOf(":");
    if (c > 0) headers.set(line.slice(0, c).toLowerCase(), line.slice(c + 1).trim());
  }
  return { headers, body };
}

function decodeWords(v: string): string {
  // RFC 2047: el espacio entre palabras codificadas adyacentes se descarta; se decodifica después.
  return v
    .replace(/(\?=)\s+(=\?UTF-8\?[BQbq]\?)/g, "$1$2")
    .replace(/=\?UTF-8\?([BQbq])\?([^?]*)\?=/g, (_m, kind: string, data: string) =>
      kind.toUpperCase() === "B" ? Buffer.from(data, "base64").toString("utf8") : decodeQuotedPrintable(data.replace(/_/g, " ")).toString("utf8"),
    );
}

function textOf(raw: string): string {
  const { headers, body } = splitHeaders(raw);
  const ct = headers.get("content-type") ?? "text/plain";
  const boundary = /boundary="?([^";]+)"?/i.exec(ct)?.[1];
  if (boundary !== undefined) {
    for (const part of body.split(`--${boundary}`)) {
      const t = textOf(part.replace(/^\r?\n/, ""));
      if (t !== "") return t;
    }
    return "";
  }
  if (!/^text\/plain/i.test(ct)) return "";
  return decodeBody(body, headers.get("content-transfer-encoding") ?? "7bit");
}

function parseMessage(raw: string, rcpt: string): Mail {
  const { headers } = splitHeaders(raw);
  return { to: rcpt.toLowerCase(), subject: decodeWords(headers.get("subject") ?? ""), text: textOf(raw) };
}

async function startSink(): Promise<Mailbox> {
  const mails: Mail[] = [];
  const sockets = new Set<Socket>();
  const server: Server = createServer((sock) => {
    sockets.add(sock);
    sock.on("close", () => sockets.delete(sock));
    sock.on("error", () => undefined);
    let buf = "";
    let data = false;
    let rcpt = "";
    sock.write("220 sink ESMTP\r\n");
    sock.on("data", (d: Buffer) => {
      buf += d.toString("latin1");
      for (;;) {
        if (data) {
          const end = buf.indexOf("\r\n.\r\n");
          if (end === -1) return;
          const raw = Buffer.from(buf.slice(0, end), "latin1").toString("utf8");
          buf = buf.slice(end + 5);
          data = false;
          mails.push(parseMessage(raw, rcpt));
          sock.write("250 2.0.0 queued\r\n");
          continue;
        }
        const nl = buf.indexOf("\r\n");
        if (nl === -1) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === "EHLO") sock.write("250-sink\r\n250 8BITMIME\r\n");
        else if (cmd === "HELO") sock.write("250 sink\r\n");
        else if (cmd === "MAIL") sock.write("250 ok\r\n");
        else if (cmd === "RCPT") {
          rcpt = /<([^>]*)>/.exec(line)?.[1] ?? "";
          sock.write("250 ok\r\n");
        } else if (cmd === "DATA") {
          data = true;
          sock.write("354 go\r\n");
        } else if (cmd === "QUIT") {
          sock.end("221 bye\r\n");
        } else if (cmd === "RSET" || cmd === "NOOP") sock.write("250 ok\r\n");
        else sock.write("502 unsupported\r\n");
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  return {
    kind: "smtp-sink",
    smtpUrl: `smtp://127.0.0.1:${port}`,
    list: async () => [...mails],
    clear: async () => void (mails.length = 0),
    close: async () => {
      for (const s of sockets) s.destroy();
      await new Promise((r) => server.close(r));
    },
  };
}

function mailpit(smtpUrl: string, api: string): Mailbox {
  const cache = new Map<string, Mail>();
  return {
    kind: "mailpit",
    smtpUrl,
    async list() {
      const res = (await (await fetch(`${api}/api/v1/messages?limit=500`)).json()) as { messages: { ID: string; Subject: string; To: { Address: string }[]; Created: string }[] };
      const sorted = [...res.messages].sort((a, b) => a.Created.localeCompare(b.Created));
      const out: Mail[] = [];
      for (const m of sorted) {
        let mail = cache.get(m.ID);
        if (!mail) {
          const full = (await (await fetch(`${api}/api/v1/message/${m.ID}`)).json()) as { Text: string };
          mail = { to: (m.To[0]?.Address ?? "").toLowerCase(), subject: m.Subject, text: full.Text };
          cache.set(m.ID, mail);
        }
        out.push(mail);
      }
      return out;
    },
    async clear() {
      cache.clear();
      await fetch(`${api}/api/v1/messages`, { method: "DELETE" });
    },
    close: async () => undefined,
  };
}

export async function openMailbox(): Promise<Mailbox> {
  const smtp = process.env.MAILPIT_SMTP_URL;
  const api = process.env.MAILPIT_API_URL;
  if (smtp && api) {
    const box = mailpit(smtp, api);
    await box.clear();
    return box;
  }
  return startSink();
}
