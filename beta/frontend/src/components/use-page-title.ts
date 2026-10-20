import { useEffect } from "react";

/** Equivale al `<title>{title} · Consent App</title>` de guestHead(). */
export function usePageTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} · Consent App`;
  }, [title]);
}
