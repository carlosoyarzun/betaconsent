import { useEffect, type RefObject } from "react";

/** Equivale al `.focus()` que los assets/*.js hacen justo después de quitar `hidden` de un bloque: se ejecuta tras el
 * commit en que `shown` pasa a true (el elemento ya no está oculto). */
export function useFocusWhen(ref: RefObject<HTMLElement | null>, shown: boolean): void {
  useEffect(() => {
    if (shown) ref.current?.focus();
  }, [ref, shown]);
}
