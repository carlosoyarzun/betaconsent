import { useEffect, type RefObject } from "react";

/** Enfoca `ref.current` cada vez que `active` pasa a verdadero (o cambia `tick` mientras está activo). Equivale al `.focus()`
 * que los assets/*.js hacían justo después de mostrar un elemento (el elemento ya está visible cuando corre el efecto). */
export function useFocusWhen(ref: RefObject<HTMLElement | null>, active: boolean, tick: number = 0): void {
  useEffect(() => {
    if (active) ref.current?.focus();
  }, [ref, active, tick]);
}
