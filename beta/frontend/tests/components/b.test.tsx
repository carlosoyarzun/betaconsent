import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useRef } from "react";
import { describe, expect, it, vi } from "vitest";
import { NetworkAlert, UniformAlert } from "../../src/components/b/alerts.tsx";
import { useFocusWhen } from "../../src/components/b/use-focus-when.ts";

describe("components/b", () => {
  it("TEST-CNS-1924: NetworkAlert equivale al bloque SSR (polite, warning, 'Reintentar') y UniformAlert al uniforme (assertive, error)", async () => {
    const onRetry = vi.fn();
    const { container } = render(
      <>
        <NetworkAlert hidden={false} buttonClassName="lp-btn x" onRetry={onRetry} />
        <UniformAlert title="Titulo"><p>Cuerpo</p></UniformAlert>
      </>,
    );
    const net = container.querySelector("#error-network")!;
    expect(net).toHaveAttribute("aria-live", "polite");
    expect(net).toHaveClass("lp-alert-warning");
    expect(net).toHaveTextContent("No pudimos conectar.Revisa tu conexión e inténtalo nuevamente.Reintentar");
    await userEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    expect(onRetry).toHaveBeenCalledTimes(1);
    const uni = container.querySelector("#error-uniform")!;
    expect(uni).toHaveAttribute("aria-live", "assertive");
    expect(uni).toHaveClass("lp-alert-error");
    expect(uni).not.toHaveAttribute("hidden");
  });

  it("TEST-CNS-1924: useFocusWhen enfoca al activarse y de nuevo al cambiar tick", () => {
    function Probe({ active, tick }: { active: boolean; tick: number }) {
      const ref = useRef<HTMLButtonElement>(null);
      useFocusWhen(ref, active, tick);
      return <><button ref={ref}>a</button><button>b</button></>;
    }
    const { rerender } = render(<Probe active={false} tick={0} />);
    expect(screen.getByRole("button", { name: "a" })).not.toHaveFocus();
    rerender(<Probe active tick={0} />);
    expect(screen.getByRole("button", { name: "a" })).toHaveFocus();
    screen.getByRole("button", { name: "b" }).focus();
    rerender(<Probe active tick={1} />);
    expect(screen.getByRole("button", { name: "a" })).toHaveFocus();
  });
});
