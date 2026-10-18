import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => {
  cleanup();
  document.cookie = "__Host-cns-csrf=; Max-Age=0; Path=/; Secure";
});
