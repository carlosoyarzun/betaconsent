import { GuestHeader } from "./components/guest-header.tsx";
import { matchRoute, readPageState, usePathname } from "./router.ts";
import { ROUTES } from "./routes.ts";

export function App() {
  const pathname = usePathname();
  const route = matchRoute(ROUTES, pathname);
  const pageState = readPageState();
  return (
    <>
      <GuestHeader />
      {route ? (
        <route.Page pageState={pageState} />
      ) : (
        <main className="lp-page-container" aria-labelledby="notfound-h1">
          <h1 id="notfound-h1">Página no encontrada</h1>
        </main>
      )}
    </>
  );
}
