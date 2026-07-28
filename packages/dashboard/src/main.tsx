import { render } from "preact";

/// Injected by Vite `define` at build time from the `IT_BUILD_ID` environment
/// variable, or the literal "dev" when it is unset. Compared against the
/// server-reported build identifier to detect a stale console after an upgrade.
declare const __BUILD_ID__: string;

/// The application shell. Renders the header, the routed screen area, and the
/// footer. In this issue the screen area is a single build-identifier line;
/// a later issue replaces it with the router outlet.
///
/// `buildId` defaults to the `__BUILD_ID__` compile-time constant and exists only
/// so a test can supply a value, since `define` cannot be stubbed at run time.
export function Shell(props: { buildId?: string }) {
  const id = props.buildId ?? __BUILD_ID__;
  return (
    <>
      <h1>IronTraffic</h1>
      <p id="build-id">build {id}</p>
    </>
  );
}

/// Renders `<Shell />` into `#app`. When `#app` is absent, writes a named message
/// into `document.body` and returns; it never throws.
export function mount(): void {
  const root = document.getElementById("app");
  if (root === null) {
    document.body.textContent = "console failed to mount: #app is missing";
    return;
  }
  render(<Shell />, root);
}

mount();
