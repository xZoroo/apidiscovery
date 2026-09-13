import tailwindcss from "@tailwindcss/vite";
import { defineConfig, type WxtViteConfig } from "wxt";

// See https://wxt.dev/api/config.html
export default defineConfig({
  srcDir: ".",
  // Default is the hidden ".output" -- there's no reason the folder you actually load unpacked
  // into the browser needs to be a dotfile, so this keeps it a regular, visible directory.
  outDir: "output",
  vite: () => ({ plugins: [tailwindcss()] }) as WxtViteConfig,
  manifest: ({ browser }) => ({
    name: "API Discovery",
    description:
      "Passively catalogs a website's backend API calls and flags endpoints worth manual security review.",
    permissions: ["storage", "webRequest", "scripting", "tabs"],
    host_permissions: ["<all_urls>"],
    // No popup: clicking the toolbar icon opens the dashboard tab directly (background.ts's
    // action.onClicked handler). This empty object is what makes the icon clickable at all.
    action: {},
    // Least-privilege note: no "debugger" permission -- CDP body capture would show Chrome's
    // "this browser is being debugged" banner and can't coexist with the real DevTools panel
    // being open, which conflicts with continuous background capture. See plan doc for the
    // full per-permission justification.
    ...(browser === "firefox"
      ? {
          browser_specific_settings: {
            gecko: {
              id: "apidiscovery@example.invalid",
              // This extension never transmits captured data anywhere outside the local
              // browser (everything lives in IndexedDB); Firefox requires new extensions to
              // declare that explicitly as of November 2025.
              data_collection_permissions: { required: ["none"] },
            },
          },
        }
      : {}),
  }),
});
