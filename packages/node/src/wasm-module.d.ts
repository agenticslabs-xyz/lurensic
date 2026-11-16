// Bundlers for Cloudflare Workers (wrangler, esbuild) turn a .wasm import into
// a compiled WebAssembly.Module. Only the `workerd` entry uses this.
declare module '*.wasm' {
  const module: WebAssembly.Module;
  export default module;
}
