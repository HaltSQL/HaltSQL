// Marks dist/cjs as CommonJS so Node loads it with require() even though the
// package itself is "type": "module".
import { writeFileSync } from "node:fs";
writeFileSync(
  new URL("../dist/cjs/package.json", import.meta.url),
  JSON.stringify({ type: "commonjs" }) + "\n",
);
