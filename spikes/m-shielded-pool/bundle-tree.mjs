import "@endo/init";
import bundleSource from "@endo/bundle-source";
import { writeFileSync } from "node:fs";
const entry = new URL("./shielded-pool-tree.contract.js", import.meta.url).pathname;
const b = await bundleSource(entry);
writeFileSync("/home/ski/zk-coreeval/tree-bundle.json", JSON.stringify(b));
console.log("bundleID: b1-" + b.endoZipBase64Sha512);
