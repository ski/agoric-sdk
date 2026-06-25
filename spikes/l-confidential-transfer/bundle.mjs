import "@endo/init";
import bundleSource from "@endo/bundle-source";
import { writeFileSync } from "node:fs";
const entry = new URL("./confidential-transfer.contract.js", import.meta.url).pathname;
const b = await bundleSource(entry);
writeFileSync("/home/ski/zk-coreeval/ct-bundle.json", JSON.stringify(b));
console.log("moduleFormat:", b.moduleFormat);
console.log("bundleID: b1-" + b.endoZipBase64Sha512);
