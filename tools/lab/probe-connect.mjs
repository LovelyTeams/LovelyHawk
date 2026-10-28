import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyhawk-backend.exe", newDataRoot());
try {
  const boot = await sidecar.call("app.bootstrap", {});
  console.log("bootstrap pages:", boot.pages.length);
  const status = await connect(sidecar, labTarget());
  console.log("connect stage:", status.stage);
  console.log("detail:", JSON.stringify(status).slice(0, 400));
} catch (error) {
  console.log("FAILED:", error.message);
  console.log("stderr:", sidecar.stderr.join("").slice(-1500));
} finally {
  sidecar.close();
}
