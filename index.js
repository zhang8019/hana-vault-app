import { defineApp } from "./sdk/app-contract/server-client.js";
import { installVaultService } from "./lib/vault-service.js";
import { registerVaultRoutes } from "./lib/routes.js";
import { registerVaultTools } from "./lib/tools.js";


export const name = "hana-vault";

export default defineApp(async (sdk) => {
  const service = installVaultService(sdk);
  await sdk.logger.info("hana-vault v2 ready; secrets are never stored in App configuration");
  await sdk.routes.register((app) => registerVaultRoutes(app, service, sdk));
  await registerVaultTools(sdk, service);
  return async () => service.shutdown();
});
