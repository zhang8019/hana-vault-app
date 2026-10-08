import { installVaultService } from "./vault-service.js";

export function serviceOf(sdk) {
  return installVaultService(sdk);
}

export function textResult(text, data) {
  return { content: [{ type: "text", text }], ...(data === undefined ? {} : { structuredContent: data }) };
}

export function secretFields(entry) {
  return ["password", "privateKey", "apiKey", "secret", "accessToken", "refreshToken", "otpSecret", "cardNumber", "cardCvv"]
    .filter((key) => entry?.[key] !== undefined && entry?.[key] !== "");
}
