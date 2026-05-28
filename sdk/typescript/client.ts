export type EvydenceClientOptions = {
  baseUrl: string;
  apiKey: string;
  fetchImpl?: typeof fetch;
};

export type CreateSSOProviderRequest = {
  name: string;
  type: "oidc" | "saml";
  issuer: string;
  client_id: string;
  groups_claim?: string;
  role_mapping?: Record<string, string>;
  jwks?: Record<string, unknown>;
};

export type VerifyProviderIdentityRequest = {
  provider_type: "oidc" | "saml";
  provider_id: string;
  subject: string;
  id_token?: string;
};

export class EvydenceClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: EvydenceClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async post<T>(path: string, idempotencyKey: string, payload: unknown): Promise<T> {
    if (!path.startsWith("/v1/") || !idempotencyKey.trim()) {
      throw new Error("invalid Evydence path or idempotency key");
    }
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        "Idempotency-Key": idempotencyKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(`Evydence request failed with status ${response.status}`);
    }
    return response.json() as Promise<T>;
  }

  async createSSOProvider<T>(
    idempotencyKey: string,
    payload: CreateSSOProviderRequest,
  ): Promise<T> {
    return this.post<T>("/v1/sso/providers", idempotencyKey, payload);
  }

  async verifyProviderIdentity<T>(
    idempotencyKey: string,
    payload: VerifyProviderIdentityRequest,
  ): Promise<T> {
    return this.post<T>("/v1/provider-verifications", idempotencyKey, payload);
  }
}
