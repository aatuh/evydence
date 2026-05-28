export type EvydenceClientOptions = {
  baseUrl: string;
  apiKey: string;
  fetchImpl?: typeof fetch;
};

export type CreateProductRequest = {
  name: string;
  slug: string;
};

export type CreateReleaseRequest = {
  product_id: string;
  project_id?: string;
  version: string;
};

export type RegisterArtifactRequest = {
  release_id?: string;
  name?: string;
  media_type?: string;
  digest: string;
  size?: number;
};

export type BuildOutput = {
  artifact_id?: string;
  digest: string;
  name?: string;
};

export type CreateBuildRequest = {
  project_id: string;
  release_id: string;
  provider: "github_actions" | "generic";
  commit_sha: string;
  status: "queued" | "running" | "passed" | "failed" | "cancelled";
  started_at: string;
  outputs?: BuildOutput[];
  github?: Record<string, unknown>;
};

export type CreateSSOProviderRequest = {
  name: string;
  type: "oidc" | "saml";
  issuer: string;
  client_id: string;
  groups_claim?: string;
  role_mapping?: Record<string, string>;
  jwks?: Record<string, unknown>;
  saml_signing_certificates?: string[];
};

export type VerifyProviderIdentityRequest = {
  provider_type: "oidc" | "saml";
  provider_id: string;
  subject: string;
  id_token?: string;
  saml_assertion?: string;
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

  async get<T>(path: string): Promise<T> {
    if (!path.startsWith("/v1/")) {
      throw new Error("invalid Evydence path");
    }
    const headers: Record<string, string> = {};
    if (this.apiKey.trim()) {
      headers["Authorization"] = `Bearer ${this.apiKey.trim()}`;
    }
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "GET",
      headers,
    });
    if (!response.ok) {
      throw new Error(`Evydence request failed with status ${response.status}`);
    }
    return response.json() as Promise<T>;
  }

  async createProduct<T>(
    idempotencyKey: string,
    payload: CreateProductRequest,
  ): Promise<T> {
    return this.post<T>("/v1/products", idempotencyKey, payload);
  }

  async createRelease<T>(
    idempotencyKey: string,
    payload: CreateReleaseRequest,
  ): Promise<T> {
    return this.post<T>("/v1/releases", idempotencyKey, payload);
  }

  async registerArtifact<T>(
    idempotencyKey: string,
    payload: RegisterArtifactRequest,
  ): Promise<T> {
    return this.post<T>("/v1/artifacts", idempotencyKey, payload);
  }

  async createBuild<T>(
    idempotencyKey: string,
    payload: CreateBuildRequest,
  ): Promise<T> {
    return this.post<T>("/v1/builds", idempotencyKey, payload);
  }

  async readiness<T>(): Promise<T> {
    return this.get<T>("/v1/ready");
  }

  async releaseReadiness<T>(releaseId: string): Promise<T> {
    return this.get<T>(`/v1/reports/release-readiness?release_id=${encodeURIComponent(releaseId)}`);
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
