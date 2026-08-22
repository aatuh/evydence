import type { ProblemDetails } from "./error_codes";

export type { ErrorCode, FieldViolation, ProblemDetails, RetryClass } from "./error_codes";

export type EvydenceClientOptions = {
  baseUrl: string;
  apiKey: string;
  fetchImpl?: typeof fetch;
};

export type PageMeta = {
  api_version: string;
  page_size: number;
  sort: "created_at" | "id";
  direction: "asc" | "desc";
  next_cursor?: string;
};

export type PageEnvelope<T> = {
  data: T[];
  meta: PageMeta;
};

/** Typed RFC 9457 response error. Switch on `problem.code`, not `message`. */
export class EvydenceProblemError extends Error {
  readonly problem: ProblemDetails;

  constructor(problem: ProblemDetails) {
    super(`Evydence request failed with status ${problem.status} (${problem.code})`);
    this.name = "EvydenceProblemError";
    this.problem = problem;
  }
}

export type CreateProductRequest = {
  name: string;
  slug: string;
};

export type CreateReleaseRequest = {
  product_id: string;
  version: string;
};

export type RegisterArtifactRequest = {
  name: string;
  media_type: string;
  digest: string;
  size?: number;
};

export type BuildOutput = {
  artifact_id?: string;
  digest: string;
};

export type CreateBuildRequest = {
  project_id: string;
  release_id: string;
  provider: "github_actions" | "generic";
  commit_sha: string;
  repository?: string;
  workflow_ref?: string;
  run_id?: string;
  run_attempt?: number;
  job_id?: string;
  actor?: string;
  ref?: string;
  oidc_subject?: string;
  status: "queued" | "running" | "passed" | "failed" | "cancelled";
  started_at: string;
  finished_at?: string;
  parameters_hash?: string;
  environment_hash?: string;
  provider_metadata?: Record<string, unknown>;
  outputs?: BuildOutput[];
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
  access_token?: string;
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
      throw await problemError(response);
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
      throw await problemError(response);
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

async function problemError(response: Response): Promise<EvydenceProblemError> {
  const retryAfter = Number.parseInt(response.headers.get("Retry-After") ?? "", 10);
  const fallback: ProblemDetails = {
    type: "about:blank",
    title: "Request failed",
    status: response.status,
    detail: "request failed",
    code: "INTERNAL_ERROR",
    request_id: "",
    retryable: false,
    retry_class: "none",
    ...(Number.isInteger(retryAfter) && retryAfter > 0 ? { retry_after_seconds: retryAfter } : {}),
  };
  try {
    const candidate = await response.json() as Partial<ProblemDetails>;
    if (typeof candidate.code !== "string") {
      return new EvydenceProblemError(fallback);
    }
    const problem: ProblemDetails = {
      ...fallback,
      ...candidate,
      status: response.status,
      retry_after_seconds:
        Number.isInteger(retryAfter) && retryAfter > 0
          ? retryAfter
          : typeof candidate.retry_after_seconds === "number"
            ? candidate.retry_after_seconds
            : fallback.retry_after_seconds,
    };
    return new EvydenceProblemError(problem);
  } catch {
    return new EvydenceProblemError(fallback);
  }
}
