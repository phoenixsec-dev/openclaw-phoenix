export class PhoenixAccessDeniedError extends Error {
  readonly status = 403;
  readonly type = "access_denied" as const;
  readonly code: string;
  readonly detail: string;
  readonly remediation: string;

  constructor(params: { code: string; message: string; detail?: string; remediation: string }) {
    super(params.message);
    this.name = new.target.name;
    this.code = params.code;
    this.detail = params.detail ?? params.message;
    this.remediation = params.remediation;
  }

  toJSON() {
    return {
      type: this.type,
      status: this.status,
      error: this.message,
      code: this.code,
      detail: this.detail,
      remediation: this.remediation,
    };
  }
}
