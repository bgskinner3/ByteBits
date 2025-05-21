export class KaloError extends Error {
  statusCode: number;
  customErrorCode: string;
  static defaultStatusCode = 400;

  constructor({
    message,
    statusCode = KaloError.defaultStatusCode,
    customErrorCode = 'UNKNOWN_ERROR',
    name = 'KaloError',
  }: {
    message: string;
    statusCode?: number;
    customErrorCode?: string;
    name?: string;
  }) {
    super(message);
    this.statusCode = statusCode;
    this.customErrorCode = customErrorCode;
    this.name = name;

    // This ensures the stack trace is correctly set in V8-based environments (Node.js)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  static MissingEnvVars(): KaloError {
    return new KaloError({
      message: 'Missing required env vars: KALO_SALT and/or KALO_NONCE',
      customErrorCode: 'AES_KEY_MISSING',
      name: 'KALO-AES Encryption Error',
    });
  }

  static InvalidHexParts(message?: string): KaloError {
    return new KaloError({
      message: message ?? 'Salt and Nonce hex parts must be 6 bytes',
      customErrorCode: 'AES_KEY_INVALID',
      name: 'KALO-AES Encryption Error',
    });
  }
  static InvalidMode(): KaloError {
    return new KaloError({
      message:
        'Invalid mode, please use the proper mode created with the handler',
      customErrorCode: 'KALO_MODE_INVALID',
      name: 'KALO-AES Mode Error',
    });
  }
  static InvalidPassword(): KaloError {
    return new KaloError({
      message: 'Password must be a non-empty string',
      customErrorCode: 'KALO_MODE_INVALID',
      name: 'KALO-AES Mode Error',
    });
  }
}
