export class AESError extends Error {
  statusCode: number;
  customErrorCode: string;
  static defaultStatusCode = 400;

  constructor({
    message,
    statusCode = AESError.defaultStatusCode,
    customErrorCode = 'UNKNOWN_ERROR',
    name = 'Custom Error',
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

    // Ensures that the stack trace is properly set in V8-based environments
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}
