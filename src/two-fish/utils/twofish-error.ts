/* istanbul ignore next */
export class TwoFishError extends Error {
  statusCode: number;
  customErrorCode: string;
  static defaultStatusCode = 400;

  constructor({
    message,
    statusCode = TwoFishError.defaultStatusCode,
    customErrorCode = 'UNKNOWN_ERROR',
    name = 'TwoFishError',
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
}
