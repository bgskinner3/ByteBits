export class ChaCha20Error extends Error {
  statusCode: number;
  customErrorCode: string;
  static defaultStatusCode = 400;

  constructor({
    message,
    statusCode = ChaCha20Error.defaultStatusCode,
    customErrorCode = 'UNKNOWN_ERROR',
    name = 'ChaCha20Error',
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

  static CoreConstructorError(message: string): ChaCha20Error {
    return new ChaCha20Error({
      message: message,
      customErrorCode: 'CORE_CONSTRUCTOR_ERROR',
      name: 'CoreConstructorError',
    });
  }
  static CounterError(message?: string): ChaCha20Error {
    return new ChaCha20Error({
      message:
        message ??
        'Counter has exceeded its maximum value or is invalid. Re-keying is required.',
      customErrorCode: 'CTR_COUNTER_ERROR',
      name: 'CounterError',
    });
  }
}
