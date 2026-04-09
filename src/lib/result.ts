export type FetchError =
  | { type: 'rate_limited'; retry_after: number }
  | { type: 'not_found'; reason: 'no_contract' | 'wrong_chain' }
  | { type: 'invalid_chain'; supported: number[] }
  | { type: 'timeout'; retryable: boolean }
  | { type: 'api_error'; code: string; message: string }
  | { type: 'network_error'; message: string };

export type Result<T, E = FetchError> =
  | { ok: true; data: T; cached: boolean }
  | { ok: false; error: E };

export function ok<T>(data: T, cached = false): Result<T, never> {
  return { ok: true, data, cached };
}

export function err<E = FetchError>(error: E): Result<never, E> {
  return { ok: false, error };
}

export function isOk<T, E>(result: Result<T, E>): result is { ok: true; data: T; cached: boolean } {
  return result.ok === true;
}

export function isErr<T, E>(result: Result<T, E>): result is { ok: false; error: E } {
  return result.ok === false;
}
