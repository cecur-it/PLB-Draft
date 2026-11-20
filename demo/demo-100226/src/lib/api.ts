export class ApiError extends Error {
  public status: number;
  public data: any;

  constructor(status: number, message: string, data?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

export function getStoredToken(): string | null {
  return localStorage.getItem('cecur_soc_token');
}

export function setStoredToken(token: string) {
  localStorage.setItem('cecur_soc_token', token);
}

export function clearStoredToken() {
  localStorage.removeItem('cecur_soc_token');
}

export async function apiRequest<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };
  const method = (options.method || 'GET').toUpperCase();
  const requestLabel = `${method} ${endpoint.split('?')[0]}`;

  let response: Response;
  try {
    response = await fetch(endpoint, {
      ...options,
      headers,
    });
  } catch (error: any) {
    throw new Error(`${requestLabel}: ${error?.message || 'Network request failed'}`, { cause: error });
  }

  const isJson = response.headers.get('content-type')?.includes('application/json');
  const data = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    const message = data?.message || data?.error || `HTTP Error ${response.status}`;
    throw new ApiError(
      response.status,
      `${requestLabel}: ${message}`,
      data
    );
  }

  return data as T;
}
