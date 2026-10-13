export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
  if (!response.ok) {
    let detail = `请求失败（HTTP ${response.status}）`;
    try {
      const body = await response.json();
      if (typeof body.error === "string") detail = body.error;
    } catch {
      /* Non-JSON upstream response. */
    }
    if (response.status === 401 && path !== "/api/v1/me")
      window.dispatchEvent(new Event("session-expired"));
    throw new ApiError(detail, response.status);
  }
  if (response.status === 204) return undefined as T;
  if (response.headers.get("content-type")?.includes("application/json"))
    return (await response.json()) as T;
  return (await response.text()) as T;
}
export function mutate<T>(
  path: string,
  method = "POST",
  data?: unknown,
): Promise<T> {
  return request<T>(path, {
    method,
    ...(data !== undefined ? { body: JSON.stringify(data) } : {}),
  });
}
export function errorText(error: unknown): string {
  return error instanceof Error ? error.message : "发生未知错误，请稍后重试。";
}
export function download(
  text: string,
  filename: string,
  type = "text/plain;charset=utf-8",
) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export async function copy(text: string) {
  if (!navigator.clipboard)
    throw new Error("当前浏览器无法写入剪贴板，请使用下载按钮。");
  await navigator.clipboard.writeText(text);
}
