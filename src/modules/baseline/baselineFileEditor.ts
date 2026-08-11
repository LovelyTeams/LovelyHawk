export function validateEditableRemotePath(path: string): string {
  const value = path.trim();
  if (!value || value.length > 4096 || !value.startsWith('/') || value.includes('\0') || /[\r\n]/.test(value)) {
    throw new Error('文件路径必须是合法的 Linux 绝对路径');
  }
  if (value === '/' || value.endsWith('/') || value.split('/').includes('..')) {
    throw new Error('文件路径不能是目录或包含上级目录跳转');
  }
  return value;
}

export function buildEditorBackupPath(path: string, timestamp = Date.now()): string {
  const validated = validateEditableRemotePath(path);
  return `${validated}.lovelyres.bak.${timestamp}`;
}

export async function contentSha256(content: string): Promise<string> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('当前运行环境不支持 WebCrypto，无法验证配置文件内容');
  }
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}
