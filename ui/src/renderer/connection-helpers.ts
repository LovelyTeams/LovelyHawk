import type {
  ConnectionExportResult,
  ConnectionImportResult,
  ConnectionSecretWrites,
  SecretWrite,
  SshAuthMethod,
} from "../shared/contract";

export interface SecretDrafts {
  password: string;
  keyPassphrase: string;
  jumpHostPassword: string;
  jumpHostKeyPassphrase: string;
  removePassword: boolean;
  removeKeyPassphrase: boolean;
  removeJumpHostPassword: boolean;
  removeJumpHostKeyPassphrase: boolean;
}

export type SecretSlot =
  | "password"
  | "keyPassphrase"
  | "jumpHostPassword"
  | "jumpHostKeyPassphrase";

export type SecretDraftAction =
  | { type: "replace"; slot: SecretSlot; value: string }
  | { type: "toggle-remove"; slot: SecretSlot }
  | { type: "clear-scope"; scope: "target" | "jump" }
  | { type: "reset" };

const removeFieldBySlot = {
  password: "removePassword",
  keyPassphrase: "removeKeyPassphrase",
  jumpHostPassword: "removeJumpHostPassword",
  jumpHostKeyPassphrase: "removeJumpHostKeyPassphrase",
} as const satisfies Record<SecretSlot, keyof SecretDrafts>;

export function emptySecretDrafts(): SecretDrafts {
  return {
    password: "",
    keyPassphrase: "",
    jumpHostPassword: "",
    jumpHostKeyPassphrase: "",
    removePassword: false,
    removeKeyPassphrase: false,
    removeJumpHostPassword: false,
    removeJumpHostKeyPassphrase: false,
  };
}

export function secretDraftReducer(
  state: SecretDrafts,
  action: SecretDraftAction,
): SecretDrafts {
  if (action.type === "reset") return emptySecretDrafts();
  if (action.type === "clear-scope") {
    return action.scope === "target"
      ? {
          ...state,
          password: "",
          keyPassphrase: "",
          removePassword: false,
          removeKeyPassphrase: false,
        }
      : {
          ...state,
          jumpHostPassword: "",
          jumpHostKeyPassphrase: "",
          removeJumpHostPassword: false,
          removeJumpHostKeyPassphrase: false,
        };
  }

  const removeField = removeFieldBySlot[action.slot];
  if (action.type === "replace") {
    return {
      ...state,
      [action.slot]: action.value,
      [removeField]: false,
    };
  }

  const remove = !state[removeField];
  return {
    ...state,
    [action.slot]: remove ? "" : state[action.slot],
    [removeField]: remove,
  };
}

export function resolveSecretWrite(value: string, remove: boolean): SecretWrite {
  if (remove) return { action: "remove" };
  return value === "" ? { action: "keep" } : { action: "replace", value };
}

export function connectionSecretWrites(
  selection: {
    authMethod: SshAuthMethod;
    jumpEnabled: boolean;
    jumpAuthMethod: SshAuthMethod;
  },
  secrets: SecretDrafts,
): ConnectionSecretWrites {
  const targetUsesPassword = selection.authMethod === "password";
  const targetUsesKeyPassphrase = usesPrivateKey(selection.authMethod);
  const jumpUsesPassword =
    selection.jumpEnabled && selection.jumpAuthMethod === "password";
  const jumpUsesKeyPassphrase =
    selection.jumpEnabled && usesPrivateKey(selection.jumpAuthMethod);

  return {
    password: targetUsesPassword
      ? resolveSecretWrite(secrets.password, secrets.removePassword)
      : { action: "remove" },
    keyPassphrase: targetUsesKeyPassphrase
      ? resolveSecretWrite(secrets.keyPassphrase, secrets.removeKeyPassphrase)
      : { action: "remove" },
    jumpHostPassword: jumpUsesPassword
      ? resolveSecretWrite(
          secrets.jumpHostPassword,
          secrets.removeJumpHostPassword,
        )
      : { action: "remove" },
    jumpHostKeyPassphrase: jumpUsesKeyPassphrase
      ? resolveSecretWrite(
          secrets.jumpHostKeyPassphrase,
          secrets.removeJumpHostKeyPassphrase,
        )
      : { action: "remove" },
  };
}

export function parseConnectionTags(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[,，]/u)
        .map((tag) => tag.trim())
        .filter(Boolean),
    ),
  ];
}

export function nextFocusIndex(
  currentIndex: number,
  itemCount: number,
  reverse: boolean,
): number | null {
  if (itemCount < 1) return null;
  if (currentIndex < 0) return reverse ? itemCount - 1 : 0;
  return (currentIndex + (reverse ? itemCount - 1 : 1)) % itemCount;
}

export function connectionImportNotice(result: ConnectionImportResult): string {
  if (result.cancelled) return "连接导入已取消。";
  return `连接导入完成：导入 ${result.imported}，跳过已有 ${result.skippedExisting}，跳过文件内重复 ${result.skippedDuplicate}。`;
}

export function connectionExportNotice(result: ConnectionExportResult): string {
  if (result.cancelled) return "连接导出已取消。";
  return `已导出 ${result.count} 个连接到 ${result.fileName ?? "JSON 文件"}。`;
}

function usesPrivateKey(method: SshAuthMethod): boolean {
  return method === "public-key" || method === "certificate";
}
