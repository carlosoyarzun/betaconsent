import type { ObjectStorage } from "../ports/object-storage.ts";

export function saveReceipt(storage: ObjectStorage, key: string, body: Uint8Array) {
  return storage.put(key, body);
}
