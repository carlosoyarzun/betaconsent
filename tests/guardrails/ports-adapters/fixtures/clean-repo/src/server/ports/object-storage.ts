export interface ObjectStorage {
  put(key: string, body: Uint8Array): Promise<void>;
}
