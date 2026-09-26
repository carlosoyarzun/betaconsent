import { S3Client } from "@aws-sdk/client-s3";
import type { ObjectStorage } from "../../server/ports/object-storage.ts";

export class S3ObjectStorage implements ObjectStorage {
  private client = new S3Client({});
  async put(key: string, body: Uint8Array): Promise<void> {
    void key;
    void body;
    void this.client;
  }
}
