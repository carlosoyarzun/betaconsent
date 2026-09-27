export async function loadS3() {
  const mod = await import("@aws-sdk/client-s3");
  return mod;
}
