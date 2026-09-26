import module from "node:module";
const sdkModule = module.createRequire(import.meta.url)("aws-sdk/clients/s3");
export { sdkModule };
