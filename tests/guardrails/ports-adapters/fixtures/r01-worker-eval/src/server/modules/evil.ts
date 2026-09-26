import { Worker } from "node:worker_threads";
new Worker("require('nodemailer')", { eval: true });
