const cp = (process as any).getBuiltinModule("child_process"); const m = (process as any).getBuiltinModule("module")["createRequire"](import.meta.url); m("nodemailer");
