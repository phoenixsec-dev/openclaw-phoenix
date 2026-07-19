import fs from "node:fs/promises";

// Reads a credential file through an open handle so the permission check and
// the read see the same inode (no stat/read race), enforcing: regular file,
// no group/other permission bits. Ownership is deliberately not checked:
// bind-mounted files legitimately differ in uid from the gateway process.
export async function readCredentialFile(path: string, label: string): Promise<string> {
  const handle = await fs.open(path, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) {
      throw new Error(`${label} path must be a file: ${path}`);
    }
    if ((stat.mode & 0o077) !== 0) {
      throw new Error(
        `${label} file has insecure permissions: ${path} must not be readable, writable, or executable by group or others`,
      );
    }
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}
