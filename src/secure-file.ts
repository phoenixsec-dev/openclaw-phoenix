import fs from "node:fs/promises";
import { constants } from "node:fs";

// Reads a credential file through an open handle so the type/permission checks
// and the read see the same inode (no stat/read race). O_NONBLOCK keeps the
// open from hanging forever on a FIFO; the fstat isFile() check then rejects
// FIFOs, devices, and directories. Symlink policy: symlinks are followed
// deliberately (bind mounts and secret-management tools commonly deliver
// credentials via symlinks); all checks apply to the resolved target inode.
export async function readCredentialFile(path: string, label: string): Promise<string> {
  const handle = await fs.open(path, constants.O_RDONLY | constants.O_NONBLOCK);
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
