// Mutates a Claude profile tree the way a live machine does — a new project
// directory appearing under `projects/`, a scratch file landing inside a
// project, a session being appended to — while `listClaudeSessions` scans it.
// Every operation is best-effort: platforms disagree about removing a directory
// that is being enumerated, and a churn failure must not fail the test.
import { appendFileSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [projectsDir, projectDir, livePath, readyPath, stopPath, counterPath] = process.argv.slice(2) as [
  string,
  string,
  string,
  string,
  string,
  string,
];

const deadline = Date.now() + 60_000;
const sleepBuffer = new Int32Array(new SharedArrayBuffer(4));

function attempt(operation: () => void): void {
  try {
    operation();
  } catch {
    // A losing race with the scanner is exactly what this process is for.
  }
}

writeFileSync(readyPath, "");

for (let index = 0; !existsSync(stopPath) && Date.now() < deadline; index++) {
  const churnDir = join(projectsDir, `-churn-${index}`);
  const churnFile = join(projectDir, `churn-${index}.tmp`);
  attempt(() => mkdirSync(churnDir));
  attempt(() => writeFileSync(churnFile, "churn"));
  attempt(() => appendFileSync(livePath, `${JSON.stringify({ type: "system", churn: index })}\n`));
  attempt(() => rmSync(churnDir, { recursive: true, force: true }));
  attempt(() => rmSync(churnFile, { force: true }));
  // One byte per pass. The reader samples the size, so it never observes a
  // truncated counter no matter when it looks.
  attempt(() => appendFileSync(counterPath, "."));
  Atomics.wait(sleepBuffer, 0, 0, 1);
}
