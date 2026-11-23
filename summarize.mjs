import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";

const tmp = process.env.RUNNER_TEMP;
const readAdvisories = (name) => {
  const audit = JSON.parse(readFileSync(`${tmp}/${name}.json`, "utf8"));
  if (audit.error) {
    throw new Error(`pnpm audit failed (${name}): ${audit.error.message}`);
  }
  return audit.advisories;
};
const group = (pairs) => {
  const map = new Map();
  for (const [name, version] of pairs) {
    map.set(name, (map.get(name) ?? new Set()).add(version));
  }
  return map;
};
const installedVersions = (names) =>
  group(names.length ? JSON.parse(execFileSync("pnpm", ["why", ...names, "--json"])).map((p) => [p.name, p.version]) : []);

const before = readAdvisories("before");
const snapshotPath = `${tmp}/installed-before.json`;
if (process.argv[2] === "snapshot") {
  const names = [...new Set(Object.values(before).map((a) => a.module_name))];
  const snapshot = [...installedVersions(names)].map(([name, versions]) => [name, [...versions]]);
  writeFileSync(snapshotPath, JSON.stringify(snapshot));
  process.exit();
}

const after = readAdvisories("after");
const resolved = Object.values(before).filter((a) => !(a.id in after));

const vulnerable = group(resolved.flatMap((a) => a.findings.map((f) => [a.module_name, f.version])));
const names = [...vulnerable.keys()];
const installedBefore = new Map(JSON.parse(readFileSync(snapshotPath, "utf8")).map(([n, v]) => [n, new Set(v)]));
const installedAfter = installedVersions(names);

const bumps = names.flatMap((name) => {
  const now = installedAfter.get(name) ?? new Set();
  const removed = [...vulnerable.get(name).difference(now)];
  const added = [...now.difference(installedBefore.get(name) ?? new Set())];
  // Empty when the fix deduped onto a version that was already installed.
  const major = (v) => v.split(".")[0];
  const to = added.length ? added : [...now].filter((v) => removed.some((r) => major(r) === major(v)));
  if (!removed.length) return [];
  return [to.length ? `Bump ${name} from ${removed.join(", ")} to ${to.join(", ")}` : `Remove ${name} ${removed.join(", ")}`];
});

const order = ["critical", "high", "moderate", "low", "info"];
const list = (advisories, detail = () => "") =>
  advisories
    .sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))
    .map((a) => `- **${a.severity}** \`${a.module_name}\`: [${a.title}](${a.url})${detail(a)}`)
    .join("\n") || "None";
const whyRemaining = (a) =>
  a.patched_versions ? ` (patched in \`${a.patched_versions}\`)` : " (no patch released)";

const count = bumps.length;
const title = count
  ? `Upgrade ${count} vulnerable ${count === 1 ? "dependency" : "dependencies"}`
  : "Ignore npm in Dependabot";
const message = `${title}\n\n${bumps.join("\n")}`.trimEnd();

writeFileSync(`${tmp}/body.md`, `## Resolved\n\n${list(resolved)}\n\n## Remaining\n\n${list(Object.values(after), whyRemaining)}\n`);
appendFileSync(process.env.GITHUB_OUTPUT, `title=${title}\ncommit-message<<MSG\n${message}\nMSG\n`);
