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
  const line = to.length ? `Bump ${name} from ${removed.join(", ")} to ${to.join(", ")}` : `Remove ${name} ${removed.join(", ")}`;
  return [{ name, line }];
});

const order = ["critical", "high", "moderate", "low", "info"];
const bySeverity = (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity);
const list = (advisories, detail = () => "") => {
  const packages = Map.groupBy(advisories.toSorted(bySeverity), (a) => a.module_name);
  if (!packages.size) return "None";
  return [...packages]
    .map(([name, items]) => {
      const summary = `${name} (${items[0].severity}, ${items.length} ${items.length === 1 ? "advisory" : "advisories"})`;
      const lines = items.map((a) => `- [${a.title}](${a.url}) (${a.severity}${detail(a)})`).join("\n");
      return `<details>\n<summary>${summary}</summary>\n\n${lines}\n\n</details>`;
    })
    .join("\n");
};
const whyRemaining = (a) =>
  a.patched_versions ? `, patched in \`${a.patched_versions}\`` : ", no patch released";

const title =
  bumps.length === 0
    ? "Disable npm Dependabot security PRs"
    : bumps.length === 1
      ? `Upgrade vulnerable ${bumps[0].name} dependency`
      : `Upgrade ${bumps.length} vulnerable dependencies`;
const message = `${title}\n\n${bumps.map((b) => b.line).join("\n")}`.trimEnd();

const remaining = Object.values(after);
const remainingSection = remaining.length ? `\n## Remaining\n\n${list(remaining, whyRemaining)}\n` : "";
writeFileSync(`${tmp}/body.md`, `## Resolved\n\n${list(resolved)}\n${remainingSection}`);
appendFileSync(process.env.GITHUB_OUTPUT, `title=${title}\ncommit-message<<MSG\n${message}\nMSG\n`);
