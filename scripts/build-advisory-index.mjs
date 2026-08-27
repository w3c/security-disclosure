#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const API_ROOT = "https://api.github.com";
const W3C_REPOSITORY_INVENTORY_URL = "https://w3c.github.io/groups/repositories.json";
const DEFAULT_OUTPUT = "advisories/index.html";
const CONCURRENCY = 8;
const REPOSITORY_TYPE_ORDER = [
  "rec-track",
  "note",
  "registry",
  "cg-report",
  "tests",
  "tool",
  "process",
  "workshop",
  "homepage",
  "translation",
  "article",
  "project",
  "others",
  "unclassified",
];

const args = parseArguments(process.argv.slice(2));
const token = process.env.GITHUB_TOKEN?.trim();
const headers = {
  Accept: "application/vnd.github+json",
  "User-Agent": "w3c-security-disclosure-advisory-index",
  "X-GitHub-Api-Version": "2022-11-28",
};

if (token) {
  headers.Authorization = `Bearer ${token}`;
}

const repositories = args.repositories.length
  ? args.repositories.map(normalizeRepository)
  : await listW3CGroupRepositories();

if (args.inventoryOnly) {
  console.log(JSON.stringify({ repositories: repositories.length }));
  process.exit(0);
}

const advisoryGroups = await mapWithConcurrency(
  repositories,
  CONCURRENCY,
  listPublishedAdvisories,
);
const publishedAdvisories = advisoryGroups
  .flat()
  .filter(isPublishedAdvisory);

const repositoryTypes = new Map(
  await mapWithConcurrency(
    [...new Map(publishedAdvisories.map(advisory => [advisory.repository, advisory])).values()],
    CONCURRENCY,
    async advisory => [
      advisory.repository,
      await getRepositoryTypes(advisory.repository, advisory.compiledRepositoryTypes),
    ],
  ),
);
const advisories = publishedAdvisories
  .map(advisory => normalizeAdvisory(advisory, repositoryTypes.get(advisory.repository)))
  .sort((left, right) => {
    const dateOrder = right.publishedAt.localeCompare(left.publishedAt);
    return dateOrder || left.repository.localeCompare(right.repository) || left.ghsaId.localeCompare(right.ghsaId);
  });

if (advisories.length === 0) {
  throw new Error("No published advisories were returned; refusing to replace the existing index.");
}

const outputPath = resolve(args.output);
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, renderPage(advisories), "utf8");
console.log(`Wrote ${advisories.length} published ${advisories.length === 1 ? "advisory" : "advisories"} to ${outputPath}`);

function parseArguments(values) {
  const parsed = { output: DEFAULT_OUTPUT, repositories: [], inventoryOnly: false };

  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === "--output") {
      parsed.output = requireValue(values, ++index, "--output");
    } else if (value === "--repository") {
      parsed.repositories.push(requireValue(values, ++index, "--repository"));
    } else if (value === "--inventory-only") {
      parsed.inventoryOnly = true;
    } else {
      throw new Error(`Unknown argument: ${value}`);
    }
  }

  return parsed;
}

function requireValue(values, index, option) {
  const value = values[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${option} requires a value.`);
  }
  return value;
}

function normalizeRepository(value) {
  const fullName = value.includes("/") ? value : `w3c/${value}`;
  const [owner, name, ...rest] = fullName.split("/");
  if (rest.length || !/^[A-Za-z0-9._-]+$/.test(owner) || !/^[A-Za-z0-9._-]+$/.test(name)) {
    throw new Error(`Repository must use the GitHub <owner>/<name> format: ${value}`);
  }
  return { name, full_name: `${owner}/${name}`, private: false, compiledRepositoryTypes: [] };
}

async function listW3CGroupRepositories() {
  const response = await fetch(W3C_REPOSITORY_INVENTORY_URL, {
    headers: {
      Accept: "application/json",
      "User-Agent": "w3c-security-disclosure-advisory-index",
    },
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    throw new Error(`W3C repository inventory request failed (${response.status}).`);
  }
  const inventory = await response.json();
  if (!Array.isArray(inventory) || inventory.length === 0) {
    throw new Error("W3C repository inventory returned an unexpected response.");
  }

  return inventory
    .filter(entry =>
      entry?.isPrivate === false &&
      entry?.w3cjson?.exposed !== false &&
      normalizeStringValues(entry?.w3cjson?.group).length > 0
    )
    .map(entry => parseGitHubRepositoryUrl(entry.url, entry.w3cjson?.["repo-type"]))
    .filter(Boolean);
}

function parseGitHubRepositoryUrl(value, repositoryTypes) {
  try {
    const url = new URL(value);
    const parts = url.pathname.replace(/\.git$/i, "").split("/").filter(Boolean);
    if (url.hostname.toLowerCase() !== "github.com" || parts.length !== 2) return null;
    const [owner, name] = parts;
    if (!/^[A-Za-z0-9._-]+$/.test(owner) || !/^[A-Za-z0-9._-]+$/.test(name)) return null;
    return {
      name,
      full_name: `${owner}/${name}`,
      private: false,
      compiledRepositoryTypes: normalizeRepositoryTypes(repositoryTypes),
    };
  } catch {
    return null;
  }
}

async function listPublishedAdvisories(repository) {
  const [owner, name] = repository.full_name.split("/");
  const url = new URL(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/security-advisories`, API_ROOT);
  url.searchParams.set("state", "published");
  url.searchParams.set("per_page", "100");
  const advisories = await fetchAll(url, { allowNotFound: true });
  return advisories.map(advisory => ({
    ...advisory,
    repository: repository.full_name,
    compiledRepositoryTypes: repository.compiledRepositoryTypes,
  }));
}

async function getRepositoryTypes(repository, compiledRepositoryTypes = []) {
  const [owner, name] = repository.split("/");
  const url = new URL(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/contents/w3c.json`, API_ROOT);
  const file = await fetchOne(url, { allowNotFound: true });
  if (!file || file.type !== "file" || file.encoding !== "base64" || typeof file.content !== "string") {
    return normalizeRepositoryTypes(compiledRepositoryTypes);
  }

  try {
    const metadata = JSON.parse(Buffer.from(file.content.replaceAll("\n", ""), "base64").toString("utf8"));
    return normalizeRepositoryTypes(metadata["repo-type"]);
  } catch {
    return normalizeRepositoryTypes(compiledRepositoryTypes);
  }
}

function normalizeRepositoryTypes(value) {
  const values = Array.isArray(value) ? value : [value];
  return [...new Set(values
    .filter(item => typeof item === "string")
    .map(item => item.trim().toLowerCase())
    .filter(item => /^[a-z0-9][a-z0-9-]{0,63}$/.test(item)))];
}

function normalizeStringValues(value) {
  return (Array.isArray(value) ? value : [value])
    .filter(item => typeof item === "string" && item.trim());
}

async function fetchAll(initialUrl, { allowNotFound = false } = {}) {
  const results = [];
  let url = initialUrl.toString();

  while (url) {
    assertGitHubApiOrigin(url);
    const response = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
    if (allowNotFound && response.status === 404) {
      return [];
    }
    if (!response.ok) {
      const rateLimitRemaining = response.headers.get("x-ratelimit-remaining");
      throw new Error(`GitHub API request failed (${response.status}) for ${url}; rate-limit remaining: ${rateLimitRemaining ?? "unknown"}.`);
    }

    const page = await response.json();
    if (!Array.isArray(page)) {
      throw new Error(`GitHub API returned an unexpected response for ${url}.`);
    }
    results.push(...page);
    url = nextLink(response.headers.get("link"));
  }

  return results;
}

async function fetchOne(initialUrl, { allowNotFound = false } = {}) {
  const url = initialUrl.toString();
  assertGitHubApiOrigin(url);
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
  if (allowNotFound && response.status === 404) return null;
  if (!response.ok) {
    const rateLimitRemaining = response.headers.get("x-ratelimit-remaining");
    throw new Error(`GitHub API request failed (${response.status}) for ${url}; rate-limit remaining: ${rateLimitRemaining ?? "unknown"}.`);
  }
  return response.json();
}

function assertGitHubApiOrigin(url) {
  if (new URL(url).origin !== new URL(API_ROOT).origin) {
    throw new Error(`Refusing to send GitHub API headers to an unexpected origin: ${url}`);
  }
}

function nextLink(linkHeader) {
  if (!linkHeader) return "";
  for (const part of linkHeader.split(",")) {
    const match = part.match(/^\s*<([^>]+)>;\s*rel="([^"]+)"\s*$/);
    if (match?.[2] === "next") return match[1];
  }
  return "";
}

async function mapWithConcurrency(values, concurrency, callback) {
  const output = new Array(values.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < values.length) {
      const index = nextIndex;
      nextIndex += 1;
      output[index] = await callback(values[index]);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, worker));
  return output;
}

function isPublishedAdvisory(advisory) {
  return advisory?.state === "published" && typeof advisory.published_at === "string";
}

function normalizeAdvisory(advisory, repositoryTypes) {
  const ghsaId = /^GHSA-[A-Za-z0-9-]+$/.test(advisory.ghsa_id) ? advisory.ghsa_id : "";
  if (!ghsaId) {
    throw new Error(`Published advisory in ${advisory.repository} has an invalid GHSA identifier.`);
  }

  const cveId = /^CVE-\d{4}-\d{4,}$/.test(advisory.cve_id ?? "") ? advisory.cve_id : "";
  const severity = ["low", "moderate", "high", "critical"].includes(advisory.severity)
    ? advisory.severity
    : "unknown";

  return {
    repository: advisory.repository,
    summary: String(advisory.summary || "Published security advisory").trim(),
    ghsaId,
    cveId,
    severity,
    repositoryTypes: repositoryTypes?.length ? repositoryTypes : ["unclassified"],
    publishedAt: advisory.published_at,
    url: `https://github.com/${advisory.repository}/security/advisories/${ghsaId}`,
  };
}

function renderPage(advisories) {
  const latestPublishedDate = advisories[0].publishedAt.slice(0, 10);
  const repositoryTypes = [...new Set(advisories.flatMap(advisory => advisory.repositoryTypes))]
    .sort(compareRepositoryTypes);
  const tables = repositoryTypes
    .map(repositoryType => renderAdvisoryTable(
      repositoryType,
      advisories.filter(advisory => advisory.repositoryTypes.includes(repositoryType)),
    ))
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Published Security Advisories for W3C Group Repositories</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; line-height: 1.5; }
    body { margin: 0; }
    main { box-sizing: border-box; max-width: 72rem; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
    h1 { line-height: 1.15; }
    .lede { max-width: 52rem; }
    .meta { color: #555; }
    h2 { margin-top: 2.5rem; }
    table { width: 100%; margin-top: 1rem; border-collapse: collapse; }
    caption { margin-bottom: .75rem; font-weight: 600; text-align: left; }
    th, td { padding: .75rem; border-bottom: 1px solid #bbb; text-align: left; vertical-align: top; }
    th { white-space: nowrap; }
    .severity { font-weight: 600; text-transform: capitalize; }
    .identifier { white-space: nowrap; }
    @media (prefers-color-scheme: dark) { .meta { color: #bbb; } th, td { border-color: #555; } }
    @media (max-width: 48rem) { .table-wrap { overflow-x: auto; } th, td { min-width: 7rem; } .summary { min-width: 18rem; } }
  </style>
</head>
<body>
  <main>
    <h1>Published Security Advisories for W3C Group Repositories</h1>
    <p class="lede">This index contains published security advisories for public repositories associated with W3C groups in the <a href="https://w3c.github.io/groups/repositories.json">W3C group repository inventory</a>.</p>
    <p class="lede">The <a href="../">W3C Vulnerability Disclosure Program</a> covers design vulnerabilities and security issues described in W3C specifications. Its <a href="../#out-of-scope">scope and application</a> separately routes implementation and tooling issues to the relevant maintainer, and vulnerabilities in W3C infrastructure and services to the <a href="https://www.openbugbounty.org/bugbounty/w3c_systeam/">W3C Systems vulnerability disclosure policy</a>.</p>
    <p class="meta">Newest advisory publication date: <time datetime="${escapeHtml(latestPublishedDate)}">${escapeHtml(formatDate(latestPublishedDate))}</time>. This page is regenerated daily from W3C repository metadata and GitHub's public repository security-advisory data.</p>
${tables}
  </main>
</body>
</html>
`;
}

function compareRepositoryTypes(left, right) {
  const leftIndex = REPOSITORY_TYPE_ORDER.indexOf(left);
  const rightIndex = REPOSITORY_TYPE_ORDER.indexOf(right);
  if (left === "unclassified") return right === "unclassified" ? 0 : 1;
  if (right === "unclassified") return -1;
  if (leftIndex === -1 && rightIndex === -1) return left.localeCompare(right);
  if (leftIndex === -1) return REPOSITORY_TYPE_ORDER.length - 1;
  if (rightIndex === -1) return 1 - REPOSITORY_TYPE_ORDER.length;
  return leftIndex - rightIndex;
}

function renderAdvisoryTable(repositoryType, advisories) {
  const rows = advisories.length
    ? advisories.map(renderAdvisory).join("\n")
    : "          <tr><td colspan=\"5\">No published advisories in this category.</td></tr>";
  const explanation = repositoryType === "unclassified"
    ? "Repositories for which no repo-type value was available in w3c.json metadata."
    : `Repositories whose w3c.json declares the repo-type ${repositoryType}.`;
  return `    <section>
      <h2>Repository type: <code>${escapeHtml(repositoryType)}</code></h2>
      <p class="lede">${escapeHtml(explanation)}</p>
      <div class="table-wrap">
        <table>
          <caption>${advisories.length} published ${advisories.length === 1 ? "advisory" : "advisories"}</caption>
          <thead><tr><th scope="col">Published</th><th scope="col">Repository</th><th scope="col">Advisory</th><th scope="col">Severity</th><th scope="col">Identifier</th></tr></thead>
          <tbody>
${rows}
          </tbody>
        </table>
      </div>
    </section>`;
}

function renderAdvisory(advisory) {
  const date = advisory.publishedAt.slice(0, 10);
  const repositoryUrl = `https://github.com/${advisory.repository}`;
  const identifier = advisory.cveId
    ? `${escapeHtml(advisory.ghsaId)}<br>${escapeHtml(advisory.cveId)}`
    : escapeHtml(advisory.ghsaId);

  return `          <tr>
            <td><time datetime="${escapeHtml(date)}">${escapeHtml(formatDate(date))}</time></td>
            <td><a href="${escapeHtml(repositoryUrl)}">${escapeHtml(advisory.repository)}</a></td>
            <td class="summary"><a href="${escapeHtml(advisory.url)}">${escapeHtml(advisory.summary)}</a></td>
            <td class="severity">${escapeHtml(advisory.severity)}</td>
            <td class="identifier">${identifier}</td>
          </tr>`;
}

function formatDate(date) {
  return new Intl.DateTimeFormat("en", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  }).format(new Date(`${date}T00:00:00Z`));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
