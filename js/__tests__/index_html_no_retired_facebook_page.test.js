import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

// ---------------------------------------------------------------------------
// Researcher findings #7-#11 (Ahmed, AI Hub issues #1201/#1134/#1133) trace
// their reproduction path from this site's footer social strip to the retired
// Facebook Page, whose own contact settings list dangling third-party
// profiles. The owner directed that the Page link be removed from every
// platform (2026-11-20). The Page's settings are third-party state this
// repository cannot change or verify; this test only guarantees that no
// first-party page published from this repository links to it again.
// Third-party IOC allowlists that merely name facebook.com as a benign domain
// are not links and are intentionally out of scope.
// ---------------------------------------------------------------------------

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const RETIRED_PAGE_ID = "61583373732736";
const FACEBOOK_PAGE_LINK = /href\s*=\s*["']https?:\/\/(?:(?:www|m|web)\.)?(?:facebook\.com|fb\.com|fb\.me)\//i;

const rootHtml = readdirSync(ROOT).filter((name) => name.endsWith(".html"));

test("the published homepage and every root HTML entry point are present", () => {
  assert.ok(rootHtml.includes("index.html"), "index.html must be present");
});

test("no root HTML entry point links to or embeds the retired Facebook Page", () => {
  for (const name of rootHtml) {
    const html = readFileSync(path.join(ROOT, name), "utf8");
    assert.equal(html.includes(RETIRED_PAGE_ID), false, `${name} embeds the retired Facebook Page ID`);
    assert.doesNotMatch(html, FACEBOOK_PAGE_LINK, `${name} links to a Facebook page`);
  }
});

test("the footer social strip no longer links to any retired profile and keeps its other identities", () => {
  const html = readFileSync(path.join(ROOT, "index.html"), "utf8");
  const strip = html.match(/<div class="social-strip">([\s\S]*?)<\/div>/);
  assert.ok(strip, "social strip must remain on the homepage");
  assert.match(strip[1], /bsky\.app\/profile\/cyberdudebivash\.bsky\.social/);
  assert.match(strip[1], /mastodon\.social\/@cyberdudebivash/);
  assert.doesNotMatch(strip[1], /facebook|instagram|x\.com|twitter\.com|github\.com|tumblr|orcid/i);
});

// Owner directive 2026-11-20 (researcher findings #7-#13): no first-party page links to, or declares in
// structured data, the Facebook, Instagram, X/Twitter, Tumblr or ORCID profiles or the GitHub profile page.
// X share-intent and cited-post links, and GitHub repository links, are not profile links.
const RETIRED_PROFILE = new RegExp(
  "https?://(?:(?:www|m|web|mobile)\\.)?(?:" +
  "facebook\\.com|fb\\.com|fb\\.me|instagram\\.com|orcid\\.org|[a-z0-9-]*\\.?tumblr\\.com|" +
  "(?:x|twitter)\\.com/(?:CDBSENTINELAPEX|cyberbivash|cyberdudebivash|Iambivash007)\\b|" +
  "github\\.com/cyberdudebivash/?(?=[\"'\\s)<,#?]|$))", "i");

test("no root page, landing page, API index, llms.txt or Next.js layout links to a retired social profile", () => {
  const files = [
    ...rootHtml,
    "landing/index.html",
    "api/index.html",
    "llms.txt",
    "platform/frontend/src/app/layout.tsx",
  ];
  assert.ok(rootHtml.length > 20, "root HTML inventory must be present");
  for (const rel of files) {
    const text = readFileSync(path.join(ROOT, rel), "utf8");
    assert.doesNotMatch(text, RETIRED_PROFILE, `${rel} links to or declares a retired social profile`);
  }
});
