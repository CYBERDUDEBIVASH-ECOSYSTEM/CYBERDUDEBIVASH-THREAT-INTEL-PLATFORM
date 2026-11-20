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

test("the footer social strip keeps its other first-party identities", () => {
  const html = readFileSync(path.join(ROOT, "index.html"), "utf8");
  const strip = html.match(/<div class="social-strip">([\s\S]*?)<\/div>/);
  assert.ok(strip, "social strip must remain on the homepage");
  assert.match(strip[1], /x\.com\/CDBSENTINELAPEX/);
  assert.match(strip[1], /instagram\.com\/cyberdudebivash_official\//);
  assert.match(strip[1], /github\.com\/cyberdudebivash/);
  assert.doesNotMatch(strip[1], /facebook/i);
});
