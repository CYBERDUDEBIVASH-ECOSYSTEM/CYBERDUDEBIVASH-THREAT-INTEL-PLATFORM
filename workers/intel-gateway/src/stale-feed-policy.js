/**
 * P0 R36: hard denial boundary for live intelligence API responses.
 *
 * Never returns the stored historical/stale item list in a LIVE route.
 * The origin feed is not mutated; historical archives remain separate.
 */
import { publicationEnvelope, parseGeneratedAt, MAX_PUBLIC_MANIFEST_AGE_HOURS, classifyManifestFreshness, STATES } from "./freshness-contract.js";

export function denyNonFreshLiveFeed(feed, nowMs = Date.now()) {
  const truth = publicationEnvelope(feed, nowMs, 0);
  if (truth.evaluation.healthy) return null;
  return {
    status: 503,
    headers: {
      ...truth.headers,
      "Cache-Control": "no-store, max-age=0",
      "Pragma": "no-cache",
      "X-Content-Type-Options": "nosniff",
    },
    body: {
      error: "live_intelligence_unavailable",
      reason: truth.evaluation.reason || "freshness_unverified",
      publication_state: truth.fields.publication_state,
      freshness_status: truth.fields.freshness_status,
      freshness_reason: truth.fields.freshness_reason,
      generated_at: truth.evaluation.intelligence.generated_at,
      age_seconds: truth.fields.age_seconds,
      max_age_seconds: truth.fields.max_age_seconds,
      items: [],
      count: 0,
      live_data_available: false,
      // A previously published item list can still exist in storage, but it
      // is never returned to live consumers until authoritative recovery.
      message: "No verified fresh threat intelligence is currently available.",
    },
  };
}

/**
 * Bound browser and edge freshness to the EXACT publication expiry, not
 * integer-floored age_seconds (which could cache up to 1 extra stale second).
 */
export function liveFreshCacheControl(feed, capSeconds = 120, nowMs = Date.now()) {
  const truth = publicationEnvelope(feed, nowMs, capSeconds);
  if (!truth.evaluation.healthy) return "no-store";
  const generatedMs = parseGeneratedAt(feed.generated_at);
  if (generatedMs === null) return "no-store";
  const expiresAt = generatedMs + MAX_PUBLIC_MANIFEST_AGE_HOURS * 3600 * 1000;
  const remaining = Math.max(0, Math.floor((expiresAt - nowMs) / 1000));
  return "public, max-age=" + Math.min(capSeconds, remaining) + ", must-revalidate";
}


/**
 * Live premium intelligence is published from a distinct R2 key. Its own
 * generated_at must be fresh AND the canonical public feed must be usable.
 * A fresh derived dashboard timestamp never heals a stale source manifest.
 * Applies to both apex.json (items) and ai_summary.json (aggregate shape).
 */
export function denyNonFreshPremiumManifest(canonicalFeed, premiumManifest, nowMs = Date.now()) {
  const canonicalDenial = denyNonFreshLiveFeed(canonicalFeed, nowMs);
  if (canonicalDenial) return canonicalDenial;

  const freshness = classifyManifestFreshness(premiumManifest?.generated_at, nowMs);
  if (!premiumManifest || typeof premiumManifest !== "object" ||
      Array.isArray(premiumManifest) || freshness.state !== STATES.FRESH) {
    return {
      status: 503,
      headers: {
        "Cache-Control": "no-store, max-age=0",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "X-Sentinel-Freshness": freshness.state.toUpperCase(),
        "X-Sentinel-Feed-Age-Seconds": freshness.age_seconds == null
          ? "unknown" : String(freshness.age_seconds),
      },
      body: {
        error: "live_intelligence_unavailable",
        reason: "premium_manifest_" + freshness.state,
        freshness_status: freshness.state.toUpperCase(),
        generated_at: typeof premiumManifest?.generated_at === "string"
          ? premiumManifest.generated_at : null,
        age_seconds: freshness.age_seconds,
        max_age_seconds: freshness.max_age_seconds,
        live_data_available: false,
        items: [],
        count: 0,
      },
    };
  }
  return null;
}

/** Never cache a premium response past EITHER source's 6h expiry. */
export function premiumLiveFreshCacheControl(canonicalFeed, premiumManifest,
                                            capSeconds = 120, nowMs = Date.now()) {
  if (denyNonFreshPremiumManifest(canonicalFeed, premiumManifest, nowMs)) {
    return "no-store";
  }
  const earliestPublication = Math.min(
    parseGeneratedAt(canonicalFeed.generated_at),
    parseGeneratedAt(premiumManifest.generated_at),
  );
  const expiresAt = earliestPublication + MAX_PUBLIC_MANIFEST_AGE_HOURS * 3600 * 1000;
  const secondsRemaining = Math.max(0, Math.floor((expiresAt - nowMs) / 1000));
  return "public, max-age=" + Math.min(capSeconds, secondsRemaining) + ", must-revalidate";
}
