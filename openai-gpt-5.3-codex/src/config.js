import dotenv from "dotenv";

dotenv.config();

function parsePositiveInt(value, fallback, max) {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  if (typeof max === "number" && parsed > max) {
    return max;
  }
  return parsed;
}

function parseNonNegativeInt(value, fallback, max) {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  if (typeof max === "number" && parsed > max) {
    return max;
  }
  return parsed;
}

function parseBoolean(value, fallback) {
  if (value == null) {
    return fallback;
  }
  const normalized = String(value).toLowerCase().trim();
  if (normalized === "true") {
    return true;
  }
  if (normalized === "false") {
    return false;
  }
  return fallback;
}

const nodeEnv = process.env.NODE_ENV ?? "development";
const isProduction = nodeEnv === "production";
const port = parsePositiveInt(process.env.PORT, 3000, 65535);

const basicAuthUser = process.env.BASIC_AUTH_USER ?? "admin";
const basicAuthPass = process.env.BASIC_AUTH_PASS ?? "change-this-password";
const publicOrigin = process.env.PUBLIC_ORIGIN ?? `http://localhost:${port}`;

let parsedPublicOrigin;
try {
  parsedPublicOrigin = new URL(publicOrigin);
} catch {
  throw new Error("PUBLIC_ORIGIN must be a valid absolute URL.");
}

if (parsedPublicOrigin.protocol !== "http:" && parsedPublicOrigin.protocol !== "https:") {
  throw new Error("PUBLIC_ORIGIN must use http or https.");
}

if (isProduction && (!process.env.BASIC_AUTH_USER || !process.env.BASIC_AUTH_PASS)) {
  throw new Error("In production, BASIC_AUTH_USER and BASIC_AUTH_PASS must be set.");
}

if (isProduction && !process.env.PUBLIC_ORIGIN) {
  throw new Error("In production, PUBLIC_ORIGIN must be set explicitly.");
}

if (
  isProduction &&
  basicAuthUser === "admin" &&
  basicAuthPass === "change-this-password"
) {
  throw new Error("Default Basic Auth credentials are not allowed in production.");
}

const requireHttps = parseBoolean(process.env.REQUIRE_HTTPS, isProduction);
if (requireHttps && parsedPublicOrigin.protocol !== "https:") {
  throw new Error("PUBLIC_ORIGIN must be https when REQUIRE_HTTPS=true.");
}

export const config = Object.freeze({
  nodeEnv,
  isProduction,
  port,
  publicOrigin: parsedPublicOrigin.origin,
  publicHost: parsedPublicOrigin.host.toLowerCase(),
  trustProxy: parseNonNegativeInt(process.env.TRUST_PROXY, 0, 10),
  requireHttps,
  basicAuthUser,
  basicAuthPass,
  rateLimitWindowMs: parsePositiveInt(process.env.RATE_LIMIT_WINDOW_MS, 60_000, 3_600_000),
  rateLimitMax: parsePositiveInt(process.env.RATE_LIMIT_MAX, 120, 5_000),
  maxBodyKb: parsePositiveInt(process.env.MAX_BODY_KB, 10, 256),
  dbPath: process.env.DB_PATH ?? "./data/notes.db",
});
