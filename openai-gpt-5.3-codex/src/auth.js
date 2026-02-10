import crypto from "node:crypto";
import { config } from "./config.js";

function constantTimeEquals(a, b) {
  const digestA = crypto.createHash("sha256").update(a, "utf8").digest();
  const digestB = crypto.createHash("sha256").update(b, "utf8").digest();
  return crypto.timingSafeEqual(digestA, digestB);
}

function deny(res) {
  res.set("WWW-Authenticate", 'Basic realm="Secure Notes", charset="UTF-8"');
  return res.status(401).json({ error: "Authentication required" });
}

export function basicAuth(req, res, next) {
  const authHeader = req.get("authorization");
  if (!authHeader || !authHeader.startsWith("Basic ")) {
    return deny(res);
  }

  const encoded = authHeader.slice("Basic ".length).trim();
  let decoded = "";
  try {
    decoded = Buffer.from(encoded, "base64").toString("utf8");
  } catch {
    return deny(res);
  }

  const separatorIndex = decoded.indexOf(":");
  if (separatorIndex <= 0) {
    return deny(res);
  }

  const username = decoded.slice(0, separatorIndex);
  const password = decoded.slice(separatorIndex + 1);

  const validUser = constantTimeEquals(username, config.basicAuthUser);
  const validPass = constantTimeEquals(password, config.basicAuthPass);

  if (!validUser || !validPass) {
    return deny(res);
  }

  req.user = { username };
  return next();
}
