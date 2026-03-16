const crypto = require("node:crypto");

const HASH_VERSION = "scrypt";
const SCRYPT_PARAMS = {
  N: 16384,
  r: 8,
  p: 1,
  keyLength: 64,
};

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = crypto.scryptSync(
    password,
    salt,
    SCRYPT_PARAMS.keyLength,
    {
      N: SCRYPT_PARAMS.N,
      r: SCRYPT_PARAMS.r,
      p: SCRYPT_PARAMS.p,
    },
  );

  return [
    HASH_VERSION,
    String(SCRYPT_PARAMS.N),
    String(SCRYPT_PARAMS.r),
    String(SCRYPT_PARAMS.p),
    salt,
    derivedKey.toString("hex"),
  ].join("$");
}

function verifyPassword(password, serializedHash) {
  if (!serializedHash || typeof serializedHash !== "string") {
    return false;
  }

  const parts = serializedHash.split("$");
  if (parts.length !== 6 || parts[0] !== HASH_VERSION) {
    return false;
  }

  const [, nValue, rValue, pValue, salt, expectedHex] = parts;
  const expected = Buffer.from(expectedHex, "hex");
  const actual = crypto.scryptSync(password, salt, expected.length, {
    N: Number(nValue),
    r: Number(rValue),
    p: Number(pValue),
  });

  return (
    actual.length === expected.length &&
    crypto.timingSafeEqual(actual, expected)
  );
}

module.exports = {
  hashPassword,
  verifyPassword,
};
