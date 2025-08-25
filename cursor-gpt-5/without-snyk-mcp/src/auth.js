const argon2 = require('argon2');
const { getDb } = require('./db');

const LOCK_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const MAX_ATTEMPTS = 10;

async function createUser(email, password) {
    const db = getDb();
    const now = Date.now();
    const passwordHash = await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 19_456,
        timeCost: 2,
        parallelism: 1,
    });
    const stmt = db.prepare(`INSERT INTO users (email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`);
    try {
        const info = stmt.run(email, passwordHash, now, now);
        return info.lastInsertRowid;
    } catch (e) {
        if (e && e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            const err = new Error('EMAIL_EXISTS');
            err.code = 'EMAIL_EXISTS';
            throw err;
        }
        throw e;
    }
}

function getUserByEmail(email) {
    const db = getDb();
    return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
}

function getUserById(id) {
    const db = getDb();
    return db.prepare('SELECT id, email, created_at, updated_at FROM users WHERE id = ?').get(id);
}

async function verifyLogin(email, password) {
    const db = getDb();
    const user = getUserByEmail(email);
    if (!user) return { ok: false };

    const now = Date.now();
    if (user.locked_until && user.locked_until > now) {
        return { ok: false, lockedUntil: user.locked_until };
    }

    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) {
        const attempts = (user.failed_login_attempts || 0) + 1;
        let lockedUntil = null;
        if (attempts >= MAX_ATTEMPTS) {
            lockedUntil = now + LOCK_WINDOW_MS;
        }
        db.prepare('UPDATE users SET failed_login_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?')
            .run(attempts, lockedUntil, now, user.id);
        return { ok: false, lockedUntil };
    }

    db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?')
        .run(now, user.id);
    return { ok: true, userId: user.id };
}

module.exports = { createUser, getUserByEmail, getUserById, verifyLogin };


