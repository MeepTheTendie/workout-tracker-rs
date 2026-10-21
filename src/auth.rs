use worker::{Env, Request, Response, Result};
use crate::db;
use crate::types::SessionRow;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use subtle::ConstantTimeEq;
use getrandom::getrandom;

pub fn new_session_id() -> String {
    let mut buf = [0u8; 32];
    getrandom(&mut buf).unwrap();
    hex::encode(buf)
}

pub fn new_csrf() -> String {
    let mut buf = [0u8; 16];
    getrandom(&mut buf).unwrap();
    hex::encode(buf)
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    if let Ok(parsed) = PasswordHash::new(hash) {
        Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
    } else {
        false
    }
}

pub fn hash_password(password: &str) -> Result<String> {
    use argon2::PasswordHasher;
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default().hash_password(password.as_bytes(), &salt).map_err(|e| worker::Error::RustError(e.to_string()))?.to_string())
}

pub async fn current_user_id(req: &Request, env: &Env) -> Result<Option<i64>> {
    let cookie = req.headers().get("Cookie")?.unwrap_or_default();
    let token = cookie.split(';').find_map(|c| {
        let c = c.trim();
        c.strip_prefix("wt_session=").map(|v| v.to_string())
    });
    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => return Ok(None),
    };
    let db = env.d1("DB")?;
    let rows = db::fetch_all::<SessionRow>(&db, "SELECT id, user_id, csrf_token, expires_at FROM sessions WHERE id = ?1", &[crate::db::j(token.clone())]).await?;
    let s = match rows.into_iter().next() {
        Some(s) => s,
        None => return Ok(None),
    };
    let now = db::now_ms() / 1000;
    if s.expires_at < now { return Ok(None); }
    Ok(Some(s.user_id))
}

pub async fn csrf_token(req: &Request, env: &Env) -> Result<String> {
    let cookie = req.headers().get("Cookie")?.unwrap_or_default();
    let token = cookie.split(';').find_map(|c| {
        let c = c.trim();
        c.strip_prefix("wt_session=").map(|v| v.to_string())
    });
    if let Some(t) = token {
        let db = env.d1("DB")?;
        let rows = db::fetch_all::<SessionRow>(&db, "SELECT id, user_id, csrf_token, expires_at FROM sessions WHERE id = ?1", &[crate::db::j(t)]).await?;
        if let Some(s) = rows.into_iter().next() {
            return Ok(s.csrf_token);
        }
    }
    Ok(new_csrf())
}

pub fn validate_csrf(submitted: &str, expected: &str) -> bool {
    submitted.as_bytes().ct_eq(expected.as_bytes()).into()
}

pub async fn create_session(env: &Env, user_id: i64) -> Result<(String, String)> {
    let db = env.d1("DB")?;
    let sid = new_session_id();
    let csrf = new_csrf();
    let now = db::now_ms() / 1000;
    let lifetime: i64 = env.var("SESSION_LIFETIME").map(|v| v.to_string().parse().unwrap_or(3600)).unwrap_or(3600);
    let expires = now + lifetime;
    db::exec(&db, "INSERT INTO sessions (id, user_id, csrf_token, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        &[
            crate::db::j(sid.clone()),
            crate::db::j(user_id),
            crate::db::j(csrf.clone()),
            crate::db::j(now),
            crate::db::j(expires),
        ]).await?;
    Ok((sid, csrf))
}

pub fn session_cookie(sid: &str, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!("wt_session={}; HttpOnly{}; SameSite=Strict; Path=/; Max-Age=3600", sid, secure_flag)
}

pub fn clear_session_cookie() -> String {
    "wt_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string()
}
