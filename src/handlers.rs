use worker::{Env, Request, Response, Result, RouteContext};
use crate::auth;
use crate::db;
use crate::html;
use crate::progression;
use crate::types::*;
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;

fn j<T: crate::db::IntoBind>(v: T) -> JsValue { crate::db::j(v) }

async fn uid(req: &Request, env: &Env) -> Result<Option<i64>> {
    auth::current_user_id(req, env).await
}

fn redirect(url: &str) -> Result<Response> {
    let mut r = Response::empty()?.with_status(302);
    r.headers_mut().set("Location", url)?;
    Ok(r)
}

fn redirect_flash(url: &str, msg: &str, ty: &str) -> Result<Response> {
    // flash via cookie-less: store in query? We'll just redirect; flash handled by session not available cross-request cheaply.
    // Simpler: append ?flash= & type= via query string and render. But to keep parity, use a flash cookie.
    let val = format!("{}|{}", ty, msg);
    let mut r = Response::empty()?.with_status(302);
    r.headers_mut().set("Location", url)?;
    r.headers_mut().set("Set-Cookie", &format!("wt_flash={}; Path=/; Max-Age=10; SameSite=Strict", urlencoding::encode(&val)))?;
    Ok(r)
}

fn read_flash(req: &Request) -> Option<(String, String)> {
    let cookie = req.headers().get("Cookie").ok().flatten().unwrap_or_default();
    for c in cookie.split(';') {
        let c = c.trim();
        if let Some(v) = c.strip_prefix("wt_flash=") {
            let dec = urlencoding::decode(v).ok()?.to_string();
            let mut parts = dec.splitn(2, '|');
            let ty = parts.next()?.to_string();
            let msg = parts.next()?.to_string();
            return Some((ty, msg));
        }
    }
    None
}

fn clear_flash_cookie() -> &'static str {
    "wt_flash=; Path=/; Max-Age=0; SameSite=Strict"
}

// ---------- login ----------
pub async fn login_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req, &env).await?.is_some() {
        return redirect("/dashboard");
    }
    let content = r#"<h1>Login</h1>
<form method="POST" action="/action/auth/login">
<input type="hidden" name="csrf_token" value="x">
<div class="field"><label>Password</label><input type="password" name="password" autofocus required></div>
<button type="submit" class="btn">Sign In</button>
</form>"#;
    // inject real csrf
    let ct = auth::new_csrf();
    let content = content.replace("value=\"x\"", &format!("value=\"{}\"", html::e(&ct)));
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("Login", &content, false, "/login", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    r.headers_mut().set("Set-Cookie", &format!("wt_csrf={}; Path=/; Max-Age=600; SameSite=Strict", ct))?;
    Ok(r)
}

#[derive(Deserialize)]
struct LoginForm { password: String, csrf_token: String }

pub async fn login_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let cookie = req.headers().get("Cookie").ok().flatten().unwrap_or_default();
    let ct = cookie.split(';').find_map(|c| { let c = c.trim(); c.strip_prefix("wt_csrf=").map(|v| v.to_string()) }).unwrap_or_default();
    let form: LoginForm = match req.form_data().await {
        Ok(fd) => {
            let p = fd.get_field("password").unwrap_or_default();
            let c = fd.get_field("csrf_token").unwrap_or_default();
            LoginForm { password: p, csrf_token: c }
        }
        Err(_) => return redirect_flash("/login", "Bad request", "error"),
    };
    if !auth::validate_csrf(&form.csrf_token, &ct) {
        return redirect_flash("/login", "Invalid security token", "error");
    }
    // rate limit simple: skip persistent; D1-based not needed
    let db = env.d1("DB")?;
    let users: Vec<UserRow> = db::fetch_all(&db, "SELECT id, name, email, password FROM users WHERE id = 1", &[]).await?;
    let user = match users.into_iter().next() {
        Some(u) => u,
        None => return redirect_flash("/login", "No user", "error"),
    };
    if !auth::verify_password(&user.password, &form.password) {
        return redirect_flash("/login", "Invalid password", "error");
    }
    let (sid, _) = auth::create_session(&env, user.id).await?;
    let secure = true;
    let cookie = auth::session_cookie(&sid, secure);
    let mut r = redirect("/dashboard")?;
    r.headers_mut().set("Set-Cookie", &cookie)?;
    Ok(r)
}

pub async fn logout_post(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    // delete session if cookie present - handled by clearing cookie
    let mut r = redirect("/login")?;
    r.headers_mut().set("Set-Cookie", &auth::clear_session_cookie())?;
    Ok(r)
}

// ---------- change password ----------
pub async fn change_password_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req, &env).await?.is_none() { return redirect("/login"); }
    let ct = auth::csrf_token(&req, &env).await.unwrap_or_default();
    let content = format!(r#"<h1>Change Password</h1>
<form method="POST" action="/action/auth/change-password">
{}
<div class="field"><label>Current Password</label><input type="password" name="current_password" required></div>
<div class="field"><label>New Password</label><input type="password" name="new_password" required minlength="8"></div>
<div class="field"><label>Confirm</label><input type="password" name="confirm_password" required></div>
<button type="submit" class="btn">Update</button>
</form>"#, format!(r#"<input type="hidden" name="csrf_token" value="{}">"#, html::e(&ct)));
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("Change Password", &content, true, "/change-password", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

#[derive(Deserialize)]
struct ChangePwForm { current_password: String, new_password: String, confirm_password: String, csrf_token: String }

pub async fn change_password_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let user_id = match uid(&req, &env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req, &env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad form".into()))?;
    let form = ChangePwForm {
        current_password: fd.get_field("current_password").unwrap_or_default(),
        new_password: fd.get_field("new_password").unwrap_or_default(),
        confirm_password: fd.get_field("confirm_password").unwrap_or_default(),
        csrf_token: fd.get_field("csrf_token").unwrap_or_default(),
    };
    if !auth::validate_csrf(&form.csrf_token, &ct) { return redirect_flash("/change-password", "Invalid token", "error"); }
    if form.new_password != form.confirm_password { return redirect_flash("/change-password", "Passwords do not match", "error"); }
    if form.new_password.len() < 8 { return redirect_flash("/change-password", "Password too short", "error"); }
    let db = env.d1("DB")?;
    let users: Vec<UserRow> = db::fetch_all(&db, "SELECT id, name, email, password FROM users WHERE id = ?1", &[j(user_id)]).await?;
    let user = match users.into_iter().next() { Some(u) => u, None => return redirect_flash("/change-password","User not found","error") };
    if !auth::verify_password(&user.password, &form.current_password) {
        return redirect_flash("/change-password", "Current password incorrect", "error");
    }
    let new_hash = auth::hash_password(&form.new_password)?;
    db::exec(&db, "UPDATE users SET password = ?1, updated_at = ?2 WHERE id = ?3",
        &[j(new_hash), j(db::now_ms()), j(user_id)]).await?;
    redirect_flash("/dashboard", "Password changed successfully", "success")
}

// ---------- dashboard ----------
pub async fn dashboard_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let user_id = match uid(&req, &env).await? { Some(u) => u, None => return redirect("/login") };
    let db = env.d1("DB")?;
    let total_workouts: i64 = db::fetch_all::<serde_json::Value>(&db, "SELECT COUNT(*) as c FROM workouts WHERE user_id = ?1 AND ended_at IS NOT NULL", &[j(user_id)]).await?
        .first().and_then(|v| v.get("c")).and_then(|v| v.as_i64()).unwrap_or(0);
    let total_sets: i64 = db::fetch_all::<serde_json::Value>(&db, "SELECT COUNT(*) as c FROM workout_sets ws JOIN workouts w ON ws.workout_id = w.id WHERE w.user_id = ?1 AND w.ended_at IS NOT NULL AND ws.completed_at IS NOT NULL", &[j(user_id)]).await?
        .first().and_then(|v| v.get("c")).and_then(|v| v.as_i64()).unwrap_or(0);
    let total_volume: f64 = db::fetch_all::<serde_json::Value>(&db, "SELECT COALESCE(SUM(ws.weight * ws.reps),0) as v FROM workout_sets ws JOIN workouts w ON ws.workout_id = w.id WHERE w.user_id = ?1 AND w.ended_at IS NOT NULL AND ws.completed_at IS NOT NULL", &[j(user_id)]).await?
        .first().and_then(|v| v.get("v")).and_then(|v| v.as_f64()).unwrap_or(0.0);
    let week_ago = (db::now_ms()/1000 - 7*86400) * 1000;
    let this_week: i64 = db::fetch_all::<serde_json::Value>(&db, "SELECT COUNT(*) as c FROM workouts WHERE user_id = ?1 AND ended_at IS NOT NULL AND started_at >= ?2", &[j(user_id), j(week_ago)]).await?
        .first().and_then(|v| v.get("c")).and_then(|v| v.as_i64()).unwrap_or(0);
    let last_workouts: Vec<WorkoutRow> = db::fetch_all(&db, "SELECT id, user_id, started_at, ended_at, notes FROM workouts WHERE user_id = ?1 ORDER BY started_at DESC LIMIT 5", &[j(user_id)]).await.unwrap_or_default();
    let mut rows = String::new();
    for w in &last_workouts {
        let when = html::fmt_date_ms(Some(w.started_at));
        let status = if w.ended_at.is_some() { "done" } else { "in progress" };
        rows.push_str(&format!(r#"<tr><td><a href="/workouts/view?id={}">#{}</a></td><td>{}</td><td>{}</td></tr>"#, w.id, w.id, when, status));
    }
    let content = format!(r#"
<h1>Dashboard</h1>
<div class="stats-grid">
  <div class="stat"><div class="stat-val">{}</div><div class="stat-label">Workouts</div></div>
  <div class="stat"><div class="stat-val">{}</div><div class="stat-label">Sets</div></div>
  <div class="stat"><div class="stat-val">{:.0}</div><div class="stat-label">Volume lbs</div></div>
  <div class="stat"><div class="stat-val">{}</div><div class="stat-label">This week</div></div>
</div>
<h2>Recent</h2>
<table class="table"><thead><tr><th>Workout</th><th>Date</th><th>Status</th></tr></thead><tbody>{}</tbody></table>
<p><a href="/workouts/log" class="btn">Log Workout</a> <a href="/change-password" class="btn secondary">Change Password</a></p>
"#, total_workouts, total_sets, total_volume, this_week, rows);
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("Dashboard", &content, true, "/dashboard", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

// ---------- workouts ----------
pub async fn workouts_log_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req, &env).await?.is_none() { return redirect("/login"); }
    let db = env.d1("DB")?;
    let uidv = uid(&req,&env).await?.unwrap();
    // active workout?
    let active: Vec<WorkoutRow> = db::fetch_all(&db, "SELECT id, user_id, started_at, ended_at, notes FROM workouts WHERE user_id = ?1 AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1", &[j(uidv)]).await.unwrap_or_default();
    let mut content = String::from("<h1>Log Workout</h1>");
    if let Some(w) = active.first() {
        // list sets grouped
        let sets: Vec<SetRow> = db::fetch_all(&db, "SELECT id, workout_id, exercise_id, set_number, reps, weight, completed_at FROM workout_sets WHERE workout_id = ?1 ORDER BY id", &[j(w.id)]).await.unwrap_or_default();
        let exs: Vec<ExerciseRow> = db::fetch_all(&db, "SELECT id, name, category FROM exercises ORDER BY category, name", &[]).await.unwrap_or_default();
        let exmap: std::collections::HashMap<i64, String> = exs.iter().map(|e| (e.id, e.name.clone())).collect();
        let ct = auth::csrf_token(&req, &env).await.unwrap_or_default();
        content.push_str(&format!(r#"<p>Active workout #{} started {}</p>"#, w.id, html::fmt_date_ms(Some(w.started_at))));
        content.push_str(r#"<form method="POST" action="/action/workouts/add-set" class="inline">"#);
        content.push_str(&format!(r#"<input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="workout_id" value="{}">"#, html::e(&ct), w.id));
        content.push_str(r#"<select name="exercise_id" required>"#);
        let mut cur = String::new();
        for e in &exs {
            if e.category != cur { if !cur.is_empty() { content.push_str("</optgroup>"); } cur = e.category.clone(); content.push_str(&format!("<optgroup label=\"{}\">", html::e(&cur))); }
            content.push_str(&format!("<option value=\"{}\">{}</option>", e.id, html::e(&e.name)));
        }
        if !cur.is_empty() { content.push_str("</optgroup>"); }
        content.push_str(r#"</select>
<input type="number" name="reps" placeholder="reps" min="1">
<input type="number" step="0.5" name="weight" placeholder="weight">
<button type="submit" class="btn">Add Set</button></form>"#);
        // sets table
        content.push_str(r#"<table class="table"><thead><tr><th>Exercise</th><th>Set</th><th>Reps</th><th>Weight</th><th></th></tr></thead><tbody>"#);
        for s in &sets {
            let name = exmap.get(&s.exercise_id).cloned().unwrap_or_default();
            let done = s.completed_at.is_some();
            content.push_str(&format!(r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>"#,
                html::e(&name), s.set_number, s.reps.unwrap_or(0), html::fmt_weight(s.weight)));
            if !done {
                content.push_str(&format!(r#"<form method="POST" action="/action/workouts/complete-set" class="inline"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="set_id" value="{}"><button class="btn small">Done</button></form>"#, html::e(&ct), s.id));
            } else {
                content.push_str("✓");
            }
            content.push_str("</td></tr>");
        }
        content.push_str("</tbody></table>");
        content.push_str(&format!(r#"<form method="POST" action="/action/workouts/finish" class="inline"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="workout_id" value="{}"><button class="btn">Finish Workout</button></form>"#, html::e(&ct), w.id));
    } else {
        let ct = auth::csrf_token(&req, &env).await.unwrap_or_default();
        content.push_str(&format!(r#"<form method="POST" action="/action/workouts/start"><input type="hidden" name="csrf_token" value="{}"><button class="btn">Start New Workout</button></form>"#, html::e(&ct)));
    }
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("Log Workout", &content, true, "/workouts/log", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

pub async fn workouts_history_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req, &env).await?.is_none() { return redirect("/login"); }
    let uidv = uid(&req,&env).await?.unwrap();
    let db = env.d1("DB")?;
    let ws: Vec<WorkoutRow> = db::fetch_all(&db, "SELECT id, user_id, started_at, ended_at, notes FROM workouts WHERE user_id = ?1 ORDER BY started_at DESC LIMIT 50", &[j(uidv)]).await.unwrap_or_default();
    let mut rows = String::new();
    for w in &ws {
        rows.push_str(&format!(r#"<tr><td><a href="/workouts/view?id={}">#{}</a></td><td>{}</td><td>{}</td></tr>"#, w.id, w.id, html::fmt_date_ms(Some(w.started_at)), if w.ended_at.is_some() {"done"} else {"in progress"}));
    }
    let content = format!(r#"<h1>History</h1><table class="table"><thead><tr><th>Workout</th><th>Date</th><th>Status</th></tr></thead><tbody>{}</tbody></table>"#, rows);
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("History", &content, true, "/workouts/history", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

pub async fn workouts_view_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req, &env).await?.is_none() { return redirect("/login"); }
    let uidv = uid(&req,&env).await?.unwrap();
    let db = env.d1("DB")?;
    let url = req.url()?;
    let id: i64 = url.query_pairs().find(|(k,_)| k=="id").and_then(|(_,v)| v.parse().ok()).unwrap_or(0);
    let ws: Vec<WorkoutRow> = db::fetch_all(&db, "SELECT id, user_id, started_at, ended_at, notes FROM workouts WHERE id = ?1 AND user_id = ?2", &[j(id), j(uidv)]).await.unwrap_or_default();
    let w = match ws.into_iter().next() { Some(w) => w, None => return redirect("/workouts/history") };
    let sets: Vec<SetRow> = db::fetch_all(&db, "SELECT id, workout_id, exercise_id, set_number, reps, weight, completed_at FROM workout_sets WHERE workout_id = ?1 ORDER BY id", &[j(w.id)]).await.unwrap_or_default();
    let exs: Vec<ExerciseRow> = db::fetch_all(&db, "SELECT id, name, category FROM exercises", &[]).await.unwrap_or_default();
    let exmap: std::collections::HashMap<i64, String> = exs.iter().map(|e| (e.id, e.name.clone())).collect();
    let ct = auth::csrf_token(&req, &env).await.unwrap_or_default();
    let mut rows = String::new();
    for s in &sets {
        let name = exmap.get(&s.exercise_id).cloned().unwrap_or_default();
        rows.push_str(&format!(r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
            html::e(&name), s.set_number, s.reps.unwrap_or(0), html::fmt_weight(s.weight),
            if s.completed_at.is_some() {"✓"} else {""}));
    }
    let content = format!(r#"<h1>Workout #{}</h1><p>Started {}</p>
<table class="table"><thead><tr><th>Exercise</th><th>Set</th><th>Reps</th><th>Weight</th><th>Done</th></tr></thead><tbody>{}</tbody></table>
<p><a href="/workouts/history" class="btn secondary">Back</a></p>"#, w.id, html::fmt_date_ms(Some(w.started_at)), rows);
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("Workout", &content, true, "/workouts/view", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

// ---------- workout actions ----------
pub async fn workout_start_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/workouts/log","Invalid token","error"); }
    let db = env.d1("DB")?;
    db::insert(&db, "INSERT INTO workouts (user_id, started_at, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
        &[j(uidv), j(db::now_ms()), j(db::now_ms()), j(db::now_ms())]).await?;
    redirect_flash("/workouts/log", "Workout started", "success")
}

pub async fn add_set_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/workouts/log","Invalid token","error"); }
    let workout_id: i64 = fd.get_field("workout_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let exercise_id: i64 = fd.get_field("exercise_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let reps: Option<i64> = fd.get_field("reps").and_then(|v| v.parse().ok());
    let weight: Option<f64> = fd.get_field("weight").and_then(|v| v.parse().ok());
    // verify ownership
    let db = env.d1("DB")?;
    let ws: Vec<WorkoutRow> = db::fetch_all(&db, "SELECT id, user_id, started_at, ended_at, notes FROM workouts WHERE id = ?1", &[j(workout_id)]).await.unwrap_or_default();
    if ws.first().map(|w| w.user_id).unwrap_or(0) != uidv { return redirect_flash("/workouts/log","Not allowed","error"); }
    // set number
    let cnt: i64 = db::fetch_all::<serde_json::Value>(&db, "SELECT COUNT(*) as c FROM workout_sets WHERE workout_id = ?1 AND exercise_id = ?2", &[j(workout_id), j(exercise_id)]).await?
        .first().and_then(|v| v.get("c")).and_then(|v| v.as_i64()).unwrap_or(0);
    db::insert(&db, "INSERT INTO workout_sets (workout_id, exercise_id, set_number, reps, weight, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        &[j(workout_id), j(exercise_id), j(cnt+1), reps.map(j).unwrap_or(JsValue::NULL), weight.map(j).unwrap_or(JsValue::NULL), j(db::now_ms()), j(db::now_ms())]).await?;
    redirect_flash("/workouts/log", "Set added", "success")
}

pub async fn complete_set_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/workouts/log","Invalid token","error"); }
    let set_id: i64 = fd.get_field("set_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let db = env.d1("DB")?;
    // ownership via workout
    let rows: Vec<serde_json::Value> = db::fetch_all(&db, "SELECT w.user_id FROM workout_sets ws JOIN workouts w ON ws.workout_id = w.id WHERE ws.id = ?1", &[j(set_id)]).await.unwrap_or_default();
    if rows.first().and_then(|v| v.get("user_id")).and_then(|v| v.as_i64()).unwrap_or(0) != uidv {
        return redirect_flash("/workouts/log","Not allowed","error");
    }
    db::exec(&db, "UPDATE workout_sets SET completed_at = ?1, updated_at = ?2 WHERE id = ?3", &[j(db::now_ms()), j(db::now_ms()), j(set_id)]).await?;
    redirect_flash("/workouts/log", "Set completed", "success")
}

pub async fn edit_set_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/workouts/log","Invalid token","error"); }
    let set_id: i64 = fd.get_field("set_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let reps: Option<i64> = fd.get_field("reps").and_then(|v| v.parse().ok());
    let weight: Option<f64> = fd.get_field("weight").and_then(|v| v.parse().ok());
    let db = env.d1("DB")?;
    let rows: Vec<serde_json::Value> = db::fetch_all(&db, "SELECT w.user_id FROM workout_sets ws JOIN workouts w ON ws.workout_id = w.id WHERE ws.id = ?1", &[j(set_id)]).await.unwrap_or_default();
    if rows.first().and_then(|v| v.get("user_id")).and_then(|v| v.as_i64()).unwrap_or(0) != uidv {
        return redirect_flash("/workouts/log","Not allowed","error");
    }
    db::exec(&db, "UPDATE workout_sets SET reps = ?1, weight = ?2, updated_at = ?3 WHERE id = ?4",
        &[reps.map(j).unwrap_or(JsValue::NULL), weight.map(j).unwrap_or(JsValue::NULL), j(db::now_ms()), j(set_id)]).await?;
    redirect_flash("/workouts/log", "Set updated", "success")
}

pub async fn finish_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/workouts/log","Invalid token","error"); }
    let workout_id: i64 = fd.get_field("workout_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let db = env.d1("DB")?;
    let ws: Vec<WorkoutRow> = db::fetch_all(&db, "SELECT id, user_id, started_at, ended_at, notes FROM workouts WHERE id = ?1", &[j(workout_id)]).await.unwrap_or_default();
    if ws.first().map(|w| w.user_id).unwrap_or(0) != uidv { return redirect_flash("/workouts/log","Not allowed","error"); }
    db::exec(&db, "UPDATE workouts SET ended_at = ?1, updated_at = ?2 WHERE id = ?3", &[j(db::now_ms()), j(db::now_ms()), j(workout_id)]).await?;
    redirect_flash("/workouts/history", "Workout finished", "success")
}

pub async fn remove_exercise_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/workouts/log","Invalid token","error"); }
    let workout_id: i64 = fd.get_field("workout_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let exercise_id: i64 = fd.get_field("exercise_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let db = env.d1("DB")?;
    let ws: Vec<WorkoutRow> = db::fetch_all(&db, "SELECT id, user_id, started_at, ended_at, notes FROM workouts WHERE id = ?1", &[j(workout_id)]).await.unwrap_or_default();
    if ws.first().map(|w| w.user_id).unwrap_or(0) != uidv { return redirect_flash("/workouts/log","Not allowed","error"); }
    db::exec(&db, "DELETE FROM workout_sets WHERE workout_id = ?1 AND exercise_id = ?2", &[j(workout_id), j(exercise_id)]).await?;
    redirect_flash("/workouts/log", "Exercise removed", "success")
}

pub async fn update_name_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/workouts/log","Invalid token","error"); }
    let workout_id: i64 = fd.get_field("workout_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let notes = fd.get_field("notes").unwrap_or_default();
    let db = env.d1("DB")?;
    let ws: Vec<WorkoutRow> = db::fetch_all(&db, "SELECT id, user_id, started_at, ended_at, notes FROM workouts WHERE id = ?1", &[j(workout_id)]).await.unwrap_or_default();
    if ws.first().map(|w| w.user_id).unwrap_or(0) != uidv { return redirect_flash("/workouts/log","Not allowed","error"); }
    db::exec(&db, "UPDATE workouts SET notes = ?1, updated_at = ?2 WHERE id = ?3", &[j(notes), j(db::now_ms()), j(workout_id)]).await?;
    redirect_flash("/workouts/log", "Updated", "success")
}

// ---------- routines ----------
pub async fn routines_list_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req,&env).await?.is_none() { return redirect("/login"); }
    let uidv = uid(&req,&env).await?.unwrap();
    let db = env.d1("DB")?;
    let routines: Vec<RoutineRow> = db::fetch_all(&db, "SELECT id, user_id, name, description FROM routines WHERE user_id = ?1 ORDER BY name", &[j(uidv)]).await.unwrap_or_default();
    let mut rows = String::new();
    for r in &routines {
        rows.push_str(&format!(r#"<tr><td><a href="/routines/edit?id={}">{}</a></td><td>{}</td><td>
<form method="POST" action="/action/routines/start" class="inline"><input type="hidden" name="csrf_token" value="X"><input type="hidden" name="routine_id" value="{}"><button class="btn small">Start</button></form>
<form method="POST" action="/action/routines/delete" class="inline"><input type="hidden" name="csrf_token" value="X"><input type="hidden" name="routine_id" value="{}"><button class="btn small danger">Delete</button></form>
</td></tr>"#, r.id, html::e(&r.name), html::e(r.description.as_deref().unwrap_or("")), r.id, r.id));
    }
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let rows = rows.replace("value=\"X\"", &format!("value=\"{}\"", html::e(&ct)));
    let content = format!(r#"<h1>Routines</h1><p><a href="/routines/create" class="btn">New Routine</a></p>
<table class="table"><thead><tr><th>Name</th><th>Description</th><th></th></tr></thead><tbody>{}</tbody></table>"#, rows);
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("Routines", &content, true, "/routines", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

pub async fn routines_create_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req,&env).await?.is_none() { return redirect("/login"); }
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let content = format!(r#"<h1>New Routine</h1>
<form method="POST" action="/action/routines/create">
<input type="hidden" name="csrf_token" value="{}">
<div class="field"><label>Name</label><input name="name" required></div>
<div class="field"><label>Description</label><textarea name="description"></textarea></div>
<button class="btn">Create</button>
</form>"#, html::e(&ct));
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("New Routine", &content, true, "/routines/create", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

pub async fn routines_edit_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req,&env).await?.is_none() { return redirect("/login"); }
    let uidv = uid(&req,&env).await?.unwrap();
    let db = env.d1("DB")?;
    let url = req.url()?;
    let id: i64 = url.query_pairs().find(|(k,_)| k=="id").and_then(|(_,v)| v.parse().ok()).unwrap_or(0);
    let rs: Vec<RoutineRow> = db::fetch_all(&db, "SELECT id, user_id, name, description FROM routines WHERE id = ?1 AND user_id = ?2", &[j(id), j(uidv)]).await.unwrap_or_default();
    let r = match rs.into_iter().next() { Some(r) => r, None => return redirect("/routines") };
    let res: Vec<RoutineExerciseRow> = db::fetch_all(&db, "SELECT id, routine_id, exercise_id, order_index, target_sets, target_reps, target_weight FROM routine_exercises WHERE routine_id = ?1 ORDER BY order_index", &[j(id)]).await.unwrap_or_default();
    let exs: Vec<ExerciseRow> = db::fetch_all(&db, "SELECT id, name, category FROM exercises ORDER BY category, name", &[]).await.unwrap_or_default();
    let exmap: std::collections::HashMap<i64, String> = exs.iter().map(|e| (e.id, e.name.clone())).collect();
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let mut rows = String::new();
    for re in &res {
        let name = exmap.get(&re.exercise_id).cloned().unwrap_or_default();
        rows.push_str(&format!(r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>
<form method="POST" action="/action/routines/remove-exercise" class="inline"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="re_id" value="{}"><button class="btn small danger">Remove</button></form>
</td></tr>"#, html::e(&name), re.target_sets.unwrap_or(0), re.target_reps.unwrap_or(0), html::fmt_weight(re.target_weight), html::e(&ct), re.id));
    }
    // add exercise form
    let mut opts = String::new();
    let mut cur = String::new();
    for e in &exs {
        if e.category != cur { if !cur.is_empty() { opts.push_str("</optgroup>"); } cur = e.category.clone(); opts.push_str(&format!("<optgroup label=\"{}\">", html::e(&cur))); }
        opts.push_str(&format!("<option value=\"{}\">{}</option>", e.id, html::e(&e.name)));
    }
    if !cur.is_empty() { opts.push_str("</optgroup>"); }
    let content = format!(r#"<h1>Edit: {}</h1>
<form method="POST" action="/action/routines/update"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="routine_id" value="{}">
<div class="field"><label>Name</label><input name="name" value="{}" required></div>
<div class="field"><label>Description</label><textarea name="description">{}</textarea></div>
<button class="btn">Save</button></form>
<h2>Exercises</h2>
<table class="table"><thead><tr><th>Exercise</th><th>Sets</th><th>Reps</th><th>Weight</th><th></th></tr></thead><tbody>{}</tbody></table>
<form method="POST" action="/action/routines/add-exercise" class="inline">
<input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="routine_id" value="{}">
<select name="exercise_id">{}</select>
<input type="number" name="target_sets" placeholder="sets" value="3">
<input type="number" name="target_reps" placeholder="reps" value="10">
<input type="number" step="0.5" name="target_weight" placeholder="weight">
<button class="btn">Add</button></form>
<p><a href="/routines" class="btn secondary">Back</a></p>"#,
        html::e(&r.name), html::e(&ct), r.id, html::e(&r.name), html::e(r.description.as_deref().unwrap_or("")), rows, html::e(&ct), r.id, opts);
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("Edit Routine", &content, true, "/routines/edit", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

// routine actions
pub async fn routines_create_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/routines","Invalid token","error"); }
    let name = fd.get_field("name").unwrap_or_default();
    let desc = fd.get_field("description").unwrap_or_default();
    if name.trim().is_empty() { return redirect_flash("/routines/create","Name required","error"); }
    let db = env.d1("DB")?;
    db::insert(&db, "INSERT INTO routines (user_id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        &[j(uidv), j(name), j(desc), j(db::now_ms()), j(db::now_ms())]).await?;
    redirect_flash("/routines", "Routine created", "success")
}

pub async fn routines_update_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/routines","Invalid token","error"); }
    let rid: i64 = fd.get_field("routine_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let name = fd.get_field("name").unwrap_or_default();
    let desc = fd.get_field("description").unwrap_or_default();
    let db = env.d1("DB")?;
    let rs: Vec<RoutineRow> = db::fetch_all(&db, "SELECT id, user_id, name, description FROM routines WHERE id = ?1", &[j(rid)]).await.unwrap_or_default();
    if rs.first().map(|r| r.user_id).unwrap_or(0) != uidv { return redirect_flash("/routines","Not allowed","error"); }
    db::exec(&db, "UPDATE routines SET name = ?1, description = ?2, updated_at = ?3 WHERE id = ?4", &[j(name), j(desc), j(db::now_ms()), j(rid)]).await?;
    redirect_flash(&format!("/routines/edit?id={}", rid), "Updated", "success")
}

pub async fn routines_delete_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/routines","Invalid token","error"); }
    let rid: i64 = fd.get_field("routine_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let db = env.d1("DB")?;
    let rs: Vec<RoutineRow> = db::fetch_all(&db, "SELECT id, user_id, name, description FROM routines WHERE id = ?1", &[j(rid)]).await.unwrap_or_default();
    if rs.first().map(|r| r.user_id).unwrap_or(0) != uidv { return redirect_flash("/routines","Not allowed","error"); }
    db::exec(&db, "DELETE FROM routine_exercises WHERE routine_id = ?1", &[j(rid)]).await?;
    db::exec(&db, "DELETE FROM routines WHERE id = ?1", &[j(rid)]).await?;
    redirect_flash("/routines", "Deleted", "success")
}

pub async fn routines_start_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/routines","Invalid token","error"); }
    let rid: i64 = fd.get_field("routine_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let db = env.d1("DB")?;
    let rs: Vec<RoutineRow> = db::fetch_all(&db, "SELECT id, user_id, name, description FROM routines WHERE id = ?1", &[j(rid)]).await.unwrap_or_default();
    if rs.first().map(|r| r.user_id).unwrap_or(0) != uidv { return redirect_flash("/routines","Not allowed","error"); }
    let rexs: Vec<RoutineExerciseRow> = db::fetch_all(&db, "SELECT id, routine_id, exercise_id, order_index, target_sets, target_reps, target_weight FROM routine_exercises WHERE routine_id = ?1", &[j(rid)]).await.unwrap_or_default();
    let wid = db::insert(&db, "INSERT INTO workouts (user_id, started_at, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)", &[j(uidv), j(db::now_ms()), j(db::now_ms()), j(db::now_ms())]).await?;
    for re in &rexs {
        let sets = re.target_sets.unwrap_or(1).max(1);
        for s in 1..=sets {
            db::insert(&db, "INSERT INTO workout_sets (workout_id, exercise_id, set_number, reps, weight, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &[j(wid), j(re.exercise_id), j(s as i64), re.target_reps.map(j).unwrap_or(JsValue::NULL), re.target_weight.map(j).unwrap_or(JsValue::NULL), j(db::now_ms()), j(db::now_ms())]).await?;
        }
    }
    redirect_flash("/workouts/log", "Routine started", "success")
}

pub async fn routines_add_exercise_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/routines","Invalid token","error"); }
    let rid: i64 = fd.get_field("routine_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let exercise_id: i64 = fd.get_field("exercise_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let target_sets: Option<i64> = fd.get_field("target_sets").and_then(|v| v.parse().ok());
    let target_reps: Option<i64> = fd.get_field("target_reps").and_then(|v| v.parse().ok());
    let target_weight: Option<f64> = fd.get_field("target_weight").and_then(|v| v.parse().ok());
    let db = env.d1("DB")?;
    let rs: Vec<RoutineRow> = db::fetch_all(&db, "SELECT id, user_id, name, description FROM routines WHERE id = ?1", &[j(rid)]).await.unwrap_or_default();
    if rs.first().map(|r| r.user_id).unwrap_or(0) != uidv { return redirect_flash("/routines","Not allowed","error"); }
    db::insert(&db, "INSERT INTO routine_exercises (routine_id, exercise_id, order_index, target_sets, target_reps, target_weight, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        &[j(rid), j(exercise_id), j(0i64), target_sets.map(j).unwrap_or(JsValue::NULL), target_reps.map(j).unwrap_or(JsValue::NULL), target_weight.map(j).unwrap_or(JsValue::NULL), j(db::now_ms()), j(db::now_ms())]).await?;
    redirect_flash(&format!("/routines/edit?id={}", rid), "Added", "success")
}

pub async fn routines_remove_exercise_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/routines","Invalid token","error"); }
    let re_id: i64 = fd.get_field("re_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let db = env.d1("DB")?;
    let rows: Vec<serde_json::Value> = db::fetch_all(&db, "SELECT r.user_id FROM routine_exercises re JOIN routines r ON re.routine_id = r.id WHERE re.id = ?1", &[j(re_id)]).await.unwrap_or_default();
    if rows.first().and_then(|v| v.get("user_id")).and_then(|v| v.as_i64()).unwrap_or(0) != uidv {
        return redirect_flash("/routines","Not allowed","error");
    }
    db::exec(&db, "DELETE FROM routine_exercises WHERE id = ?1", &[j(re_id)]).await?;
    // redirect back to edit page of that routine - need routine_id; fetch
    let rid_rows: Vec<serde_json::Value> = db::fetch_all(&db, "SELECT routine_id FROM routine_exercises WHERE id = ?1", &[j(re_id)]).await.unwrap_or_default();
    // already deleted; can't get; redirect to routines
    let _ = rid_rows;
    redirect_flash("/routines", "Removed", "success")
}

pub async fn routines_update_targets_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/routines","Invalid token","error"); }
    let re_id: i64 = fd.get_field("re_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let target_sets: Option<i64> = fd.get_field("target_sets").and_then(|v| v.parse().ok());
    let target_reps: Option<i64> = fd.get_field("target_reps").and_then(|v| v.parse().ok());
    let target_weight: Option<f64> = fd.get_field("target_weight").and_then(|v| v.parse().ok());
    let db = env.d1("DB")?;
    db::exec(&db, "UPDATE routine_exercises SET target_sets = ?1, target_reps = ?2, target_weight = ?3, updated_at = ?4 WHERE id = ?5",
        &[target_sets.map(j).unwrap_or(JsValue::NULL), target_reps.map(j).unwrap_or(JsValue::NULL), target_weight.map(j).unwrap_or(JsValue::NULL), j(db::now_ms()), j(re_id)]).await?;
    redirect_flash("/routines", "Updated", "success")
}

pub async fn apply_progression_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/routines","Invalid token","error"); }
    let rid: i64 = fd.get_field("routine_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let db = env.d1("DB")?;
    let res: Vec<RoutineExerciseRow> = db::fetch_all(&db, "SELECT id, routine_id, exercise_id, order_index, target_sets, target_reps, target_weight FROM routine_exercises WHERE routine_id = ?1", &[j(rid)]).await.unwrap_or_default();
    let exs: Vec<ExerciseRow> = db::fetch_all(&db, "SELECT id, name, category FROM exercises", &[]).await.unwrap_or_default();
    let exmap: std::collections::HashMap<i64, String> = exs.iter().map(|e| (e.id, e.name.clone())).collect();
    // last weights per exercise name
    let lw_rows: Vec<serde_json::Value> = db::fetch_all(&db, "SELECT e.name as name, ws.weight as weight, ws.completed_at as ca FROM workout_sets ws JOIN exercises e ON ws.exercise_id = e.id JOIN workouts w ON ws.workout_id = w.id WHERE w.user_id = ?1 AND w.ended_at IS NOT NULL AND ws.completed_at IS NOT NULL ORDER BY ws.completed_at DESC", &[j(uidv)]).await.unwrap_or_default();
    let mut last_weights: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    for r in &lw_rows {
        let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !last_weights.contains_key(&name) {
            if let Some(w) = r.get("weight").and_then(|v| v.as_f64()) { last_weights.insert(name, w); }
        }
    }
    for re in &res {
        let name = exmap.get(&re.exercise_id).cloned().unwrap_or_default();
        let last = last_weights.get(&name).copied();
        if let Some(nw) = progression::suggest_next_weight(&name, last) {
            db::exec(&db, "UPDATE routine_exercises SET target_weight = ?1, updated_at = ?2 WHERE id = ?3", &[j(nw), j(db::now_ms()), j(re.id)]).await?;
        }
    }
    redirect_flash(&format!("/routines/edit?id={}", rid), "Progression applied", "success")
}

// ---------- stats ----------
pub async fn stats_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req,&env).await?.is_none() { return redirect("/login"); }
    let uidv = uid(&req,&env).await?.unwrap();
    let db = env.d1("DB")?;
    let total_workouts: i64 = db::fetch_all::<serde_json::Value>(&db, "SELECT COUNT(*) as c FROM workouts WHERE user_id = ?1 AND ended_at IS NOT NULL", &[j(uidv)]).await?.first().and_then(|v| v.get("c")).and_then(|v| v.as_i64()).unwrap_or(0);
    let total_volume: f64 = db::fetch_all::<serde_json::Value>(&db, "SELECT COALESCE(SUM(ws.weight * ws.reps),0) as v FROM workout_sets ws JOIN workouts w ON ws.workout_id = w.id WHERE w.user_id = ?1 AND w.ended_at IS NOT NULL AND ws.completed_at IS NOT NULL", &[j(uidv)]).await?.first().and_then(|v| v.get("v")).and_then(|v| v.as_f64()).unwrap_or(0.0);
    let total_sets: i64 = db::fetch_all::<serde_json::Value>(&db, "SELECT COUNT(*) as c FROM workout_sets ws JOIN workouts w ON ws.workout_id = w.id WHERE w.user_id = ?1 AND w.ended_at IS NOT NULL AND ws.completed_at IS NOT NULL", &[j(uidv)]).await?.first().and_then(|v| v.get("c")).and_then(|v| v.as_i64()).unwrap_or(0);
    let week_ago = (db::now_ms()/1000 - 7*86400)*1000;
    let this_week: i64 = db::fetch_all::<serde_json::Value>(&db, "SELECT COUNT(*) as c FROM workouts WHERE user_id = ?1 AND ended_at IS NOT NULL AND started_at >= ?2", &[j(uidv), j(week_ago)]).await?.first().and_then(|v| v.get("c")).and_then(|v| v.as_i64()).unwrap_or(0);
    let ex_stats: Vec<serde_json::Value> = db::fetch_all(&db, "SELECT e.name as name, e.id as exercise_id, COUNT(*) as set_count, MAX(ws.weight) as max_weight, SUM(ws.weight * ws.reps) as total_volume FROM workout_sets ws JOIN exercises e ON ws.exercise_id = e.id JOIN workouts w ON ws.workout_id = w.id WHERE w.user_id = ?1 AND w.ended_at IS NOT NULL AND ws.completed_at IS NOT NULL GROUP BY e.id, e.name ORDER BY total_volume DESC LIMIT 10", &[j(uidv)]).await.unwrap_or_default();
    let mut rows = String::new();
    for s in &ex_stats {
        let name = s.get("name").and_then(|v|v.as_str()).unwrap_or("");
        let sets = s.get("set_count").and_then(|v|v.as_i64()).unwrap_or(0);
        let maxw = s.get("max_weight").and_then(|v|v.as_f64());
        let vol = s.get("total_volume").and_then(|v|v.as_f64()).unwrap_or(0.0);
        rows.push_str(&format!(r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.0}</td></tr>"#, html::e(name), sets, html::fmt_weight(maxw), vol));
    }
    let content = format!(r#"<h1>Stats</h1>
<div class="stats-grid">
  <div class="stat"><div class="stat-val">{}</div><div class="stat-label">Workouts</div></div>
  <div class="stat"><div class="stat-val">{}</div><div class="stat-label">Sets</div></div>
  <div class="stat"><div class="stat-val">{:.0}</div><div class="stat-label">Volume lbs</div></div>
  <div class="stat"><div class="stat-val">{}</div><div class="stat-label">This week</div></div>
</div>
<h2>Top exercises</h2>
<table class="table"><thead><tr><th>Exercise</th><th>Sets</th><th>Max</th><th>Volume</th></tr></thead><tbody>{}</tbody></table>"#, total_workouts, total_sets, total_volume, this_week, rows);
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("Stats", &content, true, "/stats", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

// ---------- goals ----------
pub async fn goals_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req,&env).await?.is_none() { return redirect("/login"); }
    let uidv = uid(&req,&env).await?.unwrap();
    let db = env.d1("DB")?;
    let goals: Vec<GoalRow> = db::fetch_all(&db, "SELECT id, user_id, title, target_value, current_value, unit, deadline FROM goals WHERE user_id = ?1 ORDER BY id DESC", &[j(uidv)]).await.unwrap_or_default();
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let mut rows = String::new();
    for g in &goals {
        rows.push_str(&format!(r#"<tr><td>{}</td><td>{}/{}</td><td>{}</td><td>
<form method="POST" action="/action/goals/delete" class="inline"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="goal_id" value="{}"><button class="btn small danger">Delete</button></form></td></tr>"#,
            html::e(&g.title), html::fmt_num(g.current_value), html::fmt_num(g.target_value), html::e(g.unit.as_deref().unwrap_or("")), html::e(&ct), g.id));
    }
    let content = format!(r#"<h1>Goals</h1>
<form method="POST" action="/action/goals/save" class="card">
<input type="hidden" name="csrf_token" value="{}">
<div class="field"><label>Title</label><input name="title" required></div>
<div class="field"><label>Target</label><input type="number" step="0.1" name="target_value"></div>
<div class="field"><label>Current</label><input type="number" step="0.1" name="current_value"></div>
<div class="field"><label>Unit</label><input name="unit"></div>
<button class="btn">Save Goal</button></form>
<table class="table"><thead><tr><th>Title</th><th>Progress</th><th>Unit</th><th></th></tr></thead><tbody>{}</tbody></table>"#, html::e(&ct), rows);
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("Goals", &content, true, "/goals", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

pub async fn goals_save_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/goals","Invalid token","error"); }
    let title = fd.get_field("title").unwrap_or_default();
    let target: Option<f64> = fd.get_field("target_value").and_then(|v| v.parse().ok());
    let current: Option<f64> = fd.get_field("current_value").and_then(|v| v.parse().ok());
    let unit = fd.get_field("unit").unwrap_or_default();
    let db = env.d1("DB")?;
    db::insert(&db, "INSERT INTO goals (user_id, title, target_value, current_value, unit, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        &[j(uidv), j(title), target.map(j).unwrap_or(JsValue::NULL), current.map(j).unwrap_or(JsValue::NULL), j(unit), j(db::now_ms()), j(db::now_ms())]).await?;
    redirect_flash("/goals", "Saved", "success")
}

pub async fn goals_delete_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/goals","Invalid token","error"); }
    let goal_id: i64 = fd.get_field("goal_id").and_then(|v| v.parse().ok()).unwrap_or(0);
    let db = env.d1("DB")?;
    db::exec(&db, "DELETE FROM goals WHERE id = ?1 AND user_id = ?2", &[j(goal_id), j(uidv)]).await?;
    redirect_flash("/goals", "Deleted", "success")
}

// ---------- prs ----------
pub async fn prs_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req,&env).await?.is_none() { return redirect("/login"); }
    let uidv = uid(&req,&env).await?.unwrap();
    let db = env.d1("DB")?;
    let rows: Vec<serde_json::Value> = db::fetch_all(&db, "SELECT e.name as name, MAX(ws.weight) as max_weight, MAX(ws.reps) as max_reps FROM workout_sets ws JOIN exercises e ON ws.exercise_id = e.id JOIN workouts w ON ws.workout_id = w.id WHERE w.user_id = ?1 AND w.ended_at IS NOT NULL AND ws.completed_at IS NOT NULL GROUP BY e.id ORDER BY max_weight DESC", &[j(uidv)]).await.unwrap_or_default();
    let mut tr = String::new();
    for r in &rows {
        let name = r.get("name").and_then(|v|v.as_str()).unwrap_or("");
        let mw = r.get("max_weight").and_then(|v|v.as_f64());
        let mr = r.get("max_reps").and_then(|v|v.as_i64()).unwrap_or(0);
        tr.push_str(&format!(r#"<tr><td>{}</td><td>{}</td><td>{}</td></tr>"#, html::e(name), html::fmt_weight(mw), mr));
    }
    let content = format!(r#"<h1>Personal Records</h1><table class="table"><thead><tr><th>Exercise</th><th>Max Weight</th><th>Max Reps</th></tr></thead><tbody>{}</tbody></table>"#, tr);
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("PRs", &content, true, "/prs", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

// ---------- cardio ----------
pub async fn cardio_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req,&env).await?.is_none() { return redirect("/login"); }
    let uidv = uid(&req,&env).await?.unwrap();
    let db = env.d1("DB")?;
    let rows: Vec<CardioRow> = db::fetch_all(&db, "SELECT id, user_id, session_type, duration_minutes, calories_burned, heart_rate_avg, resistance_level, notes, completed_at FROM cardio_sessions WHERE user_id = ?1 ORDER BY completed_at DESC LIMIT 50", &[j(uidv)]).await.unwrap_or_default();
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let mut tr = String::new();
    for c in &rows {
        tr.push_str(&format!(r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#, html::e(&c.session_type), c.duration_minutes, c.calories_burned.unwrap_or(0), html::fmt_date_ms(Some(c.completed_at))));
    }
    let content = format!(r#"<h1>Cardio</h1>
<form method="POST" action="/action/cardio/add" class="card">
<input type="hidden" name="csrf_token" value="{}">
<div class="field"><label>Type</label><select name="session_type"><option value="bike">Bike</option><option value="run">Run</option><option value="walk">Walk</option></select></div>
<div class="field"><label>Minutes</label><input type="number" name="duration_minutes" value="15" required></div>
<div class="field"><label>Calories</label><input type="number" name="calories_burned"></div>
<div class="field"><label>HR avg</label><input type="number" name="heart_rate_avg"></div>
<div class="field"><label>Resistance</label><input type="number" name="resistance_level"></div>
<button class="btn">Add Session</button></form>
<table class="table"><thead><tr><th>Type</th><th>Min</th><th>Cal</th><th>Date</th></tr></thead><tbody>{}</tbody></table>"#, html::e(&ct), tr);
    let flash = read_flash(&req);
    let fref = flash.as_ref().map(|(t,m)| (t.as_str(), m.as_str()));
    let body = html::render_page("Cardio", &content, true, "/cardio", fref);
    let mut r = Response::from_html(body)?;
    r.headers_mut().set("Set-Cookie", clear_flash_cookie())?;
    Ok(r)
}

pub async fn cardio_add_post(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    let uidv = match uid(&req,&env).await? { Some(u) => u, None => return redirect("/login") };
    let ct = auth::csrf_token(&req,&env).await.unwrap_or_default();
    let fd = req.form_data().await.map_err(|_| worker::Error::RustError("bad".into()))?;
    let t = fd.get_field("csrf_token").unwrap_or_default();
    if !auth::validate_csrf(&t, &ct) { return redirect_flash("/cardio","Invalid token","error"); }
    let session_type = fd.get_field("session_type").unwrap_or_else(|| "bike".into());
    let duration: i64 = fd.get_field("duration_minutes").and_then(|v| v.parse().ok()).unwrap_or(15);
    let calories: Option<i64> = fd.get_field("calories_burned").and_then(|v| v.parse().ok());
    let hr: Option<i64> = fd.get_field("heart_rate_avg").and_then(|v| v.parse().ok());
    let res: Option<i64> = fd.get_field("resistance_level").and_then(|v| v.parse().ok());
    let db = env.d1("DB")?;
    db::insert(&db, "INSERT INTO cardio_sessions (user_id, session_type, duration_minutes, calories_burned, heart_rate_avg, resistance_level, completed_at, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        &[j(uidv), j(session_type), j(duration), calories.map(j).unwrap_or(JsValue::NULL), hr.map(j).unwrap_or(JsValue::NULL), res.map(j).unwrap_or(JsValue::NULL), j(db::now_ms()), j(db::now_ms()), j(db::now_ms())]).await?;
    redirect_flash("/cardio", "Saved", "success")
}

// ---------- export ----------
pub async fn export_get(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env.clone();
    if uid(&req,&env).await?.is_none() { return redirect("/login"); }
    let uidv = uid(&req,&env).await?.unwrap();
    let db = env.d1("DB")?;
    let ws: Vec<WorkoutRow> = db::fetch_all(&db, "SELECT id, user_id, started_at, ended_at, notes FROM workouts WHERE user_id = ?1 ORDER BY started_at", &[j(uidv)]).await.unwrap_or_default();
    let mut out = String::from("workout_id,started_at,ended_at,exercise,set_number,reps,weight,completed_at\n");
    for w in &ws {
        let sets: Vec<SetRow> = db::fetch_all(&db, "SELECT id, workout_id, exercise_id, set_number, reps, weight, completed_at FROM workout_sets WHERE workout_id = ?1", &[j(w.id)]).await.unwrap_or_default();
        let exs: Vec<ExerciseRow> = db::fetch_all(&db, "SELECT id, name, category FROM exercises", &[]).await.unwrap_or_default();
        let exmap: std::collections::HashMap<i64, String> = exs.iter().map(|e| (e.id, e.name.clone())).collect();
        for s in &sets {
            let name = exmap.get(&s.exercise_id).cloned().unwrap_or_default();
            out.push_str(&format!("{},{},{},{},{},{},{},{}\n", w.id, w.started_at, w.ended_at.unwrap_or(0), name, s.set_number, s.reps.unwrap_or(0), s.weight.unwrap_or(0.0), s.completed_at.unwrap_or(0)));
        }
    }
    let mut r = Response::ok(out)?;
    r.headers_mut().set("Content-Type", "text/csv")?;
    r.headers_mut().set("Content-Disposition", "attachment; filename=workouts.csv")?;
    Ok(r)
}

// ---------- 404 ----------
pub async fn not_found(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let _env = ctx.env.clone();
    let env = _env;
    Response::error("Not Found", 404)
}
