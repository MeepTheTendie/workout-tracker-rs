pub fn e(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

pub fn now_ts() -> i64 { crate::db::now_ms() / 1000 }

pub fn fmt_date_ms(ts: Option<i64>) -> String {
    let ts = match ts { Some(t) => t, None => return "N/A".into() };
    let secs = if ts > 1_000_000_000_000 { ts / 1000 } else { ts };
    if secs <= 0 { return "N/A".into(); }
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|d| d.format("%b %-d, %Y").to_string())
        .unwrap_or_else(|| "N/A".into())
}

pub fn fmt_time_ms(ts: Option<i64>) -> String {
    let ts = match ts { Some(t) => t, None => return "-".into() };
    let secs = if ts > 1_000_000_000_000 { ts / 1000 } else { ts };
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|d| d.format("%-I:%M %p").to_string())
        .unwrap_or_else(|| "-".into())
}

pub fn fmt_weight(w: Option<f64>) -> String {
    match w { Some(v) => format!("{:.1} lbs", v), None => "-".into() }
}

pub fn fmt_num(n: Option<f64>) -> String {
    match n { Some(v) => format!("{}", v as i64), None => "0".into() }
}

pub fn flash_html(flash: Option<(&str, &str)>) -> String {
    match flash {
        Some((ty, msg)) => format!(r#"<div class="flash flash-{}">{}</div>"#, e(ty), e(msg)),
        None => String::new(),
    }
}

pub const CSS: &str = include_str!("../static/style.css");

pub fn nav_html(path: &str) -> String {
    let items = [
        ("/dashboard", "Home", r#"<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>"#),
        ("/workouts/log", "Log", r#"<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/>"#),
        ("/workouts/history", "History", r#"<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>"#),
        ("/routines", "Routines", r#"<path d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2"/><rect x="9" y="3" width="6" height="4" rx="2"/>"#),
        ("/stats", "Stats", r#"<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>"#),
        ("/prs", "PRs", r#"<path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6"/><path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/><path d="M4 22h16"/><path d="M18 2H6v7a6 6 0 0 0 12 0V2Z"/>"#),
        ("/goals", "Goals", r#"<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>"#),
        ("/cardio", "Cardio", r#"<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>"#),
        ("/export", "Export", r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>"#),
    ];
    let mut out = String::from("<nav>");
    for (href, label, svg) in items {
        let active = if path == href { " active" } else { "" };
        out.push_str(&format!(
            r#"<a href="{}" class="nav-btn{}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">{}</svg>{}</a>"#,
            href, active, svg, label
        ));
    }
    out.push_str("</nav>");
    out
}

pub fn render_page(title: &str, content: &str, show_nav: bool, path: &str, flash: Option<(&str, &str)>) -> String {
    let nav = if show_nav { nav_html(path) } else { String::new() };
    let f = flash_html(flash);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} - Workout Tracker</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>{css}</style>
</head>
<body>
<div class="app">
<div class="content">
{flash}
{content}
</div>
{nav}
</div>
</body>
</html>"#,
        title = e(title),
        css = CSS,
        flash = f,
        content = content,
        nav = nav
    )
}
