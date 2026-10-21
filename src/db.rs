use worker::D1Database;
use serde::de::DeserializeOwned;
use worker::wasm_bindgen::JsValue;

pub trait IntoBind {
    fn into_bind(self) -> JsValue;
}

impl IntoBind for i64 {
    fn into_bind(self) -> JsValue { JsValue::from(self as f64) }
}
impl IntoBind for i32 {
    fn into_bind(self) -> JsValue { JsValue::from(self as f64) }
}
impl IntoBind for f64 {
    fn into_bind(self) -> JsValue { JsValue::from(self) }
}
impl IntoBind for String {
    fn into_bind(self) -> JsValue { JsValue::from(self) }
}
impl IntoBind for &str {
    fn into_bind(self) -> JsValue { JsValue::from(self.to_string()) }
}
impl IntoBind for JsValue {
    fn into_bind(self) -> JsValue { self }
}
impl<T: IntoBind> IntoBind for Option<T> {
    fn into_bind(self) -> JsValue {
        match self { Some(v) => v.into_bind(), None => JsValue::NULL }
    }
}

pub fn j<T: IntoBind>(v: T) -> JsValue { v.into_bind() }

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub async fn exec(db: &D1Database, sql: &str, params: &[JsValue]) -> worker::Result<()> {
    let stmt = db.prepare(sql);
    let stmt = stmt.bind(params)?;
    stmt.run().await?;
    Ok(())
}

pub async fn fetch_all<T: DeserializeOwned>(db: &D1Database, sql: &str, params: &[JsValue]) -> worker::Result<Vec<T>> {
    let stmt = db.prepare(sql);
    let stmt = stmt.bind(params)?;
    let r = stmt.all().await?;
    let rows: Vec<T> = r.results()?;
    Ok(rows)
}

pub async fn fetch_one<T: DeserializeOwned>(db: &D1Database, sql: &str, params: &[JsValue]) -> worker::Result<Option<T>> {
    let rows = fetch_all::<T>(db, sql, params).await?;
    Ok(rows.into_iter().next())
}

pub async fn insert(db: &D1Database, sql: &str, params: &[JsValue]) -> worker::Result<i64> {
    let stmt = db.prepare(sql);
    let stmt = stmt.bind(params)?;
    let r = stmt.run().await?;
    let meta = r.meta()?;
    Ok(meta.and_then(|m| m.last_row_id).unwrap_or(0))
}
