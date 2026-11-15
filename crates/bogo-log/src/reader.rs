//! Owner-facing views over verified entries. Exports contain audit data, never result bodies.
use crate::Entry;
pub fn search<'a>(entries: &'a [Entry], text: &str) -> Vec<&'a Entry> {
    entries.iter().filter(|e| e.raw.contains(text)).collect()
}
pub fn export_jsonl(entries: &[Entry]) -> String {
    entries.iter().map(|e| format!("{}\n", e.raw)).collect()
}
pub fn export_csv(entries: &[Entry]) -> String {
    let mut out = "seq,timestamp,kind,record\r\n".to_string();
    for e in entries {
        out.push_str(&format!(
            "{},\"{}\",\"{}\",\"{}\"\r\n",
            e.seq,
            e.ts,
            e.event.kind(),
            e.raw.replace('"', "\"\"")
        ));
    }
    out
}
