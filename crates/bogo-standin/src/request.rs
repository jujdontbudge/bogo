//! A read-only walk over BOGO's request encoding (ARCHITECTURE §3.2), only to
//! find fixed-width fields. Only the Lean encoder produces requests; the
//! stand-in takes the Lean vectors and overwrites fixed-width fields in place
//! (bogoId, nonce, times), which keeps every length and the canonical form.
use std::ops::Range;

pub struct Fields {
    pub bogo_id: Range<usize>,
    pub upstream: String,
    pub tool: String,
    pub justification: Option<String>,
    pub agent_id: Vec<u8>,
    pub agent_name: String,
    pub nonce: Range<usize>,
    pub created: Range<usize>,
    pub expires: Option<Range<usize>>,
}

struct R<'a> {
    b: &'a [u8],
    at: usize,
}

impl R<'_> {
    fn take(&mut self, n: usize) -> Option<Range<usize>> {
        let end = self.at.checked_add(n)?;
        (end <= self.b.len()).then(|| {
            let r = self.at..end;
            self.at = end;
            r
        })
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|r| self.b[r.start])
    }
    fn u32(&mut self) -> Option<usize> {
        let r = self.take(4)?;
        Some(u32::from_be_bytes(self.b[r].try_into().ok()?) as usize)
    }
    fn tag(&mut self, t: u8) -> Option<()> {
        (self.u8()? == t).then_some(())
    }
    fn bytes(&mut self) -> Option<Range<usize>> {
        let n = self.u32()?;
        self.take(n)
    }
    fn str(&mut self) -> Option<String> {
        let r = self.bytes()?;
        String::from_utf8(self.b[r].to_vec()).ok()
    }
    fn opt<T>(&mut self, f: impl FnOnce(&mut Self) -> Option<T>) -> Option<Option<T>> {
        match self.u8()? {
            0 => Some(None),
            1 => f(self).map(Some),
            _ => None,
        }
    }
    fn value(&mut self, depth: u32) -> Option<()> {
        if depth > 64 {
            return None;
        }
        match self.u8()? {
            0..=2 => Some(()),
            3 | 4 => self.bytes().map(|_| ()),
            5 => {
                for _ in 0..self.u32()? {
                    self.value(depth + 1)?;
                }
                Some(())
            }
            6 => {
                for _ in 0..self.u32()? {
                    self.bytes()?;
                    self.value(depth + 1)?;
                }
                Some(())
            }
            _ => None,
        }
    }
}

pub fn parse(b: &[u8]) -> Option<Fields> {
    let mut r = R { b, at: 0 };
    if b.get(..8)? != b"BOGOREQ\0" {
        return None;
    }
    r.take(8)?;
    let v = r.take(2)?;
    if b[v] != [0, 1] {
        return None;
    }
    r.tag(1)?;
    let bogo_id = r.bytes()?;
    r.tag(2)?;
    let upstream = r.str()?;
    r.tag(3)?;
    let tool = r.str()?;
    r.tag(4)?;
    r.opt(|r| r.value(0))?;
    r.tag(5)?;
    let justification = r.opt(|r| r.str())?;
    r.tag(6)?;
    for _ in 0..r.u32()? {
        for _ in 0..r.u32()? {
            match r.u8()? {
                0 => {
                    r.str()?;
                }
                1 => {
                    r.take(4)?;
                }
                _ => return None,
            }
        }
        r.opt(|r| r.str())?;
    }
    r.tag(7)?;
    let agent = r.bytes()?;
    r.tag(8)?;
    let agent_name = r.str()?;
    r.tag(9)?;
    r.opt(|r| r.str())?;
    r.tag(10)?;
    r.bytes()?;
    r.tag(11)?;
    let nonce = r.bytes()?;
    r.tag(12)?;
    let created = r.take(8)?;
    r.tag(13)?;
    let expires = r.opt(|r| r.take(8))?;
    if r.at != b.len() || bogo_id.len() != 32 || nonce.len() != 40 {
        return None;
    }
    Some(Fields {
        bogo_id,
        upstream,
        tool,
        justification,
        agent_id: b[agent].to_vec(),
        agent_name,
        nonce,
        created,
        expires,
    })
}

fn u64_at(b: &[u8], r: &Range<usize>) -> u64 {
    u64::from_be_bytes(b[r.clone()].try_into().unwrap_or_default())
}

/// A vector's bytes with this boot's nonce, the current time, the same expiry
/// lifetime if it has one, and (unless kept) this Mac's bogoId.
pub fn restamp(vector: &[u8], bogo_id: Option<&[u8; 32]>, nonce: &[u8; 40], now_ms: u64) -> Option<Vec<u8>> {
    let f = parse(vector)?;
    let mut b = vector.to_vec();
    if let Some(id) = bogo_id {
        b[f.bogo_id.clone()].copy_from_slice(id);
    }
    b[f.nonce.clone()].copy_from_slice(nonce);
    let created = u64_at(vector, &f.created);
    b[f.created.clone()].copy_from_slice(&now_ms.to_be_bytes());
    if let Some(e) = &f.expires {
        let lifetime = u64_at(vector, e).saturating_sub(created).clamp(60_000, 3_600_000);
        b[e.clone()].copy_from_slice(&(now_ms + lifetime).to_be_bytes());
    }
    parse(&b).map(|_| b)
}
