use std::io;

use socksaddr::SocksAddr;
use utils::end_frame;

mod utils;

const NEW: u8 = 1;
const KEEP: u8 = 2;
const END: u8 = 3;
const KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const MAX_META: usize = 512;

#[derive(Debug)]
#[allow(clippy::exhaustive_enums)]
pub enum Event {
    Open { sid: u32, target: SocksAddr },
    Data { sid: u32, data: Vec<u8> },
    Eof { sid: u32 },
    Reset { sid: u32 },
    Reject { sid: u32 },
}

#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::exhaustive_structs)]
pub struct Decoder;

impl Decoder {
    pub fn decode(&self, buf: &mut Vec<u8>) -> io::Result<Vec<Event>> {
        let Some(frame_len) = buf
            .get(..2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        else {
            return Ok(Vec::new());
        };
        let meta_len = usize::from(u16::from_be_bytes(frame_len));
        if meta_len > MAX_META {
            return Err(invalid("invalid mux.cool metadata length"));
        }
        let Some(meta) = buf.get(2..2 + meta_len) else {
            return Ok(Vec::new());
        };
        let Some([sid_0, sid_1, status, option]) = meta
            .get(..4)
            .and_then(|header| <[u8; 4]>::try_from(header).ok())
        else {
            return Err(invalid("invalid mux.cool metadata"));
        };
        let sid = u32::from(u16::from_be_bytes([sid_0, sid_1]));
        if !matches!(status, NEW | KEEP | END | KEEP_ALIVE) {
            return Err(invalid("invalid mux.cool status"));
        }
        let (data_len, data) = if option & OPTION_DATA != 0 {
            let Some(data_len_bytes) = buf
                .get(2 + meta_len..4 + meta_len)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            else {
                return Ok(Vec::new());
            };
            let data_len = usize::from(u16::from_be_bytes(data_len_bytes));
            let Some(data) = buf.get(4 + meta_len..4 + meta_len + data_len) else {
                return Ok(Vec::new());
            };
            (Some(data_len), Some(data.to_vec()))
        } else {
            (None, None)
        };
        let mut events = Vec::with_capacity(2);
        match status {
            NEW => {
                let Some((&network, address_bytes)) =
                    meta.get(4..).and_then(|tail| tail.split_first())
                else {
                    return Err(invalid("invalid mux.cool new frame"));
                };
                let (addr, _) = SocksAddr::parse_xray(address_bytes).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid mux.cool target: {err}"),
                    )
                })?;
                match network {
                    1 if sid == 0 => events.push(Event::Reject { sid }),
                    1 => {
                        events.push(Event::Open { sid, target: addr });
                        if let Some(data) = data.filter(|data| !data.is_empty()) {
                            events.push(Event::Data { sid, data });
                        }
                    }
                    2 => events.push(Event::Reject { sid }),
                    _ => return Err(invalid("invalid mux.cool network")),
                }
            }
            KEEP => {
                if meta.get(4).copied() == Some(2) {
                    events.push(Event::Reject { sid });
                } else if let Some(data) = data.filter(|data| !data.is_empty()) {
                    events.push(Event::Data { sid, data });
                }
            }
            END => {
                if option & OPTION_ERROR != 0 {
                    events.push(Event::Reset { sid });
                } else {
                    events.push(Event::Eof { sid });
                }
            }
            KEEP_ALIVE => {}
            _ => return Err(invalid("invalid mux.cool status")),
        }
        buf.drain(..2 + meta_len + data_len.map_or(0, |len| 2 + len));
        Ok(events)
    }

    pub const fn chunk_limit(&self) -> usize {
        u16::MAX as usize
    }

    pub fn data_frame(&self, sid: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + data.len());
        out.extend_from_slice(&4_u16.to_be_bytes());
        let [_, _, sid_0, sid_1] = sid.to_be_bytes();
        out.extend_from_slice(&[sid_0, sid_1]);
        out.push(KEEP);
        out.push(OPTION_DATA);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    pub fn eof_frame(&self, sid: u32) -> Vec<u8> {
        end_frame(sid, false)
    }

    pub fn reset_frame(&self, sid: u32) -> Vec<u8> {
        end_frame(sid, true)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
