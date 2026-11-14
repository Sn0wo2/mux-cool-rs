use std::io;

use socksaddr::SocksAddr;

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
        let Some((&meta_len, rest)) = buf.split_first_chunk() else {
            return Ok(Vec::new());
        };
        let meta_len = usize::from(u16::from_be_bytes(meta_len));
        if meta_len > 512 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mux.cool metadata length",
            ));
        }
        let Some((meta, rest)) = rest.split_at_checked(meta_len) else {
            return Ok(Vec::new());
        };
        let Some((&[sid_0, sid_1, status, option], target)) = meta.split_first_chunk() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mux.cool metadata",
            ));
        };
        let sid = u32::from(u16::from_be_bytes([sid_0, sid_1]));
        if !matches!(status, 1..=4) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mux.cool status",
            ));
        }
        let (data, rest) = if option & 1 != 0 {
            let Some((&data_len, rest)) = rest.split_first_chunk() else {
                return Ok(Vec::new());
            };
            let Some(payload) = rest.split_at_checked(usize::from(u16::from_be_bytes(data_len)))
            else {
                return Ok(Vec::new());
            };
            payload
        } else {
            (&[][..], rest)
        };
        let mut events = Vec::with_capacity(2);
        match status {
            1 => {
                let Some((&network, address_bytes)) = target.split_first() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid mux.cool new frame",
                    ));
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
                        if !data.is_empty() {
                            events.push(Event::Data {
                                sid,
                                data: data.to_vec(),
                            });
                        }
                    }
                    2 => events.push(Event::Reject { sid }),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid mux.cool network",
                        ));
                    }
                }
            }
            2 => {
                if target.first() == Some(&2) {
                    events.push(Event::Reject { sid });
                } else if !data.is_empty() {
                    events.push(Event::Data {
                        sid,
                        data: data.to_vec(),
                    });
                }
            }
            3 => {
                if option & 2 != 0 {
                    events.push(Event::Reset { sid });
                } else {
                    events.push(Event::Eof { sid });
                }
            }
            _ => {}
        }
        buf.drain(..buf.len() - rest.len());
        Ok(events)
    }

    pub const fn chunk_limit(&self) -> usize {
        u16::MAX as usize
    }

    pub fn data_frame(&self, sid: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + data.len());
        let [_, _, sid_0, sid_1] = sid.to_be_bytes();
        out.extend_from_slice(&[0, 4, sid_0, sid_1, 2, 1]);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    pub fn eof_frame(&self, sid: u32) -> Vec<u8> {
        let [_, _, sid_0, sid_1] = sid.to_be_bytes();
        vec![0, 4, sid_0, sid_1, 3, 0]
    }

    pub fn reset_frame(&self, sid: u32) -> Vec<u8> {
        let [_, _, sid_0, sid_1] = sid.to_be_bytes();
        vec![0, 4, sid_0, sid_1, 3, 2]
    }
}
