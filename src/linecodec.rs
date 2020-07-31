use std::{io, str};
use tokio_util::codec::{Decoder, Encoder};
use bytes::BytesMut;
use crate::maws::MAWSMessageKind;

pub struct LineCodec;

impl Decoder for LineCodec {
    type Item = MAWSMessageKind;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let newline = src.as_ref().iter().position(|b| *b == b'\n');
        if let Some(n) = newline {
            let line = src.split_to(n + 1);
            return match str::from_utf8(line.as_ref()) {
                Ok(s) => {
                    // strip the ascii (dec) 1,2,3 codes used by MAWS over serial line
                    let utf_string = s.to_string().replace("\u{1}", "").replace("\u{2}", "").replace("\u{3}", "");
                    Ok(Some(MAWSMessageKind::parse(utf_string)))
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid String")),
            };
        }
        Ok(None)
    }
}

impl Encoder for LineCodec {
    type Item = String;
    type Error = io::Error;

    fn encode(&mut self, _item: Self::Item, _dst: &mut BytesMut) -> Result<(), Self::Error> {
        Ok(())
    }
}

// eof
