use crate::{
    braille::Braille,
    cluster::{Offset, Word},
    payload::Payload,
    response::ReturnCode,
};

#[derive(Debug)]
pub struct Overflow(pub Option<usize>);

impl Overflow {
    fn get(braille: &mut Braille) -> Option<Offset> {
        let mut step = 8;
        let mut start = 8;

        loop {
            let rc = {
                let payload = Payload(Word(vec![b'A'; start]));
                braille.probe(&payload)?
            };
            match rc {
                ReturnCode::Crash => {
                    start -= step;
                    break;
                }
                ReturnCode::NoCrash => {
                    start += step;
                }
                _ => return None,
            }
        }

        loop {
            step /= 2;
            let rc = {
                let payload = Payload(Word(vec![b'A'; start + step]));
                braille.probe(&payload)?
            };
            if let ReturnCode::NoCrash = rc {
                start += step;
            }
            if step == 1 {
                return Some(start);
            }
        }
    }

    pub fn new(braille: &mut Braille) -> Self {
        Self(Self::get(braille))
    }

    pub fn value(&self) -> Option<Offset> {
        self.0
    }
}
