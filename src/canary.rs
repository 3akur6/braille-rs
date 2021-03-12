use crate::{
    braille::Braille,
    cluster::{Frame, WordLike},
    payload::Payload,
};

#[derive(Debug)]
pub struct Canary {
    exist: bool,
    value: Option<Frame>,
}

impl Canary {
    pub fn exist(&self) -> bool {
        self.exist
    }

    fn get(braille: &mut Braille) -> Option<Self> {
        let mut payload = Payload::through_overflow(braille)?;
        payload.push(0x00);

        if let Ok(mut read) = braille.stack_read_word(&payload, 7) {
            read.insert(0, 0x00);
            Some(Canary {
                exist: true,
                value: Some(Frame::from_vec(read.to_vec())),
            })
        } else {
            Some(Canary {
                exist: false,
                value: None,
            })
        }
    }

    pub fn new(braille: &mut Braille) -> Option<Self> {
        Self::get(braille)
    }

    pub fn value(&self) -> Option<&Frame> {
        self.value.as_ref()
    }
}
