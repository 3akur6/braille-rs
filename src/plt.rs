use std::fmt;

use crate::{
    braille::Braille,
    cluster::{Frame, FrameLike},
    gadget::{Gadget, Gadgets},
};

#[derive(Debug)]
pub struct PLT(Gadgets);

impl PLT {
    pub fn succ_item(gadget: &Gadget) -> Gadget {
        Gadget(Frame::from_u64(gadget.to_frame().to_u64() + 0x10))
    }

    pub fn pred_item(gadget: &Gadget) -> Gadget {
        Gadget(Frame::from_u64(gadget.to_frame().to_u64() - 0x10))
    }

    pub fn get(braille: &mut Braille) -> Option<PLT> {
        let gadgets = braille.get_gadgets()?.to_owned();
        let mut cache = Gadgets::new();
        for gadget in gadgets.0.iter() {
            if gadget.to_u64() & 0xf == 0 {
                let other = gadget.to_owned() + 6;
                if gadgets.contains(&other)
                    && (gadgets.contains(&Self::succ_item(gadget))
                        || gadgets.contains(&Self::pred_item(gadget)))
                {
                    cache.push(gadget.to_owned());
                }
            }
        }

        if cache.len() > 0 {
            Some(PLT(cache))
        } else {
            None
        }
    }

    pub fn items(&self) -> &Gadgets {
        &self.0
    }
}

impl fmt::Display for PLT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}
