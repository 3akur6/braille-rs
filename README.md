## braille-rs

tool for brop ([Blind return oriented programming](https://en.wikipedia.org/wiki/Blind_return_oriented_programming)) attack

this exploit technique is clearly demonstrated in the paper '[Hacking Blind](http://www.scs.stanford.edu/brop/bittau-brop.pdf)' and [PoC](http://www.scs.stanford.edu/brop/braille.rb) is available

**braille-rs** tests on [Ali's server](http://www.scs.stanford.edu/brop/a.out), expected to be a **one-stop** facility to implement a full brop attack

TODO
----
1) refact single thread to multithread in intensive IO operations
2) find new ways to locate useful gadgets more precisely
3) reconstruct code to be more 'Rustacean' (laugh~~)
