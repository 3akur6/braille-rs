use std::fmt;
use std::ops;

pub trait FrameLike {
    fn to_frame(&self) -> Frame;
    fn from_frame(frame: Frame) -> Self;

    fn from_vec(vec: Vec<u8>) -> Self
    where
        Self: std::marker::Sized,
    {
        Self::from_frame(Frame::from_vec(vec))
    }

    fn to_vec(&self) -> Vec<u8> {
        self.to_frame().to_vec()
    }
    fn from_u64(u: u64) -> Self
    where
        Self: std::marker::Sized,
    {
        Self::from_frame(Frame::from_u64(u))
    }

    fn to_u64(&self) -> u64 {
        self.to_frame().to_u64()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Cluster {
    Byte(Byte),
    Frame(Frame),
    Word(Word),
}

#[derive(Debug, PartialEq, Clone)]
pub struct Frame(pub [Byte; 8]);

impl Frame {
    pub fn from_vec(vec: Vec<u8>) -> Self {
        let mut array = [0; 8];
        for (i, byte) in vec.into_iter().enumerate() {
            array[i] = byte;
        }
        Self(array)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn from_u64(u: u64) -> Self {
        Self(u.to_le_bytes())
    }

    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }
}

impl ops::Add<u64> for Frame {
    type Output = Self;

    fn add(self, rhs: u64) -> Self {
        Frame::from_u64(self.to_u64() + rhs)
    }
}

impl ops::BitAnd<u64> for Frame {
    type Output = Self;

    fn bitand(self, rhs: u64) -> Self::Output {
        Frame::from_u64(self.to_u64() & rhs)
    }
}

impl ops::Index<usize> for Frame {
    type Output = Byte;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl ops::IndexMut<usize> for Frame {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018X}", self.to_u64())
    }
}

pub trait WordLike {
    fn insert(&mut self, index: usize, element: u8);

    fn remove(&mut self, index: usize) -> u8;

    fn to_vec(&self) -> Vec<Byte>;

    fn from_vec(vec: Vec<Byte>) -> Self;

    fn push(&mut self, value: u8) {
        self.insert(self.len(), value)
    }

    fn pop(&mut self) -> Option<u8> {
        Some(self.remove(self.len() - 1))
    }

    fn append(&mut self, other: Cluster) {
        match other {
            Cluster::Byte(byte) => self.push(byte),
            Cluster::Frame(frame) => {
                for &i in frame.0.iter() {
                    self.push(i)
                }
            }
            Cluster::Word(word) => {
                for &v in word.0.iter() {
                    self.push(v);
                }
            }
        }
    }

    fn len(&self) -> usize {
        self.to_vec().len()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Word(pub Vec<Byte>);

impl WordLike for Word {
    fn insert(&mut self, index: usize, element: u8) {
        self.0.insert(index, element)
    }

    fn remove(&mut self, index: usize) -> u8 {
        self.0.remove(index)
    }

    fn to_vec(&self) -> Vec<Byte> {
        self.0.to_owned()
    }

    fn from_vec(vec: Vec<Byte>) -> Self {
        Self(vec)
    }
}

impl fmt::Display for Word {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            write!(f, "{:02X}", byte)?;
            if i % 16 == 15 {
                writeln!(f)?;
            } else if i % 8 == 7 {
                write!(f, "  ")?;
            } else {
                write!(f, " ")?;
            }
        }
        Ok(())
    }
}

pub type Byte = u8;
pub type Offset = usize;

pub const OVERFLOW_BUFFER_SIZE: usize = 200;

#[cfg(test)]
mod tests {
    use super::Frame;
    use super::Word;
    use super::WordLike;
    #[test]
    fn test_frame_init() {
        let frame = Frame::from_u64(0x40_0000);
        assert_eq!(frame, Frame([0, 0, 64, 0, 0, 0, 0, 0]));
        let frame = Frame::from_u64(0x400_0000);
        assert_eq!(frame, Frame([0, 0, 0, 4, 0, 0, 0, 0]));
    }

    #[test]
    fn test_frame_add() {
        let frame = Frame::from_u64(0x40_0000);
        assert_eq!(frame + 256, Frame([0, 1, 64, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn test_word_like_trait() {
        let mut word = Word::from_vec(vec![b'a'; 10]);
        word.pop();
        assert_eq!(9, word.len());
    }
}
