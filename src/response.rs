use crate::cluster::Cluster;

#[derive(Debug)]
pub enum ReturnCode {
    Crash,
    NoCrash,
    Infinite,
}

pub type ReturnVal = Cluster;

pub struct Response {
    pub code: ReturnCode,
    pub value: ReturnVal,
}
