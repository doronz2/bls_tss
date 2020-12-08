#![allow(non_snake_case)]

pub mod party;
pub mod test;


#[derive(Clone, Debug)]
pub struct ErrorType {
    error_type: String,
    bad_actors: Vec<usize>,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
#[allow(non_camel_case_types)]
pub enum Error{
    InvalidSS_phase1,
    InvalidSS_Phase2,
    InvalidPartialSig
}
