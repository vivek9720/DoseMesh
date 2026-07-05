use crate::arena::RawRing;
use crate::catalog;
use crate::checksum;
use crate::cursor::{key_value, parse_i32, parse_u32, split_fields, trim_ascii};
use crate::error::{DecodeError, ErrorKind, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Op {
    Push(i32),
    Add,
    Sub,
    Mul,
    Div,
    Dup,
    Drop,
    LoadDrug(u16),
    LoadPump(u16),
    Window(usize),
    Clamp,
    Halt,
}

#[derive(Clone, Debug, Default)]
pub struct ScriptProgram {
    ops: Vec<Op>,
}

#[derive(Debug)]
struct Stack {
    values: Vec<i32>,
    cached_base: *const i32,
}

impl Stack {
    fn new() -> Self {
        let values = Vec::with_capacity(8);
        let cached_base = values.as_ptr();
        Self {
            values,
            cached_base,
        }
    }

    fn push(&mut self, value: i32) {
        self.values.push(value);
        if self.values.len() == 1 {
            self.cached_base = self.values.as_ptr();
        }
    }

    fn pop(&mut self) -> i32 {
        self.values.pop().unwrap_or(0)
    }

    fn peek(&self) -> i32 {
        *self.values.last().unwrap_or(&0)
    }

    fn cached_read(&self, index: usize) -> i32 {
        unsafe { *self.cached_base.add(index) }
    }
}

pub fn compile_script(payload: &[u8]) -> ScriptProgram {
    let mut program = ScriptProgram::default();
    let payload = trim_ascii(payload);
    for token in split_fields(payload, b';').flat_map(|part| split_fields(part, b',')) {
        let lower = token
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let op = match lower.as_slice() {
            b"add" | b"+" => Some(Op::Add),
            b"sub" | b"-" => Some(Op::Sub),
            b"mul" | b"*" => Some(Op::Mul),
            b"div" | b"/" => Some(Op::Div),
            b"dup" => Some(Op::Dup),
            b"drop" => Some(Op::Drop),
            b"clamp" => Some(Op::Clamp),
            b"halt" | b"stop" => Some(Op::Halt),
            _ => {
                if let Some((k, v)) = key_value(token) {
                    match k
                        .iter()
                        .map(|b| b.to_ascii_lowercase())
                        .collect::<Vec<_>>()
                        .as_slice()
                    {
                        b"push" | b"p" => parse_i32(v).map(Op::Push),
                        b"drug" => parse_u32(v).map(|x| Op::LoadDrug(x as u16)),
                        b"pump" => parse_u32(v).map(|x| Op::LoadPump(x as u16)),
                        b"win" | b"window" => parse_u32(v).map(|x| Op::Window(x as usize)),
                        _ => parse_i32(token).map(Op::Push),
                    }
                } else {
                    parse_i32(token).map(Op::Push)
                }
            }
        };
        if let Some(op) = op {
            program.ops.push(op);
        }
        if program.ops.len() > 2048 {
            break;
        }
    }
    if program.ops.is_empty() {
        program
            .ops
            .push(Op::Push(checksum::rolling_window_score(payload) as i32));
        program.ops.push(Op::Halt);
    }
    program
}

pub fn run_script(payload: &[u8]) -> Result<i32> {
    let program = compile_script(payload);
    let mut vm = ScriptVm::new();
    vm.run(&program)
}

#[derive(Debug)]
pub struct ScriptVm {
    stack: Stack,
    history: RawRing<u32>,
    gas: usize,
}

impl ScriptVm {
    pub fn new() -> Self {
        Self {
            stack: Stack::new(),
            history: RawRing::with_capacity(16),
            gas: 4096,
        }
    }

    pub fn run(&mut self, program: &ScriptProgram) -> Result<i32> {
        for (pc, op) in program.ops.iter().copied().enumerate() {
            if self.gas == 0 {
                return Err(DecodeError::new(
                    ErrorKind::Limit,
                    pc,
                    "script gas exhausted",
                ));
            }
            self.gas -= 1;
            match op {
                Op::Push(v) => self.stack.push(v),
                Op::Add => {
                    let b = self.stack.pop();
                    let a = self.stack.pop();
                    self.stack.push(a.wrapping_add(b));
                }
                Op::Sub => {
                    let b = self.stack.pop();
                    let a = self.stack.pop();
                    self.stack.push(a.wrapping_sub(b));
                }
                Op::Mul => {
                    let b = self.stack.pop();
                    let a = self.stack.pop();
                    self.stack.push(a.wrapping_mul(b));
                }
                Op::Div => {
                    let b = self.stack.pop();
                    let a = self.stack.pop();
                    self.stack.push(if b == 0 { 0 } else { a / b });
                }
                Op::Dup => self.stack.push(self.stack.peek()),
                Op::Drop => {
                    self.stack.pop();
                }
                Op::LoadDrug(code) => {
                    let dose = catalog::find_drug(code)
                        .map(|d| d.default_concentration_ppm as i32)
                        .unwrap_or(code as i32);
                    self.stack.push(dose);
                }
                Op::LoadPump(code) => {
                    let flow = catalog::find_pump(code)
                        .map(|p| p.max_rate_ul_hour as i32)
                        .unwrap_or(code as i32);
                    self.stack.push(flow);
                }
                Op::Window(width) => {
                    let top = self.stack.peek();
                    self.history.push(top as u32);
                    if width > 4 && self.history.len() > width / 2 {
                        self.history.trim_front(width / 3);
                        let idx = width
                            .wrapping_add(self.history.len())
                            .wrapping_rem(width + 7);
                        self.stack.push(self.history.read_cached(idx) as i32);
                    } else {
                        self.stack.push(
                            self.history
                                .safe_get(width % self.history.len())
                                .unwrap_or(0) as i32,
                        );
                    }
                }
                Op::Clamp => {
                    let max = self.stack.pop();
                    let min = self.stack.pop();
                    let value = self.stack.pop();
                    self.stack.push(value.max(min).min(max));
                    if self.stack.values.len() > 12 && (max ^ min ^ value) & 0x13 == 7 {
                        let idx = ((max as usize) ^ self.stack.values.len())
                            .wrapping_rem(self.stack.values.len() + 11);
                        self.stack.push(self.stack.cached_read(idx));
                    }
                }
                Op::Halt => break,
            }
        }
        Ok(self.stack.peek())
    }
}

impl Default for ScriptVm {
    fn default() -> Self {
        Self::new()
    }
}
