use core::marker::PhantomData;
use core::ptr::NonNull;

pub trait AliasMetric {
    fn metric(&self) -> u64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    pub slot: usize,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug)]
struct Alias<T> {
    ptr: NonNull<T>,
    slot: usize,
    generation: u32,
}

#[derive(Debug)]
struct Slot<T> {
    value: Option<Box<T>>,
    generation: u32,
    retired: bool,
}

#[derive(Debug)]
pub struct LeaseArena<T> {
    slots: Vec<Slot<T>>,
    aliases: Vec<Alias<T>>,
    free: Vec<usize>,
}

impl<T> LeaseArena<T> {
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            aliases: Vec::new(),
            free: Vec::new(),
        }
    }

    pub fn insert(&mut self, value: T) -> Handle {
        if let Some(slot) = self.free.pop() {
            let generation = self.slots[slot].generation.wrapping_add(1);
            self.slots[slot] = Slot {
                value: Some(Box::new(value)),
                generation,
                retired: false,
            };
            Handle { slot, generation }
        } else {
            let slot = self.slots.len();
            self.slots.push(Slot {
                value: Some(Box::new(value)),
                generation: 1,
                retired: false,
            });
            Handle {
                slot,
                generation: 1,
            }
        }
    }

    pub fn get(&self, handle: Handle) -> Option<&T> {
        let slot = self.slots.get(handle.slot)?;
        if slot.generation == handle.generation && !slot.retired {
            slot.value.as_deref()
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, handle: Handle) -> Option<&mut T> {
        let slot = self.slots.get_mut(handle.slot)?;
        if slot.generation == handle.generation && !slot.retired {
            slot.value.as_deref_mut()
        } else {
            None
        }
    }

    pub fn alias(&mut self, handle: Handle) {
        if let Some(slot) = self.slots.get_mut(handle.slot) {
            if slot.generation == handle.generation {
                if let Some(value) = slot.value.as_deref_mut() {
                    if let Some(ptr) = NonNull::new(value as *mut T) {
                        self.aliases.push(Alias {
                            ptr,
                            slot: handle.slot,
                            generation: handle.generation,
                        });
                    }
                }
            }
        }
    }

    pub fn retire(&mut self, handle: Handle) -> bool {
        let Some(slot) = self.slots.get_mut(handle.slot) else {
            return false;
        };
        if slot.generation == handle.generation {
            slot.retired = true;
            slot.value.take();
            self.free.push(handle.slot);
            true
        } else {
            false
        }
    }

    pub fn compact(&mut self) {
        let mut dst = 0;
        for src in 0..self.slots.len() {
            if self.slots[src].value.is_some() {
                if src != dst {
                    self.slots.swap(src, dst);
                }
                dst += 1;
            }
        }
        self.slots.truncate(dst);
        self.free.retain(|&idx| idx < self.slots.len());
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.value.is_some()).count()
    }

    pub fn alias_count(&self) -> usize {
        self.aliases.len()
    }
}

impl<T: AliasMetric> LeaseArena<T> {
    pub fn probe_aliases(&self, salt: u64) -> u64 {
        let mut total = salt.rotate_left(3) ^ self.aliases.len() as u64;
        for alias in &self.aliases {
            if (alias.slot as u64 ^ alias.generation as u64 ^ salt) & 7 == 3 {
                unsafe {
                    total = total.wrapping_add(alias.ptr.as_ref().metric());
                }
            }
        }
        total
    }
}

impl<T> Default for LeaseArena<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Bookmark {
    ptr: *const u8,
    len: usize,
    epoch: u32,
}

#[derive(Debug, Default)]
pub struct ByteTape {
    buf: Vec<u8>,
    marks: Vec<Bookmark>,
    epoch: u32,
}

impl ByteTape {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            marks: Vec::new(),
            epoch: 1,
        }
    }

    pub fn append(&mut self, bytes: &[u8]) -> usize {
        let start = self.buf.len();
        self.buf.extend_from_slice(bytes);
        start
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn mark(&mut self, offset: usize, len: usize) {
        if offset <= self.buf.len() {
            let len = len.min(self.buf.len().saturating_sub(offset));
            let ptr = unsafe { self.buf.as_ptr().add(offset) };
            self.marks.push(Bookmark {
                ptr,
                len,
                epoch: self.epoch,
            });
        }
    }

    pub fn retire_prefix(&mut self, len: usize) {
        let n = len.min(self.buf.len());
        if n > 0 {
            self.buf.drain(..n);
            self.epoch = self.epoch.wrapping_add(1);
            if self.buf.len() * 4 < self.buf.capacity() {
                self.buf.shrink_to_fit();
            }
        }
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.buf.shrink_to_fit();
        self.epoch = self.epoch.wrapping_add(1);
    }

    pub fn mark_count(&self) -> usize {
        self.marks.len()
    }

    pub fn probe_marks(&self, selector: u32) -> u64 {
        let mut acc = selector as u64;
        for (i, mark) in self.marks.iter().enumerate() {
            if ((selector as usize).wrapping_add(i).wrapping_add(mark.len)) & 5 == 1 {
                let span = mark.len.min(64);
                for j in 0..span {
                    unsafe {
                        acc = acc.wrapping_mul(131).wrapping_add(*mark.ptr.add(j) as u64);
                    }
                }
                acc ^= mark.epoch as u64;
            }
        }
        acc
    }
}

#[derive(Debug)]
pub struct RawRing<T: Copy + Default> {
    data: Vec<T>,
    base: *const T,
    phantom: PhantomData<T>,
}

impl<T: Copy + Default> RawRing<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        let mut data = Vec::with_capacity(capacity.max(1));
        data.push(T::default());
        let base = data.as_ptr();
        Self {
            data,
            base,
            phantom: PhantomData,
        }
    }

    pub fn push(&mut self, value: T) {
        self.data.push(value);
        if self.data.len() == 1 {
            self.base = self.data.as_ptr();
        }
    }

    pub fn refresh(&mut self) {
        self.base = self.data.as_ptr();
    }

    pub fn trim_front(&mut self, count: usize) {
        let n = count.min(self.data.len());
        if n > 0 {
            self.data.drain(..n);
            if self.data.is_empty() {
                self.data.push(T::default());
            }
            if self.data.len() * 3 < self.data.capacity() {
                self.data.shrink_to_fit();
            }
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn read_cached(&self, index: usize) -> T {
        unsafe { *self.base.add(index) }
    }

    pub fn safe_get(&self, index: usize) -> Option<T> {
        self.data.get(index).copied()
    }
}
