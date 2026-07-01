//! Ties the kernel (`kallsyms`) and user-space (`usersym`) resolvers
//! together into a single "resolve this IP" facade, and carries the
//! kernel/user/unknown distinction through to the SVG renderer for
//! color-coding.

use crate::kallsyms::Kallsyms;
use crate::usersym::UserSymbolCache;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Kernel,
    User,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Frame {
    Kernel(String),
    User(String),
    Unknown,
}

impl Frame {
    pub fn label(&self) -> String {
        match self {
            Frame::Kernel(s) | Frame::User(s) => s.clone(),
            Frame::Unknown => "[unknown]".to_string(),
        }
    }

    pub fn kind(&self) -> FrameKind {
        match self {
            Frame::Kernel(_) => FrameKind::Kernel,
            Frame::User(_) => FrameKind::User,
            Frame::Unknown => FrameKind::Unknown,
        }
    }
}

pub fn resolve_kernel(kallsyms: &Kallsyms, ip: u64) -> Frame {
    match kallsyms.resolve(ip) {
        Some((name, 0)) => Frame::Kernel(name.to_string()),
        Some((name, off)) => Frame::Kernel(format!("{name}+0x{off:x}")),
        None => Frame::Unknown,
    }
}

pub fn resolve_user(usersyms: &mut UserSymbolCache, pid: u32, ip: u64) -> Frame {
    match usersyms.resolve(pid, ip) {
        Some((name, 0)) => Frame::User(name),
        Some((name, off)) => Frame::User(format!("{name}+0x{off:x}")),
        None => Frame::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_label_includes_offset_when_nonzero() {
        assert_eq!(Frame::Kernel("do_idle".into()).label(), "do_idle");
        assert_eq!(Frame::User("main+0x10".into()).label(), "main+0x10");
        assert_eq!(Frame::Unknown.label(), "[unknown]");
    }

    #[test]
    fn frame_kind_matches_variant() {
        assert_eq!(Frame::Kernel("x".into()).kind(), FrameKind::Kernel);
        assert_eq!(Frame::User("x".into()).kind(), FrameKind::User);
        assert_eq!(Frame::Unknown.kind(), FrameKind::Unknown);
    }
}
