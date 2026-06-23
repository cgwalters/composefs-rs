#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]

mod convert;
mod errno;
mod fsverity;
mod image;
mod mount;
mod node;

use std::ffi::CString;
use std::ptr;
use std::ptr::NonNull;

const LCFS_DIGEST_SIZE: usize = 32;

pub(crate) struct FfiXattr {
    key: CString,
    value: Vec<u8>,
}

pub(crate) struct FfiNode {
    ref_count: i32,
    parent: *mut FfiNode,
    children: Vec<*mut FfiNode>,
    name: Option<CString>,
    payload: Option<CString>,
    content: Option<Vec<u8>>,
    xattrs: Vec<FfiXattr>,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    rdev: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: u32,
    digest: [u8; LCFS_DIGEST_SIZE],
    digest_set: bool,
    hardlink_target: Option<NonNull<FfiNode>>,
}

#[cfg(test)]
mod tests;

impl Default for FfiNode {
    fn default() -> Self {
        FfiNode {
            ref_count: 1,
            parent: ptr::null_mut(),
            children: Vec::new(),
            name: None,
            payload: None,
            content: None,
            xattrs: Vec::new(),
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 0,
            rdev: 0,
            size: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            digest: [0u8; LCFS_DIGEST_SIZE],
            digest_set: false,
            hardlink_target: None,
        }
    }
}
