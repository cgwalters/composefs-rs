use std::ffi::c_void;
use std::io::{Read, Seek};
use std::mem::ManuallyDrop;
use std::os::fd::{BorrowedFd, FromRawFd};

use libc::{c_int, ssize_t};
use zerocopy::IntoBytes;

use composefs::fsverity::{self, EnableVerityError, MeasureVerityError, Sha256HashValue};

use crate::errno::set_errno;
use crate::{FfiNode, LCFS_DIGEST_SIZE};

type LcfsReadCb = unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> ssize_t;

fn copy_hash_to_digest(hash: &Sha256HashValue, digest: *mut u8) {
    let bytes = hash.as_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), digest, LCFS_DIGEST_SIZE);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_compute_fsverity_from_data(
    digest: *mut u8,
    data: *mut u8,
    data_len: usize,
) -> c_int {
    if digest.is_null() || data.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    let input = unsafe { std::slice::from_raw_parts(data, data_len) };
    let hash = fsverity::compute_verity::<Sha256HashValue>(input);
    copy_hash_to_digest(&hash, digest);
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_compute_fsverity_from_fd(digest: *mut u8, fd: c_int) -> c_int {
    if digest.is_null() || fd < 0 {
        set_errno(libc::EINVAL);
        return -1;
    }

    let mut file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    if file.seek(std::io::SeekFrom::Start(0)).is_err() {
        set_errno(libc::EIO);
        return -1;
    }
    let mut data = Vec::new();
    if file.read_to_end(&mut data).is_err() {
        set_errno(libc::EIO);
        return -1;
    }

    let hash = fsverity::compute_verity::<Sha256HashValue>(&data);
    copy_hash_to_digest(&hash, digest);
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_compute_fsverity_from_content(
    digest: *mut u8,
    file: *mut c_void,
    read_cb: LcfsReadCb,
) -> c_int {
    if digest.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    let mut data = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = unsafe { read_cb(file, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n < 0 {
            set_errno(libc::EIO);
            return -1;
        }
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n as usize]);
    }

    let hash = fsverity::compute_verity::<Sha256HashValue>(&data);
    copy_hash_to_digest(&hash, digest);
    0
}

const ENOVERITY: c_int = libc::ENOTTY;

fn measure_error_to_errno(e: &MeasureVerityError) -> c_int {
    match e {
        MeasureVerityError::VerityMissing | MeasureVerityError::FilesystemNotSupported => ENOVERITY,
        MeasureVerityError::Io(io_err) => {
            let raw = io_err.raw_os_error().unwrap_or(libc::EIO);
            if raw == libc::ENODATA || raw == libc::EOPNOTSUPP || raw == libc::ENOTTY {
                ENOVERITY
            } else {
                raw
            }
        }
        _ => libc::EIO,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_fd_measure_fsverity(digest: *mut u8, fd: c_int) -> c_int {
    if digest.is_null() || fd < 0 {
        set_errno(libc::EINVAL);
        return -1;
    }

    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    match fsverity::measure_verity::<Sha256HashValue>(borrowed) {
        Ok(hash) => {
            copy_hash_to_digest(&hash, digest);
            0
        }
        Err(ref e) => {
            let err = measure_error_to_errno(e);
            set_errno(err);
            -(err)
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_fd_get_fsverity(digest: *mut u8, fd: c_int) -> c_int {
    if digest.is_null() || fd < 0 {
        set_errno(libc::EINVAL);
        return -1;
    }

    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    match fsverity::measure_verity_opt::<Sha256HashValue>(borrowed) {
        Ok(Some(hash)) => {
            copy_hash_to_digest(&hash, digest);
            0
        }
        Ok(None) => {
            set_errno(libc::ENODATA);
            -(libc::ENODATA)
        }
        Err(ref e) => {
            let err = measure_error_to_errno(e);
            set_errno(err);
            -(err)
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_fd_enable_fsverity(fd: c_int) -> c_int {
    if fd < 0 {
        set_errno(libc::EINVAL);
        return -1;
    }

    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    match fsverity::enable_verity_raw::<Sha256HashValue>(borrowed) {
        Ok(()) => 0,
        Err(EnableVerityError::AlreadyEnabled) => 0,
        Err(EnableVerityError::Io(ref io_err)) => {
            let errno_val = io_err.raw_os_error().unwrap_or(libc::EIO);
            -(errno_val)
        }
        Err(_) => {
            set_errno(libc::ENOTSUP);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_fsverity_from_content(
    node: *mut FfiNode,
    file: *mut c_void,
    read_cb: LcfsReadCb,
) -> c_int {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    let mut digest = [0u8; LCFS_DIGEST_SIZE];
    let ret = unsafe { lcfs_compute_fsverity_from_content(digest.as_mut_ptr(), file, read_cb) };
    if ret < 0 {
        return ret;
    }

    unsafe {
        (*node).digest = digest;
        (*node).digest_set = true;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_fsverity_from_fd(node: *mut FfiNode, fd: c_int) -> c_int {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    let mut digest = [0u8; LCFS_DIGEST_SIZE];
    let ret = unsafe { lcfs_compute_fsverity_from_fd(digest.as_mut_ptr(), fd) };
    if ret < 0 {
        return ret;
    }

    unsafe {
        (*node).digest = digest;
        (*node).digest_set = true;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_from_content(
    node: *mut FfiNode,
    dirfd: c_int,
    fname: *const libc::c_char,
    _buildflags: c_int,
) -> c_int {
    if node.is_null() || fname.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    unsafe {
        let fd = libc::openat(dirfd, fname, libc::O_RDONLY);
        if fd < 0 {
            return -1;
        }

        let mut file = std::fs::File::from_raw_fd(fd);
        let mut data = Vec::new();
        if file.read_to_end(&mut data).is_err() {
            set_errno(libc::EIO);
            return -1;
        }

        (*node).content = Some(data.clone());
        (*node).size = data.len() as u64;

        let hash = fsverity::compute_verity::<Sha256HashValue>(&data);
        (*node).digest.copy_from_slice(hash.as_bytes());
        (*node).digest_set = true;

        0
    }
}
