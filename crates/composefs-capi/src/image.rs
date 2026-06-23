use std::ffi::{CStr, c_char, c_int, c_void};
use std::io::{Read, Seek};
use std::mem::{ManuallyDrop, MaybeUninit};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
use std::ptr;

use libc::size_t;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawDir, openat, readlinkat, statat};
use zerocopy::IntoBytes;

use crate::FfiNode;
use crate::convert::{ffi_tree_to_filesystem, filesystem_to_ffi_tree};
use crate::errno::set_errno;
use composefs::erofs::format::FormatVersion;
use composefs::erofs::reader::erofs_to_filesystem;
use composefs::erofs::writer::{ValidatedFileSystem, mkfs_erofs_versioned};
use composefs::fsverity::Sha256HashValue;

// C callback types
type LcfsWriteCb = unsafe extern "C" fn(*mut c_void, *mut c_void, size_t) -> isize;
// C struct layout from lcfs-writer.h
#[repr(C)]
pub struct LcfsWriteOptions {
    pub format: u32,
    pub version: u32,
    pub flags: u32,
    pub digest_out: *mut u8,
    pub file: *mut c_void,
    pub file_write_cb: Option<LcfsWriteCb>,
    pub max_version: u32,
    pub reserved: [u32; 3],
    pub reserved2: [*mut c_void; 4],
}

#[repr(C)]
pub struct LcfsReadOptions {
    pub toplevel_entries: *const *const c_char,
    pub reserved: [u32; 3],
    pub reserved2: [*mut c_void; 4],
}

const LCFS_BUILD_COMPUTE_DIGEST: u32 = 1 << 3;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_load_node_from_image(
    image_data: *const u8,
    image_data_size: size_t,
) -> *mut FfiNode {
    unsafe { lcfs_load_node_from_image_ext(image_data, image_data_size, ptr::null()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_load_node_from_image_ext(
    image_data: *const u8,
    image_data_size: size_t,
    options: *const LcfsReadOptions,
) -> *mut FfiNode {
    if image_data.is_null() || image_data_size == 0 {
        set_errno(libc::EINVAL);
        return ptr::null_mut();
    }

    let data = unsafe { std::slice::from_raw_parts(image_data, image_data_size) };

    let fs = match erofs_to_filesystem::<Sha256HashValue>(data) {
        Ok(fs) => fs,
        Err(_) => {
            set_errno(libc::EINVAL);
            return ptr::null_mut();
        }
    };

    let root = filesystem_to_ffi_tree(&fs);

    // Apply toplevel_entries filter if specified
    if !options.is_null() {
        unsafe {
            let opts = &*options;
            if !opts.toplevel_entries.is_null() {
                filter_toplevel(root, opts.toplevel_entries);
            }
        }
    }

    root
}

unsafe fn filter_toplevel(root: *mut FfiNode, entries: *const *const c_char) {
    if root.is_null() || entries.is_null() {
        return;
    }

    unsafe {
        // Collect allowed names
        let mut allowed = Vec::new();
        let mut p = entries;
        while !(*p).is_null() {
            allowed.push(CStr::from_ptr(*p));
            p = p.add(1);
        }

        // Remove children not in the allowed list
        let mut i = 0;
        while i < (*root).children.len() {
            let child = (&(*root).children)[i];
            let keep = (*child)
                .name
                .as_ref()
                .is_some_and(|name| allowed.contains(&name.as_c_str()));
            if keep {
                i += 1;
            } else {
                (*root).children.remove(i);
                (*child).parent = ptr::null_mut();
                crate::node::lcfs_node_unref(child);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_load_node_from_fd(fd: c_int) -> *mut FfiNode {
    unsafe { lcfs_load_node_from_fd_ext(fd, ptr::null()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_load_node_from_fd_ext(
    fd: c_int,
    options: *const LcfsReadOptions,
) -> *mut FfiNode {
    if fd < 0 {
        set_errno(libc::EBADF);
        return ptr::null_mut();
    }

    let mut file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    if file.seek(std::io::SeekFrom::Start(0)).is_err() {
        set_errno(libc::EIO);
        return ptr::null_mut();
    }
    let mut data = Vec::new();
    if file.read_to_end(&mut data).is_err() {
        set_errno(libc::EIO);
        return ptr::null_mut();
    }

    unsafe { lcfs_load_node_from_image_ext(data.as_ptr(), data.len(), options) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_version_from_fd(fd: c_int) -> c_int {
    use composefs::erofs::format::{COMPOSEFS_MAGIC, ComposefsHeader};
    use zerocopy::FromBytes;

    if fd < 0 {
        set_errno(libc::EBADF);
        return -1;
    }

    let mut file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    if file.seek(std::io::SeekFrom::Start(0)).is_err() {
        set_errno(libc::EIO);
        return -1;
    }
    let mut buf = [0u8; size_of::<ComposefsHeader>()];
    if file.read_exact(&mut buf).is_err() {
        set_errno(libc::EIO);
        return -1;
    }

    let header = ComposefsHeader::ref_from_bytes(&buf).unwrap();
    if header.magic != COMPOSEFS_MAGIC || header.version.get() != 1 {
        set_errno(libc::EINVAL);
        return -1;
    }

    header.composefs_version.get() as c_int
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_write_to(
    root: *mut FfiNode,
    options: *mut LcfsWriteOptions,
) -> c_int {
    if root.is_null() || options.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    unsafe { write_to_inner(root, options) }
}

unsafe fn ffi_tree_has_whiteout(node: *const FfiNode) -> bool {
    unsafe {
        let n = &*node;
        let file_type = n.mode & libc::S_IFMT;
        if file_type == libc::S_IFCHR as u32 && n.rdev == 0 {
            return true;
        }
        for &child in &n.children {
            if !child.is_null() {
                let child_ref = &*child;
                if child_ref.hardlink_target.is_some() {
                    continue;
                }
                if ffi_tree_has_whiteout(child) {
                    return true;
                }
            }
        }
        false
    }
}

unsafe fn write_to_inner(root: *mut FfiNode, options: *mut LcfsWriteOptions) -> c_int {
    unsafe {
        let opts = &*options;
        let root_ref = &*root;

        // Convert FfiNode tree to FileSystem
        let fs = match ffi_tree_to_filesystem(root_ref) {
            Ok(fs) => fs,
            Err(_) => {
                set_errno(libc::EINVAL);
                return -1;
            }
        };

        // Validate the filesystem
        let validated = match ValidatedFileSystem::new(fs) {
            Ok(v) => v,
            Err(_) => {
                set_errno(libc::EINVAL);
                return -1;
            }
        };

        // C library auto-bumps version from 0 to 1 when the tree contains
        // chardev whiteouts (S_IFCHR, rdev=0) and max_version >= 1.
        let mut effective_version = opts.version;
        if effective_version < 1 && opts.max_version >= 1 {
            if ffi_tree_has_whiteout(root) {
                effective_version = 1;
            }
        }

        let version = match effective_version {
            0 => FormatVersion::V0,
            1 => FormatVersion::V1,
            _ => FormatVersion::V0,
        };

        // Generate the EROFS image
        let image_data = mkfs_erofs_versioned(&validated, version);

        // Compute digest if requested
        if opts.flags & LCFS_BUILD_COMPUTE_DIGEST != 0 && !opts.digest_out.is_null() {
            let digest = composefs::fsverity::compute_verity::<Sha256HashValue>(&image_data);
            ptr::copy_nonoverlapping(digest.as_bytes().as_ptr(), opts.digest_out, 32);
        }

        // Write through callback
        if let Some(write_cb) = opts.file_write_cb {
            let mut offset = 0;
            while offset < image_data.len() {
                let remaining = image_data.len() - offset;
                let written = write_cb(
                    opts.file,
                    image_data[offset..].as_ptr() as *mut c_void,
                    remaining,
                );
                if written < 0 {
                    set_errno(libc::EIO);
                    return -1;
                }
                offset += written as usize;
            }
        }

        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_load_node_from_file(
    dirfd: c_int,
    fname: *const c_char,
    _buildflags: c_int,
) -> *mut FfiNode {
    if fname.is_null() {
        set_errno(libc::EINVAL);
        return ptr::null_mut();
    }

    unsafe {
        let name = CStr::from_ptr(fname);
        let dirfd = BorrowedFd::borrow_raw(dirfd);

        let stat = match statat(dirfd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(s) => s,
            Err(e) => {
                set_errno(e.raw_os_error());
                return ptr::null_mut();
            }
        };

        let node = Box::into_raw(Box::new(FfiNode::default()));
        (*node).mode = stat.st_mode as u32;
        (*node).uid = stat.st_uid;
        (*node).gid = stat.st_gid;
        (*node).nlink = stat.st_nlink as u32;
        (*node).size = stat.st_size as u64;
        (*node).rdev = stat.st_rdev;
        (*node).mtime_sec = stat.st_mtime;
        (*node).mtime_nsec = stat.st_mtime_nsec as u32;

        if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink
            && let Ok(target) = readlinkat(dirfd, name, Vec::new())
        {
            (*node).payload = Some(target);
        }

        node
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_build(
    dirfd: c_int,
    fname: *const c_char,
    buildflags: c_int,
    _failed_path_out: *mut *mut c_char,
) -> *mut FfiNode {
    if fname.is_null() {
        set_errno(libc::EINVAL);
        return ptr::null_mut();
    }

    unsafe {
        let name = CStr::from_ptr(fname);
        let dirfd = BorrowedFd::borrow_raw(dirfd);

        let fd = match openat(
            dirfd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(e) => {
                set_errno(e.raw_os_error());
                return ptr::null_mut();
            }
        };

        match build_dir_recursive(fd.as_fd(), buildflags) {
            Some(node) => node,
            None => {
                set_errno(libc::EIO);
                ptr::null_mut()
            }
        }
    }
}

unsafe fn build_dir_recursive(dirfd: BorrowedFd<'_>, buildflags: c_int) -> Option<*mut FfiNode> {
    let stat = rustix::fs::fstat(dirfd).ok()?;

    let node = Box::into_raw(Box::new(FfiNode::default()));
    unsafe {
        (*node).mode = stat.st_mode as u32;
        (*node).uid = stat.st_uid;
        (*node).gid = stat.st_gid;
        (*node).nlink = stat.st_nlink as u32;
        (*node).size = stat.st_size as u64;
        (*node).rdev = stat.st_rdev;
        (*node).mtime_sec = stat.st_mtime;
        (*node).mtime_nsec = stat.st_mtime_nsec as u32;
    }

    let mut buf = [MaybeUninit::uninit(); 8192];
    let mut raw_dir = RawDir::new(dirfd, &mut buf);

    while let Some(Ok(entry)) = raw_dir.next() {
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }

        let name_ptr = name.as_ptr();
        let child = unsafe { lcfs_load_node_from_file(dirfd.as_raw_fd(), name_ptr, buildflags) };
        if child.is_null() {
            continue;
        }

        unsafe {
            if ((*child).mode & libc::S_IFMT) == libc::S_IFDIR
                && let Ok(child_fd) = openat(
                    dirfd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY,
                    Mode::empty(),
                )
            {
                build_dir_children(child_fd.as_fd(), child, buildflags);
            }

            crate::node::lcfs_node_add_child(node, child, name_ptr);
        }
    }

    Some(node)
}

unsafe fn build_dir_children(dirfd: BorrowedFd<'_>, parent: *mut FfiNode, buildflags: c_int) {
    let mut buf = [MaybeUninit::uninit(); 8192];
    let mut raw_dir = RawDir::new(dirfd, &mut buf);

    while let Some(Ok(entry)) = raw_dir.next() {
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }

        let name_ptr = name.as_ptr();
        let child = unsafe { lcfs_load_node_from_file(dirfd.as_raw_fd(), name_ptr, buildflags) };
        if child.is_null() {
            continue;
        }

        unsafe {
            if ((*child).mode & libc::S_IFMT) == libc::S_IFDIR
                && let Ok(child_fd) = openat(
                    dirfd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY,
                    Mode::empty(),
                )
            {
                build_dir_children(child_fd.as_fd(), child, buildflags);
            }

            crate::node::lcfs_node_add_child(parent, child, name_ptr);
        }
    }
}
