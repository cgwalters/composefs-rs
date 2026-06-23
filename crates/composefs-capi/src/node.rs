use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr;
use std::ptr::NonNull;

use libc::{self, size_t, timespec};

use crate::errno::set_errno;
use crate::{FfiNode, FfiXattr, LCFS_DIGEST_SIZE};

// ---------------------------------------------------------------------------
// Node lifecycle
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_new() -> *mut FfiNode {
    let node = Box::new(FfiNode::default());
    Box::into_raw(node)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_ref(node: *mut FfiNode) -> *mut FfiNode {
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*node).ref_count += 1;
    }
    node
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_unref(node: *mut FfiNode) {
    if node.is_null() {
        return;
    }
    unsafe {
        (*node).ref_count -= 1;
        if (*node).ref_count > 0 {
            return;
        }

        // Unref all children
        let children: Vec<*mut FfiNode> = (*node).children.drain(..).collect();
        for child in children {
            (*child).parent = ptr::null_mut();
            lcfs_node_unref(child);
        }

        if let Some(target) = (*node).hardlink_target.take() {
            lcfs_node_unref(target.as_ptr());
        }

        drop(Box::from_raw(node));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_clone(node: *mut FfiNode) -> *mut FfiNode {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return ptr::null_mut();
    }

    unsafe {
        let src = &*node;
        let cloned = FfiNode {
            ref_count: 1,
            parent: ptr::null_mut(),
            children: Vec::new(),
            name: None, // name is set by add_child
            payload: src.payload.clone(),
            content: src.content.clone(),
            xattrs: src
                .xattrs
                .iter()
                .map(|x| FfiXattr {
                    key: x.key.clone(),
                    value: x.value.clone(),
                })
                .collect(),
            mode: src.mode,
            uid: src.uid,
            gid: src.gid,
            nlink: src.nlink,
            rdev: src.rdev,
            size: src.size,
            mtime_sec: src.mtime_sec,
            mtime_nsec: src.mtime_nsec,
            digest: src.digest,
            digest_set: src.digest_set,
            hardlink_target: src
                .hardlink_target
                .map(|t| NonNull::new(lcfs_node_ref(t.as_ptr())).unwrap()),
        };

        Box::into_raw(Box::new(cloned))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_clone_deep(node: *mut FfiNode) -> *mut FfiNode {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return ptr::null_mut();
    }

    unsafe {
        let cloned = lcfs_node_clone(node);
        if cloned.is_null() {
            return ptr::null_mut();
        }

        // Deep-clone all children
        let src = &*node;
        for child_ptr in &src.children {
            let child_clone = lcfs_node_clone_deep(*child_ptr);
            if child_clone.is_null() {
                lcfs_node_unref(cloned);
                return ptr::null_mut();
            }
            let child_name = (*(*child_ptr))
                .name
                .as_ref()
                .map(|n| n.as_ptr())
                .unwrap_or(ptr::null());
            if lcfs_node_add_child(cloned, child_clone, child_name) < 0 {
                lcfs_node_unref(child_clone);
                lcfs_node_unref(cloned);
                return ptr::null_mut();
            }
        }

        cloned
    }
}

// ---------------------------------------------------------------------------
// Metadata getters/setters
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_dirp(node: *mut FfiNode) -> bool {
    if node.is_null() {
        return false;
    }
    unsafe { ((*node).mode & libc::S_IFMT) == libc::S_IFDIR }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_mode(node: *mut FfiNode) -> u32 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).mode }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_mode(node: *mut FfiNode, mode: u32) {
    if node.is_null() {
        return;
    }
    unsafe {
        (*node).mode = mode;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_try_set_mode(node: *mut FfiNode, mode: u32) -> c_int {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let file_type = mode & libc::S_IFMT;
    if file_type != libc::S_IFREG
        && file_type != libc::S_IFDIR
        && file_type != libc::S_IFCHR
        && file_type != libc::S_IFBLK
        && file_type != libc::S_IFIFO
        && file_type != libc::S_IFLNK
        && file_type != libc::S_IFSOCK
    {
        set_errno(libc::EINVAL);
        return -1;
    }
    unsafe {
        (*node).mode = mode;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_uid(node: *mut FfiNode) -> u32 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).uid }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_uid(node: *mut FfiNode, uid: u32) {
    if !node.is_null() {
        unsafe {
            (*node).uid = uid;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_gid(node: *mut FfiNode) -> u32 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).gid }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_gid(node: *mut FfiNode, gid: u32) {
    if !node.is_null() {
        unsafe {
            (*node).gid = gid;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_nlink(node: *mut FfiNode) -> u32 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).nlink }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_nlink(node: *mut FfiNode, nlink: u32) {
    if !node.is_null() {
        unsafe {
            (*node).nlink = nlink;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_size(node: *mut FfiNode) -> u64 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).size }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_size(node: *mut FfiNode, size: u64) {
    if !node.is_null() {
        unsafe {
            if (*node).size != size {
                (*node).content = None;
            }
            (*node).size = size;
        }
    }
}

#[unsafe(no_mangle)]
#[deprecated]
pub unsafe extern "C" fn lcfs_node_get_rdev(node: *mut FfiNode) -> u32 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).rdev as u32 }
}

#[unsafe(no_mangle)]
#[deprecated]
pub unsafe extern "C" fn lcfs_node_set_rdev(node: *mut FfiNode, rdev: u32) {
    if !node.is_null() {
        unsafe {
            (*node).rdev = rdev as u64;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_rdev64(node: *mut FfiNode) -> u64 {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).rdev }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_rdev64(node: *mut FfiNode, rdev: u64) {
    if !node.is_null() {
        unsafe {
            (*node).rdev = rdev;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_mtime(node: *mut FfiNode, time: *mut timespec) {
    if node.is_null() || time.is_null() {
        return;
    }
    unsafe {
        (*time).tv_sec = (*node).mtime_sec;
        (*time).tv_nsec = (*node).mtime_nsec as i64;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_mtime(node: *mut FfiNode, time: *mut timespec) {
    if node.is_null() || time.is_null() {
        return;
    }
    unsafe {
        (*node).mtime_sec = (*time).tv_sec;
        (*node).mtime_nsec = (*time).tv_nsec as u32;
    }
}

// ---------------------------------------------------------------------------
// Extended attributes
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_xattr(
    node: *mut FfiNode,
    name: *const c_char,
    length: *mut size_t,
) -> *const c_char {
    if node.is_null() || name.is_null() {
        return ptr::null();
    }
    unsafe {
        let name_cstr = CStr::from_ptr(name);
        for xattr in &(*node).xattrs {
            if xattr.key.as_c_str() == name_cstr {
                if !length.is_null() {
                    *length = xattr.value.len();
                }
                return xattr.value.as_ptr() as *const c_char;
            }
        }
    }
    ptr::null()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_xattr(
    node: *mut FfiNode,
    name: *const c_char,
    value: *const c_char,
    value_len: size_t,
) -> c_int {
    if node.is_null() || name.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    unsafe {
        let name_cstr = CStr::from_ptr(name);
        let key = match CString::new(name_cstr.to_bytes()) {
            Ok(k) => k,
            Err(_) => {
                set_errno(libc::EINVAL);
                return -1;
            }
        };
        let val = if value.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(value as *const u8, value_len).to_vec()
        };

        // Update existing or insert new
        for xattr in &mut (*node).xattrs {
            if xattr.key.as_c_str() == name_cstr {
                xattr.value = val;
                return 0;
            }
        }
        (*node).xattrs.push(FfiXattr { key, value: val });
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_unset_xattr(node: *mut FfiNode, name: *const c_char) -> c_int {
    if node.is_null() || name.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    unsafe {
        let name_cstr = CStr::from_ptr(name);
        let orig_len = (*node).xattrs.len();
        (*node).xattrs.retain(|x| x.key.as_c_str() != name_cstr);
        if (*node).xattrs.len() == orig_len {
            set_errno(libc::ENODATA);
            return -1;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_n_xattr(node: *mut FfiNode) -> size_t {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).xattrs.len() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_xattr_name(
    node: *mut FfiNode,
    index: size_t,
) -> *const c_char {
    if node.is_null() {
        return ptr::null();
    }
    unsafe {
        if index >= (*node).xattrs.len() {
            return ptr::null();
        }
        (&(*node).xattrs)[index].key.as_ptr()
    }
}

// ---------------------------------------------------------------------------
// Content and payload
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_payload(
    node: *mut FfiNode,
    payload: *const c_char,
) -> c_int {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    unsafe {
        if payload.is_null() {
            (*node).payload = None;
        } else {
            (*node).payload = Some(CStr::from_ptr(payload).to_owned());
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_symlink_payload(
    node: *mut FfiNode,
    payload: *const c_char,
) -> c_int {
    unsafe { lcfs_node_set_payload(node, payload) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_payload(node: *mut FfiNode) -> *const c_char {
    if node.is_null() {
        return ptr::null();
    }
    unsafe {
        match &(*node).payload {
            Some(p) => p.as_ptr(),
            None => ptr::null(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_content(
    node: *mut FfiNode,
    data: *const u8,
    data_size: size_t,
) -> c_int {
    if node.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    unsafe {
        if data.is_null() || data_size == 0 {
            (*node).content = None;
            (*node).size = 0;
        } else {
            let content = std::slice::from_raw_parts(data, data_size).to_vec();
            (*node).size = data_size as u64;
            (*node).content = Some(content);
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_content(node: *mut FfiNode) -> *const u8 {
    if node.is_null() {
        return ptr::null();
    }
    unsafe {
        match &(*node).content {
            Some(c) => c.as_ptr(),
            None => ptr::null(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tree structure
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_name(node: *mut FfiNode) -> *const c_char {
    if node.is_null() {
        return ptr::null();
    }
    unsafe {
        match &(*node).name {
            Some(n) => n.as_ptr(),
            None => ptr::null(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_parent(node: *mut FfiNode) -> *mut FfiNode {
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe { (*node).parent }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_n_children(node: *mut FfiNode) -> size_t {
    if node.is_null() {
        return 0;
    }
    unsafe { (*node).children.len() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_child(node: *mut FfiNode, i: size_t) -> *mut FfiNode {
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        if i >= (*node).children.len() {
            return ptr::null_mut();
        }
        (&(*node).children)[i]
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_lookup_child(
    node: *mut FfiNode,
    name: *const c_char,
) -> *mut FfiNode {
    if node.is_null() || name.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        let name_cstr = CStr::from_ptr(name);
        for child_ptr in &(*node).children {
            if let Some(ref child_name) = (**child_ptr).name
                && child_name.as_c_str() == name_cstr
            {
                return *child_ptr;
            }
        }
    }
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_add_child(
    parent: *mut FfiNode,
    child: *mut FfiNode,
    name: *const c_char,
) -> c_int {
    if parent.is_null() || child.is_null() || name.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }

    unsafe {
        // Must be a directory
        if ((*parent).mode & libc::S_IFMT) != libc::S_IFDIR {
            set_errno(libc::ENOTDIR);
            return -1;
        }

        let name_cstr = CStr::from_ptr(name);
        let name_bytes = name_cstr.to_bytes();

        // Empty name not allowed
        if name_bytes.is_empty() {
            set_errno(libc::EINVAL);
            return -1;
        }

        // Name too long
        if name_bytes.len() > 255 {
            set_errno(libc::ENAMETOOLONG);
            return -1;
        }

        // Child already has a name (already in a tree)
        if (*child).name.is_some() {
            set_errno(libc::EMLINK);
            return -1;
        }

        // Check for duplicate name
        for existing in &(*parent).children {
            if let Some(ref existing_name) = (**existing).name
                && existing_name.as_c_str() == name_cstr
            {
                set_errno(libc::EEXIST);
                return -1;
            }
        }

        // Set name and parent on child
        (*child).name = Some(CString::new(name_bytes).unwrap());
        (*child).parent = parent;

        // Insert sorted by name
        let insert_pos = (*parent)
            .children
            .binary_search_by(|probe| {
                let probe_name = (**probe).name.as_ref().unwrap();
                probe_name.as_bytes().cmp(name_bytes)
            })
            .unwrap_or_else(|pos| pos);
        (*parent).children.insert(insert_pos, child);
    }
    0
}

// ---------------------------------------------------------------------------
// Hardlinks
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_make_hardlink(node: *mut FfiNode, target: *mut FfiNode) {
    if node.is_null() || target.is_null() {
        return;
    }
    unsafe {
        if let Some(old) = (*node).hardlink_target.take() {
            lcfs_node_unref(old.as_ptr());
        }
        (*node).hardlink_target = NonNull::new(lcfs_node_ref(target));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_hardlink_target(node: *mut FfiNode) -> *mut FfiNode {
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (*node)
            .hardlink_target
            .map_or(ptr::null_mut(), |t| t.as_ptr())
    }
}

// ---------------------------------------------------------------------------
// fs-verity digest on node
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_get_fsverity_digest(node: *mut FfiNode) -> *const u8 {
    if node.is_null() {
        return ptr::null();
    }
    unsafe {
        if (*node).digest_set {
            (*node).digest.as_ptr()
        } else {
            ptr::null()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcfs_node_set_fsverity_digest(node: *mut FfiNode, digest: *const u8) {
    if node.is_null() || digest.is_null() {
        return;
    }
    unsafe {
        (*node)
            .digest
            .copy_from_slice(std::slice::from_raw_parts(digest, LCFS_DIGEST_SIZE));
        (*node).digest_set = true;
    }
}
