unsafe extern "C" {
    fn test_basic();
    fn test_xattr_addremove();
    fn test_xattr_doubleadd();
    fn test_add_uninitialized_child();
    fn test_hardlinked_whiteout_load();
    fn test_no_verity();
}

#[test]
fn c_test_basic() {
    unsafe { test_basic() };
}

#[test]
fn c_test_xattr_addremove() {
    unsafe { test_xattr_addremove() };
}

#[test]
fn c_test_xattr_doubleadd() {
    unsafe { test_xattr_doubleadd() };
}

#[test]
fn c_test_add_uninitialized_child() {
    unsafe { test_add_uninitialized_child() };
}

#[test]
fn c_test_hardlinked_whiteout_load() {
    unsafe { test_hardlinked_whiteout_load() };
}

#[test]
fn c_test_no_verity() {
    unsafe { test_no_verity() };
}
