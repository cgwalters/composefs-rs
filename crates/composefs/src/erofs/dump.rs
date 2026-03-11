//! EROFS image dumping in composefs-dump(5) format.
//!
//! This module delegates to [`erofs_to_filesystem`] to parse the EROFS image
//! into a generic filesystem tree, then uses [`write_dumpfile`] to serialize
//! it in the composefs dumpfile text format.
//!
//! [`erofs_to_filesystem`]: super::reader::erofs_to_filesystem
//! [`write_dumpfile`]: crate::dumpfile::write_dumpfile

use std::io::Write;

use anyhow::Result;

use super::reader::erofs_to_filesystem;
use crate::{dumpfile::write_dumpfile, fsverity::Sha256HashValue};

/// Dumps an EROFS image in composefs-dump(5) format.
///
/// Parses the image into a filesystem tree via [`erofs_to_filesystem`], optionally
/// filters to specific top-level entries, then writes the dumpfile via [`write_dumpfile`].
///
/// If `filters` is provided and non-empty, only top-level entries whose names
/// match one of the filter strings will be included in the output (along with
/// the root directory itself).
pub fn dump_erofs(output: &mut impl Write, image_data: &[u8], filters: &[String]) -> Result<()> {
    let mut fs = erofs_to_filesystem::<Sha256HashValue>(image_data)?;

    if !filters.is_empty() {
        fs.root
            .retain_top_level(|name| filters.iter().any(|f| f == name));
    }

    write_dumpfile(output, &fs)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dumpfile::dumpfile_to_filesystem, erofs::format::FormatVersion, erofs::writer::mkfs_erofs,
    };

    fn roundtrip_test(input: &str) -> String {
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(input).unwrap();
        let image = mkfs_erofs(&fs, FormatVersion::default());
        let mut output = Vec::new();
        dump_erofs(&mut output, &image, &[]).unwrap();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn test_dump_empty_root() {
        let input = "/ 4096 40755 2 0 0 0 0.0 - - -\n";
        let output = roundtrip_test(input);
        // Output should have a root entry
        assert!(output.starts_with("/ "), "Output: {}", output);
        assert!(output.contains(" 40755 "), "Output: {}", output);
    }

    #[test]
    fn test_dump_with_file() {
        let input = "/ 4096 40755 2 0 0 0 0.0 - - -\n\
                     /file 5 100644 1 0 0 0 0.0 - hello -\n";
        let output = roundtrip_test(input);
        assert!(output.contains("/file "), "Output: {}", output);
        assert!(output.contains(" 100644 "), "Output: {}", output);
        assert!(output.contains(" hello "), "Output: {}", output);
    }

    #[test]
    fn test_dump_with_symlink() {
        let input = "/ 4096 40755 2 0 0 0 0.0 - - -\n\
                     /link 7 120777 1 0 0 0 0.0 /target - -\n";
        let output = roundtrip_test(input);
        assert!(output.contains("/link "), "Output: {}", output);
        assert!(output.contains(" 120777 "), "Output: {}", output);
        assert!(output.contains(" /target "), "Output: {}", output);
    }

    #[test]
    fn test_dump_with_subdirectory() {
        let input = "/ 4096 40755 2 0 0 0 0.0 - - -\n\
                     /subdir 4096 40755 2 0 0 0 0.0 - - -\n\
                     /subdir/file 3 100644 1 0 0 0 0.0 - abc -\n";
        let output = roundtrip_test(input);
        assert!(output.contains("/subdir "), "Output: {}", output);
        assert!(output.contains("/subdir/file "), "Output: {}", output);
    }

    #[test]
    fn test_dump_with_xattr() {
        let input = "/ 4096 40755 2 0 0 0 0.0 - - - user.test=hello\n";
        let output = roundtrip_test(input);
        assert!(output.contains("user.test=hello"), "Output: {}", output);
    }

    #[test]
    fn test_dump_with_filter() {
        let input = "/ 4096 40755 3 0 0 0 0.0 - - -\n\
                     /file1 4 100644 1 0 0 0 0.0 - test -\n\
                     /file2 5 100644 1 0 0 0 0.0 - hello -\n\
                     /dir 4096 40755 2 0 0 0 0.0 - - -\n";
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(input).unwrap();
        let image = mkfs_erofs(&fs, FormatVersion::default());

        // Test with filter for file1 only
        let mut output = Vec::new();
        let filters = vec!["file1".to_string()];
        dump_erofs(&mut output, &image, &filters).unwrap();
        let output_str = String::from_utf8(output).unwrap();

        // Should contain root and file1
        assert!(output_str.contains("/ "), "Output: {}", output_str);
        assert!(output_str.contains("/file1 "), "Output: {}", output_str);
        // Should NOT contain file2 or dir
        assert!(
            !output_str.contains("/file2 "),
            "file2 should be filtered out: {}",
            output_str
        );
        assert!(
            !output_str.contains("/dir "),
            "dir should be filtered out: {}",
            output_str
        );
    }

    #[test]
    fn test_dump_with_multiple_filters() {
        let input = "/ 4096 40755 3 0 0 0 0.0 - - -\n\
                     /file1 4 100644 1 0 0 0 0.0 - test -\n\
                     /file2 5 100644 1 0 0 0 0.0 - hello -\n\
                     /dir 4096 40755 2 0 0 0 0.0 - - -\n\
                     /dir/nested 3 100644 1 0 0 0 0.0 - abc -\n";
        let fs = dumpfile_to_filesystem::<Sha256HashValue>(input).unwrap();
        let image = mkfs_erofs(&fs, FormatVersion::default());

        // Test with filter for file1 and dir
        let mut output = Vec::new();
        let filters = vec!["file1".to_string(), "dir".to_string()];
        dump_erofs(&mut output, &image, &filters).unwrap();
        let output_str = String::from_utf8(output).unwrap();

        // Should contain root, file1, dir, and nested file inside dir
        assert!(output_str.contains("/ "), "Output: {}", output_str);
        assert!(output_str.contains("/file1 "), "Output: {}", output_str);
        assert!(output_str.contains("/dir "), "Output: {}", output_str);
        assert!(
            output_str.contains("/dir/nested "),
            "nested file in dir should be included: {}",
            output_str
        );
        // Should NOT contain file2
        assert!(
            !output_str.contains("/file2 "),
            "file2 should be filtered out: {}",
            output_str
        );
    }
}
