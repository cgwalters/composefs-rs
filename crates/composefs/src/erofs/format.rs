//! EROFS on-disk format definitions and data structures.
//!
//! This module defines the binary layout of EROFS filesystem structures
//! including superblocks, inodes, directory entries, and other metadata
//! using safe zerocopy-based parsing.

// This is currently implemented using zerocopy but the eventual plan is to do this with safe
// transmutation.  As such: all of the structures are defined in terms of pure LE integer sizes, we
// handle the conversion to enum values separately, and we avoid the TryFromBytes trait.

use std::fmt;

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    little_endian::{U16, U32, U64},
};

/// Number of bits used for block size (12 = 4096 bytes)
pub const BLOCK_BITS: u8 = 12;
/// Size of a block in bytes (4096)
pub const BLOCK_SIZE: u16 = 1 << BLOCK_BITS;

/// Errors that can occur when parsing EROFS format structures
#[derive(Debug)]
pub enum FormatError {
    /// The data layout field contains an invalid value
    InvalidDataLayout,
}

/* Special handling for enums: FormatField and FileTypeField */
// FormatField == InodeLayout | DataLayout
/// Combined field encoding both inode layout and data layout in a single u16 value
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct FormatField(U16);

impl Default for FormatField {
    fn default() -> Self {
        FormatField(0xffff.into())
    }
}

impl fmt::Debug for FormatField {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} = {:?} | {:?}",
            self.0.get(),
            InodeLayout::from(*self),
            DataLayout::try_from(*self)
        )
    }
}

const INODE_LAYOUT_MASK: u16 = 0b00000001;
const INODE_LAYOUT_COMPACT: u16 = 0;
const INODE_LAYOUT_EXTENDED: u16 = 1;

/// Inode layout format, determining the inode header size
#[derive(Debug)]
#[repr(u16)]
pub enum InodeLayout {
    /// Compact 32-byte inode header
    Compact = INODE_LAYOUT_COMPACT,
    /// Extended 64-byte inode header with additional fields
    Extended = INODE_LAYOUT_EXTENDED,
}

impl From<FormatField> for InodeLayout {
    fn from(value: FormatField) -> Self {
        match value.0.get() & INODE_LAYOUT_MASK {
            INODE_LAYOUT_COMPACT => InodeLayout::Compact,
            INODE_LAYOUT_EXTENDED => InodeLayout::Extended,
            _ => unreachable!(),
        }
    }
}

const INODE_DATALAYOUT_MASK: u16 = 0b00001110;
const INODE_DATALAYOUT_FLAT_PLAIN: u16 = 0;
const INODE_DATALAYOUT_FLAT_INLINE: u16 = 4;
const INODE_DATALAYOUT_CHUNK_BASED: u16 = 8;

/// Data layout method for file content storage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DataLayout {
    /// File data stored in separate blocks
    FlatPlain = 0,
    /// File data stored inline within the inode
    FlatInline = 4,
    /// File data stored using chunk-based addressing
    ChunkBased = 8,
}

impl TryFrom<FormatField> for DataLayout {
    type Error = FormatError;

    fn try_from(value: FormatField) -> Result<Self, FormatError> {
        match value.0.get() & INODE_DATALAYOUT_MASK {
            INODE_DATALAYOUT_FLAT_PLAIN => Ok(DataLayout::FlatPlain),
            INODE_DATALAYOUT_FLAT_INLINE => Ok(DataLayout::FlatInline),
            INODE_DATALAYOUT_CHUNK_BASED => Ok(DataLayout::ChunkBased),
            // This is non-injective, but only occurs in error cases.
            _ => Err(FormatError::InvalidDataLayout),
        }
    }
}

impl std::ops::BitOr<DataLayout> for InodeLayout {
    type Output = FormatField;

    // Convert InodeLayout | DataLayout into a format field
    fn bitor(self, datalayout: DataLayout) -> FormatField {
        FormatField((self as u16 | datalayout as u16).into())
    }
}

/// File type mask for st_mode
pub const S_IFMT: u16 = 0o170000;
/// Regular file mode bit
pub const S_IFREG: u16 = 0o100000;
/// Character device mode bit
pub const S_IFCHR: u16 = 0o020000;
/// Directory mode bit
pub const S_IFDIR: u16 = 0o040000;
/// Block device mode bit
pub const S_IFBLK: u16 = 0o060000;
/// FIFO mode bit
pub const S_IFIFO: u16 = 0o010000;
/// Symbolic link mode bit
pub const S_IFLNK: u16 = 0o120000;
/// Socket mode bit
pub const S_IFSOCK: u16 = 0o140000;

// FileTypeField == FileType
/// Unknown file type value
pub const FILE_TYPE_UNKNOWN: u8 = 0;
/// Regular file type value
pub const FILE_TYPE_REGULAR_FILE: u8 = 1;
/// Directory file type value
pub const FILE_TYPE_DIRECTORY: u8 = 2;
/// Character device file type value
pub const FILE_TYPE_CHARACTER_DEVICE: u8 = 3;
/// Block device file type value
pub const FILE_TYPE_BLOCK_DEVICE: u8 = 4;
/// FIFO file type value
pub const FILE_TYPE_FIFO: u8 = 5;
/// Socket file type value
pub const FILE_TYPE_SOCKET: u8 = 6;
/// Symbolic link file type value
pub const FILE_TYPE_SYMLINK: u8 = 7;

/// File type enumeration for directory entries
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum FileType {
    /// Unknown or invalid file type
    Unknown = FILE_TYPE_UNKNOWN,
    /// Regular file
    RegularFile = FILE_TYPE_REGULAR_FILE,
    /// Directory
    Directory = FILE_TYPE_DIRECTORY,
    /// Character device
    CharacterDevice = FILE_TYPE_CHARACTER_DEVICE,
    /// Block device
    BlockDevice = FILE_TYPE_BLOCK_DEVICE,
    /// FIFO (named pipe)
    Fifo = FILE_TYPE_FIFO,
    /// Socket
    Socket = FILE_TYPE_SOCKET,
    /// Symbolic link
    Symlink = FILE_TYPE_SYMLINK,
}

impl From<FileTypeField> for FileType {
    fn from(value: FileTypeField) -> Self {
        match value.0 {
            FILE_TYPE_REGULAR_FILE => Self::RegularFile,
            FILE_TYPE_DIRECTORY => Self::Directory,
            FILE_TYPE_CHARACTER_DEVICE => Self::CharacterDevice,
            FILE_TYPE_BLOCK_DEVICE => Self::BlockDevice,
            FILE_TYPE_FIFO => Self::Fifo,
            FILE_TYPE_SOCKET => Self::Socket,
            FILE_TYPE_SYMLINK => Self::Symlink,
            // This is non-injective, but only occurs in error cases.
            _ => Self::Unknown,
        }
    }
}

impl From<FileType> for FileTypeField {
    fn from(value: FileType) -> Self {
        FileTypeField(value as u8)
    }
}

impl std::ops::BitOr<u16> for FileType {
    type Output = U16;

    // Convert ifmt | permissions into a st_mode field
    fn bitor(self, permissions: u16) -> U16 {
        (match self {
            Self::RegularFile => S_IFREG,
            Self::CharacterDevice => S_IFCHR,
            Self::Directory => S_IFDIR,
            Self::BlockDevice => S_IFBLK,
            Self::Fifo => S_IFIFO,
            Self::Symlink => S_IFLNK,
            Self::Socket => S_IFSOCK,
            Self::Unknown => unreachable!(),
        } | permissions)
            .into()
    }
}

/// Raw file type field as stored in directory entries
#[derive(Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct FileTypeField(u8);

impl fmt::Debug for FileTypeField {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&FileType::from(*self), f)
    }
}

impl Default for FileTypeField {
    fn default() -> Self {
        FileTypeField(0xff)
    }
}

/* ModeField */
/// File mode field combining file type and permissions
#[derive(Clone, Copy, Default, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct ModeField(pub U16);

impl ModeField {
    /// Checks if this mode field represents a directory
    pub fn is_dir(self) -> bool {
        self.0.get() & S_IFMT == S_IFDIR
    }
}

impl fmt::Debug for ModeField {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mode = self.0.get();
        let fmt = match mode & S_IFMT {
            S_IFREG => "regular file",
            S_IFCHR => "chardev",
            S_IFDIR => "directory",
            S_IFBLK => "blockdev",
            S_IFIFO => "fifo",
            S_IFLNK => "symlink",
            S_IFSOCK => "socket",
            _ => "INVALID",
        };

        write!(f, "0{mode:06o} ({fmt})")
    }
}

impl std::ops::BitOr<u32> for FileType {
    type Output = ModeField;

    fn bitor(self, permissions: u32) -> ModeField {
        ModeField(self | (permissions as u16))
    }
}

/* composefs Header */

/// EROFS format version number
pub const VERSION: U32 = U32::new(1);
/// Composefs-specific version number (V2, Rust-native format)
pub const COMPOSEFS_VERSION: U32 = U32::new(2);
/// Composefs-specific version number for V1 (C-compatible format: compact inodes, whiteout table)
pub const COMPOSEFS_VERSION_V1: U32 = U32::new(0);
/// Magic number identifying composefs images
pub const COMPOSEFS_MAGIC: U32 = U32::new(0xd078629a);

/// Format version for composefs images
///
/// This enum represents the different format versions supported by composefs.
/// The format version affects the composefs header version field and build time handling.
///
/// Serialized as an integer: V1 → `1`, V2 → `2`.
#[repr(u32)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Hash,
    PartialEq,
    Eq,
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
)]
pub enum FormatVersion {
    /// Format V1: compact inodes, whiteout table.
    ///
    /// This is the original format used by older versions of composefs.
    /// Build time is set to the minimum mtime across all inodes.
    /// The `composefs_version` header field is 0 normally, but 1 when
    /// user-land whiteout files are present (matching C mkcomposefs behavior).
    V1 = 1,
    /// Format V2: extended inodes, no whiteout table, composefs_version=2
    ///
    /// This is the current default format.
    #[default]
    V2 = 2,
}

impl FormatVersion {
    /// Returns the composefs_version value for this format version
    pub fn composefs_version(self) -> U32 {
        match self {
            FormatVersion::V1 => COMPOSEFS_VERSION_V1,
            FormatVersion::V2 => COMPOSEFS_VERSION,
        }
    }
}

/// The set of EROFS format versions to generate when committing images.
///
/// Stored in `meta.json` via the `"v1_erofs"` ro_compat feature flag:
/// flag present → [`V1_ONLY`](Self::V1_ONLY), flag absent → [`BOTH`](Self::BOTH).
///
/// A `FormatSet` is a small bitset (bit 0 = V1, bit 1 = V2) so it can be
/// cheaply copied and tested without heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatSet(u8);

impl FormatSet {
    /// Generate only V1 EROFS (C-tool compatible).
    pub const V1_ONLY: FormatSet = FormatSet(0b01);
    /// Generate only V2 EROFS (composefs-rs native; repositories without a format flag).
    pub const V2_ONLY: FormatSet = FormatSet(0b10);
    /// Generate both V1 and V2 EROFS (used by bootc and other multi-format consumers).
    pub const BOTH: FormatSet = FormatSet(0b11);

    /// Map a [`FormatVersion`] to its bit position in the `FormatSet` bitset.
    ///
    /// V1 → bit 0 (`0b01`), V2 → bit 1 (`0b10`).  Adding a V3 only requires
    /// updating this one function.
    fn version_bit(v: FormatVersion) -> u8 {
        match v {
            FormatVersion::V1 => 0b01,
            FormatVersion::V2 => 0b10,
        }
    }

    /// Returns `true` if this set includes the given format version.
    pub fn contains(self, v: FormatVersion) -> bool {
        self.0 & Self::version_bit(v) != 0
    }

    /// Iterate over the format versions in this set, in ascending order (V1 before V2).
    pub fn iter(self) -> impl Iterator<Item = FormatVersion> {
        [FormatVersion::V1, FormatVersion::V2]
            .into_iter()
            .filter(move |&v| self.contains(v))
    }
}

impl From<FormatVersion> for FormatSet {
    /// Create a single-version `FormatSet` from a [`FormatVersion`].
    fn from(v: FormatVersion) -> Self {
        FormatSet(FormatSet::version_bit(v))
    }
}

/// Flag indicating the presence of ACL data
pub const COMPOSEFS_FLAGS_HAS_ACL: U32 = U32::new(1 << 0);

/// Composefs-specific header preceding the standard EROFS superblock
#[derive(Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct ComposefsHeader {
    /// Magic number for identification
    pub magic: U32,
    /// EROFS format version
    pub version: U32,
    /// Composefs feature flags
    pub flags: U32,
    /// Composefs format version
    pub composefs_version: U32,
    /// Reserved for future use
    pub unused: [U32; 4],
}

/* Superblock */

/// EROFS version 1 magic number
pub const MAGIC_V1: U32 = U32::new(0xE0F5E1E2);

// feature_compat flags
/// Superblock CRC32C checksum present
pub const FEATURE_COMPAT_SB_CHKSUM: u32 = 0x0000_0001;
/// Inode mtime support
pub const FEATURE_COMPAT_MTIME: u32 = 0x0000_0002;
/// xattr name filter (bloom filter) support
pub const FEATURE_COMPAT_XATTR_FILTER: u32 = 0x0000_0004;
/// Mask of feature_compat bits supported by composefs.
///
/// The kernel defines additional compat flags (shared EA in metabox,
/// plain xattr prefixes, ishare xattrs) that composefs does not use.
/// Unknown compat bits are rejected by `restrict_to_composefs()`.
pub const FEATURE_COMPAT_SUPPORTED: u32 =
    FEATURE_COMPAT_SB_CHKSUM | FEATURE_COMPAT_MTIME | FEATURE_COMPAT_XATTR_FILTER;

// feature_incompat flags
/// LZ4 zero-padding for decompression
pub const FEATURE_INCOMPAT_LZ4_0PADDING: u32 = 0x0000_0001;
/// Compression configs / big physical clusters
pub const FEATURE_INCOMPAT_COMPR_CFGS: u32 = 0x0000_0002;
/// Chunk-based file data (used by composefs for external files)
pub const FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 0x0000_0004;
/// Multi-device support / compression head type 2
pub const FEATURE_INCOMPAT_DEVICE_TABLE: u32 = 0x0000_0008;
/// Compressed tail packing
pub const FEATURE_INCOMPAT_ZTAILPACKING: u32 = 0x0000_0010;
/// Fragment / dedup support
pub const FEATURE_INCOMPAT_FRAGMENTS: u32 = 0x0000_0020;
/// Custom xattr name prefixes
pub const FEATURE_INCOMPAT_XATTR_PREFIXES: u32 = 0x0000_0040;
/// 48-bit block addressing
pub const FEATURE_INCOMPAT_48BIT: u32 = 0x0000_0080;
/// Metabox inodes
pub const FEATURE_INCOMPAT_METABOX: u32 = 0x0000_0100;

/// EROFS filesystem superblock structure
#[derive(Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct Superblock {
    // vertical whitespace every 16 bytes (hexdump-friendly)
    /// EROFS magic number
    pub magic: U32,
    /// Filesystem checksum
    pub checksum: U32,
    /// Compatible feature flags
    pub feature_compat: U32,
    /// Block size in bits (log2 of block size)
    pub blkszbits: u8,
    /// Number of extended attribute slots
    pub extslots: u8,
    /// Root inode number
    pub root_nid: U16,

    /// Total number of inodes
    pub inos: U64,
    /// Build time in seconds since epoch
    pub build_time: U64,

    /// Build time nanoseconds component
    pub build_time_nsec: U32,
    /// Total number of blocks
    pub blocks: U32,
    /// Starting block address of metadata
    pub meta_blkaddr: U32,
    /// Starting block address of extended attributes
    pub xattr_blkaddr: U32,

    /// Filesystem UUID
    pub uuid: [u8; 16],

    /// Volume name
    pub volume_name: [u8; 16],

    /// Incompatible feature flags
    pub feature_incompat: U32,
    /// Available compression algorithms bitmap
    pub available_compr_algs: U16,
    /// Number of extra devices
    pub extra_devices: U16,
    /// Device slot offset
    pub devt_slotoff: U16,
    /// Directory block size in bits
    pub dirblkbits: u8,
    /// Number of xattr prefixes
    pub xattr_prefix_count: u8,
    /// Starting position of xattr prefix table
    pub xattr_prefix_start: U32,

    /// Packed inode number
    pub packed_nid: U64,
    /// Reserved for xattr filtering
    pub xattr_filter_reserved: u8,
    /// Reserved for future use
    pub reserved2: [u8; 23],
}

/* Inodes */

/// Compact 32-byte inode header for basic file metadata
#[derive(Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct CompactInodeHeader {
    /// Format field combining inode layout and data layout
    pub format: FormatField,
    /// Extended attribute inode count
    pub xattr_icount: U16,
    /// File mode (type and permissions)
    pub mode: ModeField,
    /// Number of hard links
    pub nlink: U16,

    /// File size in bytes
    pub size: U32,
    /// Reserved field
    pub reserved: U32,

    /// Union field (block address, device number, etc.)
    pub u: U32,
    /// Inode number for 32-bit stat compatibility
    pub ino: U32, // only used for 32-bit stat compatibility

    /// User ID
    pub uid: U16,
    /// Group ID
    pub gid: U16,
    /// Reserved field
    pub reserved2: [u8; 4],
}

/// Extended 64-byte inode header with additional metadata fields
#[derive(Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct ExtendedInodeHeader {
    /// Format field combining inode layout and data layout
    pub format: FormatField,
    /// Extended attribute inode count
    pub xattr_icount: U16,
    /// File mode (type and permissions)
    pub mode: ModeField,
    /// Reserved field
    pub reserved: U16,
    /// File size in bytes
    pub size: U64,

    /// Union field (block address, device number, etc.)
    pub u: U32,
    /// Inode number for 32-bit stat compatibility
    pub ino: U32, // only used for 32-bit stat compatibility
    /// User ID
    pub uid: U32,
    /// Group ID
    pub gid: U32,

    /// Modification time in seconds since epoch
    pub mtime: U64,

    /// Modification time nanoseconds component
    pub mtime_nsec: U32,
    /// Number of hard links
    pub nlink: U32,

    /// Reserved field
    pub reserved2: [u8; 16],
}

/// Header for inode extended attributes section
#[derive(Debug, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct InodeXAttrHeader {
    /// Name filter hash for quick xattr lookups
    pub name_filter: U32,
    /// Number of shared xattr references
    pub shared_count: u8,
    /// Reserved field
    pub reserved: [u8; 7],
}

/* Extended attributes */
/// Seed value for xattr name filter hash calculation
pub const XATTR_FILTER_SEED: u32 = 0x25BBE08F;

/// Header for an extended attribute entry
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct XAttrHeader {
    /// Length of the attribute name suffix
    pub name_len: u8,
    /// Index into the xattr prefix table
    pub name_index: u8,
    /// Size of the attribute value
    pub value_size: U16,
}

/// EROFS xattr prefix index for `system.posix_acl_access` (index 2).
pub const XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;
/// EROFS xattr prefix index for `system.posix_acl_default` (index 3).
pub const XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;
/// EROFS xattr prefix index for `lustre.` (index 5).
/// Absent from C mkcomposefs v1.0.8's prefix table; V1 writer skips it.
pub const XATTR_INDEX_LUSTRE: u8 = 5;

// Overlay xattr keys used by composefs V1 whiteout escaping.
// Named to match the C mkcomposefs OVERLAY_XATTR_* constants.
/// `trusted.overlay.overlay.whiteout` — V1 escaped whiteout marker.
pub const XATTR_OVERLAY_WHITEOUT: &[u8] = b"trusted.overlay.overlay.whiteout";
/// `user.overlay.whiteout` — userxattr escaped whiteout marker.
pub const XATTR_USERXATTR_WHITEOUT: &[u8] = b"user.overlay.whiteout";
/// `trusted.overlay.overlay.whiteouts` — escaped whiteouts directory marker.
pub const XATTR_OVERLAY_WHITEOUTS: &[u8] = b"trusted.overlay.overlay.whiteouts";
/// `user.overlay.whiteouts` — userxattr whiteouts directory marker.
pub const XATTR_USERXATTR_WHITEOUTS: &[u8] = b"user.overlay.whiteouts";
/// `trusted.overlay.overlay.opaque` — escaped opaque directory marker.
pub const XATTR_OVERLAY_OPAQUE: &[u8] = b"trusted.overlay.overlay.opaque";
/// `user.overlay.opaque` — userxattr opaque directory marker.
pub const XATTR_USERXATTR_OPAQUE: &[u8] = b"user.overlay.opaque";
/// `trusted.overlay.opaque` — root opaque marker written by V1 writer.
pub const XATTR_OVERLAY_OPAQUE_ROOT: &[u8] = b"trusted.overlay.opaque";
/// `trusted.overlay.metacopy` — metacopy marker (C adds redirect xattr too).
pub const XATTR_OVERLAY_METACOPY: &[u8] = b"trusted.overlay.metacopy";
/// `trusted.overlay.redirect` — redirect target xattr.
pub const XATTR_OVERLAY_REDIRECT: &[u8] = b"trusted.overlay.redirect";
/// `trusted.overlay.` prefix — all xattrs with this prefix are escaped in V1.
pub const XATTR_OVERLAY_PREFIX: &[u8] = b"trusted.overlay.";
/// `trusted.overlay.overlay.` prefix — escaped overlay xattr prefix.
pub const XATTR_OVERLAY_ESCAPED_PREFIX: &[u8] = b"trusted.overlay.overlay.";
/// `security.selinux` — SELinux label, copied to overlay whiteout stubs.
pub const XATTR_SECURITY_SELINUX: &[u8] = b"security.selinux";

/// Standard xattr name prefixes indexed by EROFS name_index.
///
/// Index 0 is the fallback (empty prefix, full name stored as suffix).
/// Indices 1–6 map to the well-known EROFS prefix constants:
///   EROFS_XATTR_INDEX_USER=1, POSIX_ACL_ACCESS=2, POSIX_ACL_DEFAULT=3,
///   EROFS_XATTR_INDEX_TRUSTED=4, EROFS_XATTR_INDEX_LUSTRE=5, EROFS_XATTR_INDEX_SECURITY=6.
///
/// **V1 compatibility note:** C mkcomposefs v1.0.8 does NOT include `lustre.` (index 5)
/// in its prefix table. Any `lustre.*` xattr is therefore encoded with prefix index 0
/// (raw fallback) by C. For V1 images the writer must skip index 5 during prefix
/// matching so that `lustre.*` xattrs fall through to the empty-string fallback.
pub const XATTR_PREFIXES: [&[u8]; 7] = [
    b"",
    b"user.",
    b"system.posix_acl_access",
    b"system.posix_acl_default",
    b"trusted.",
    b"lustre.",
    b"security.",
];

/* Directories */

/// Header for a directory entry
#[derive(Debug, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct DirectoryEntryHeader {
    /// Inode number of the entry
    pub inode_offset: U64,
    /// Offset to the entry name within the directory block
    pub name_offset: U16,
    /// File type of the entry
    pub file_type: FileTypeField,
    /// Reserved field
    pub reserved: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_set_contains() {
        assert!(FormatSet::BOTH.contains(FormatVersion::V1));
        assert!(FormatSet::BOTH.contains(FormatVersion::V2));
        assert!(FormatSet::V1_ONLY.contains(FormatVersion::V1));
        assert!(!FormatSet::V1_ONLY.contains(FormatVersion::V2));
    }

    #[test]
    fn test_format_set_from_version() {
        assert_eq!(FormatSet::from(FormatVersion::V1), FormatSet::V1_ONLY);
        // V2 alone is a single-version set (neither V1_ONLY nor BOTH).
        let v2_only = FormatSet::from(FormatVersion::V2);
        assert!(!v2_only.contains(FormatVersion::V1));
        assert!(v2_only.contains(FormatVersion::V2));
    }

    #[test]
    fn test_format_set_iter_order() {
        // iter() must yield V1 before V2.
        let versions: Vec<_> = FormatSet::BOTH.iter().collect();
        assert_eq!(versions, vec![FormatVersion::V1, FormatVersion::V2]);

        let v1_only: Vec<_> = FormatSet::V1_ONLY.iter().collect();
        assert_eq!(v1_only, vec![FormatVersion::V1]);
    }
}
