#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionScheme {
    Mbr,
    Gpt,
}

impl std::fmt::Display for PartitionScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PartitionScheme::Mbr => write!(f, "mbr"),
            PartitionScheme::Gpt => write!(f, "gpt"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filesystem {
    Ext2,
    Ext3,
    Ext4,
    Fat32,
    Ntfs,
    Btrfs,
    Xfs,
}

impl Filesystem {
    pub fn mkfs_cmd(&self) -> Vec<&'static str> {
        match self {
            Filesystem::Ext2 => vec!["mkfs.ext2", "-F"],
            Filesystem::Ext3 => vec!["mkfs.ext3", "-F"],
            Filesystem::Ext4 => vec!["mkfs.ext4", "-F"],
            Filesystem::Fat32 => vec!["mkfs.fat", "-F", "32"],
            Filesystem::Ntfs => vec!["mkfs.ntfs", "-f"],
            Filesystem::Btrfs => vec!["mkfs.btrfs", "-f"],
            Filesystem::Xfs => vec!["mkfs.xfs", "-f"],
        }
    }
}

impl std::fmt::Display for Filesystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Filesystem::Ext2 => write!(f, "ext2"),
            Filesystem::Ext3 => write!(f, "ext3"),
            Filesystem::Ext4 => write!(f, "ext4"),
            Filesystem::Fat32 => write!(f, "fat32"),
            Filesystem::Ntfs => write!(f, "ntfs"),
            Filesystem::Btrfs => write!(f, "btrfs"),
            Filesystem::Xfs => write!(f, "xfs"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Text,
    Binary,
    Image,
}

impl std::fmt::Display for DataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataType::Text => write!(f, "text"),
            DataType::Binary => write!(f, "binary"),
            DataType::Image => write!(f, "image"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptionType {
    HeaderZeroed,
    L1Corrupted,
    L2Corrupted,
    RefcountCorrupted,
    HeaderAndL1,
    AllMetadata,
}

impl std::fmt::Display for CorruptionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorruptionType::HeaderZeroed => write!(f, "header_zeroed"),
            CorruptionType::L1Corrupted => write!(f, "l1_corrupted"),
            CorruptionType::L2Corrupted => write!(f, "l2_corrupted"),
            CorruptionType::RefcountCorrupted => write!(f, "refcount_corrupted"),
            CorruptionType::HeaderAndL1 => write!(f, "header_and_l1"),
            CorruptionType::AllMetadata => write!(f, "all_metadata"),
        }
    }
}
