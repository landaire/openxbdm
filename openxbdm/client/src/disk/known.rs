//! Block devices named by the monitor's drive table.

/// Whether `gethddblk` is known to be safe on a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    /// A disk, partition, or memory unit. Reading an absent one fails
    /// with `400`.
    Storage,
    /// Not a sector-addressed disk. Probes must not be sent: `gethddblk`
    /// on `\Device\Flash` stopped kernel 16547, which then restarted.
    Other,
}

#[derive(Debug, Clone, Copy)]
pub struct KnownDevice {
    pub name: &'static str,
    /// Drive names that the default or internal drive map points at the
    /// device.
    pub drives: &'static [&'static str],
    pub contents: &'static str,
    pub kind: DeviceKind,
}

impl KnownDevice {
    pub const fn is_probe_safe(&self) -> bool {
        matches!(self.kind, DeviceKind::Storage)
    }
}

const fn storage(
    name: &'static str,
    drives: &'static [&'static str],
    contents: &'static str,
) -> KnownDevice {
    KnownDevice {
        name,
        drives,
        contents,
        kind: DeviceKind::Storage,
    }
}

const fn other(
    name: &'static str,
    drives: &'static [&'static str],
    contents: &'static str,
) -> KnownDevice {
    KnownDevice {
        name,
        drives,
        contents,
        kind: DeviceKind::Other,
    }
}

/// Devices of the default and internal drive maps
/// (`openxbdm/server/src/commands/filesystem/drive.rs`), plus the whole
/// hard disk.
pub const KNOWN_DEVICES: &[KnownDevice] = &[
    storage(
        r"\Device\Harddisk0\Partition0",
        &[],
        "whole hard disk; sector 0 holds the devkit partition table",
    ),
    storage(
        r"\Device\Harddisk0\Partition1",
        &["HDD", "Z"],
        "hard disk data partition (XTAF)",
    ),
    storage(
        r"\Device\Harddisk0\SystemPartition",
        &["Y"],
        "hard disk system partition",
    ),
    storage(
        r"\Device\Harddisk0\SystemExtPartition",
        &["HDDSYSEXT"],
        "hard disk system extended partition",
    ),
    storage(
        r"\Device\Harddisk0\SystemAuxPartition",
        &["HDDSYSAUX"],
        "hard disk system auxiliary partition",
    ),
    storage(
        r"\Device\BuiltInMuSfc",
        &["MUINT"],
        "internal memory unit data partition (XTAF)",
    ),
    storage(
        r"\Device\BuiltInMuSfcSystem",
        &["MUINTSYS"],
        "internal memory unit system partition (XTAF)",
    ),
    storage(r"\Device\Mu0", &["MU0"], "memory unit 0"),
    storage(r"\Device\Mu1", &["MU1"], "memory unit 1"),
    storage(
        r"\Device\Mu0System",
        &["MU0SYS"],
        "memory unit 0 system partition",
    ),
    storage(
        r"\Device\Mu1System",
        &["MU1SYS"],
        "memory unit 1 system partition",
    ),
    storage(
        r"\Device\BuiltInMuUsb\Storage",
        &["INTUSB"],
        "internal USB memory unit",
    ),
    storage(
        r"\Device\BuiltInMuUsb\StorageSystem",
        &["INTUSBSYS"],
        "internal USB memory unit system partition",
    ),
    storage(
        r"\Device\BuiltInMuUsb\SystemExtPartition",
        &["INTUSBSYSEXT"],
        "internal USB memory unit system extended partition",
    ),
    storage(
        r"\Device\BuiltInMuUsb\SystemAuxPartition",
        &["INTUSBSYSAUX"],
        "internal USB memory unit system auxiliary partition",
    ),
    storage(
        r"\Device\BuiltInMuMmc\Storage",
        &["INTMMC"],
        "internal MMC memory unit",
    ),
    storage(
        r"\Device\BuiltInMuMmc\StorageSystem",
        &["INTMMCSYS"],
        "internal MMC memory unit system partition",
    ),
    storage(
        r"\Device\BuiltInMuMmc\SystemExtPartition",
        &["INTMMCSYSEXT"],
        "internal MMC memory unit system extended partition",
    ),
    storage(
        r"\Device\BuiltInMuMmc\SystemAuxPartition",
        &["INTMMCSYSAUX"],
        "internal MMC memory unit system auxiliary partition",
    ),
    storage(r"\Device\Mass0", &["USBMASS0"], "USB mass storage 0"),
    storage(r"\Device\Mass1", &["USBMASS1"], "USB mass storage 1"),
    storage(r"\Device\Mass2", &["USBMASS2"], "USB mass storage 2"),
    other(
        r"\Device\Flash",
        &["FLASH"],
        "NAND flash; gethddblk stopped kernel 16547",
    ),
    other(r"\Device\Cdrom0", &["A", "DVD"], "optical drive"),
    other(r"\Device\HdDvdRom", &["HDDVD"], "HD DVD drive"),
    other(
        r"\Device\HdDvdStorage",
        &["HDDVDMU"],
        "HD DVD drive storage",
    ),
    other(r"\Device\HdDvdPlayer", &["HDDVDSYS"], "HD DVD player"),
    other(
        r"\Device\TransferCable",
        &["TRANSFERCABLE"],
        "transfer cable",
    ),
    other(
        r"\Device\Mass0PartitionFile\Storage",
        &["USBMASS0MU"],
        "memory unit file on USB mass storage 0",
    ),
    other(
        r"\Device\Mass1PartitionFile\Storage",
        &["USBMASS1MU"],
        "memory unit file on USB mass storage 1",
    ),
    other(
        r"\Device\Mass0PartitionFile\StorageSystem",
        &["USBMASS0MUSYS"],
        "memory unit file system partition on USB mass storage 0",
    ),
    other(
        r"\Device\Mass1PartitionFile\StorageSystem",
        &["USBMASS1MUSYS"],
        "memory unit file system partition on USB mass storage 1",
    ),
];

/// The known device with this name, compared without regard to case as
/// NT object names are.
pub fn known_device(name: &str) -> Option<&'static KnownDevice> {
    KNOWN_DEVICES
        .iter()
        .find(|device| device.name.eq_ignore_ascii_case(name))
}
