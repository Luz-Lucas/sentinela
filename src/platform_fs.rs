//! Which locations make up "the whole computer".

use std::path::PathBuf;

/// `DRIVE_FIXED` from `GetDriveTypeW`.
const DRIVE_FIXED: u32 = 3;

/// Turns a `GetLogicalDrives` bitmask into `X:\` roots, keeping the drives
/// for which `drive_type` reports `DRIVE_FIXED`. Pure, so it is testable on
/// any platform.
pub fn roots_from_drive_mask(mask: u32, drive_type: impl Fn(&str) -> u32) -> Vec<PathBuf> {
    (0..26u8)
        .filter(|bit| mask & (1 << bit) != 0)
        .map(|bit| format!("{}:\\", char::from(b'A' + bit)))
        .filter(|root| drive_type(root) == DRIVE_FIXED)
        .map(PathBuf::from)
        .collect()
}

/// Every fixed (non-removable, non-network, non-optical) drive.
/// Off Windows this is just `/` (development fallback).
pub fn fixed_drive_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
        // SAFETY: no pointers involved.
        let mask = unsafe { GetLogicalDrives() };
        roots_from_drive_mask(mask, |root| {
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call.
            unsafe { GetDriveTypeW(wide.as_ptr()) }
        })
    }
    #[cfg(not(windows))]
    {
        vec![PathBuf::from("/")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_keeps_only_fixed_drives() {
        // A, C, D, E present; C and D fixed, A removable (2), E network (4).
        let mask = 0b11101;
        let roots = roots_from_drive_mask(mask, |r| match r {
            "C:\\" | "D:\\" => 3,
            "A:\\" => 2,
            _ => 4,
        });
        assert_eq!(roots, vec![PathBuf::from("C:\\"), PathBuf::from("D:\\")]);
    }

    #[test]
    fn empty_mask_yields_nothing() {
        assert!(roots_from_drive_mask(0, |_| 3).is_empty());
    }

    #[test]
    fn fixed_drive_roots_is_not_empty_on_dev_hosts() {
        #[cfg(not(windows))]
        assert_eq!(fixed_drive_roots(), vec![PathBuf::from("/")]);
    }
}
