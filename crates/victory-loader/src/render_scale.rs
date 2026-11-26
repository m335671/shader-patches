//! Optional half-resolution rendering for the known 1.0.2.1 title image.
//! Placement and signatures follow VIctory-NVIDIA 033be27 and its
//! victory-perf/ScarlettPort sources. This hook only adjusts render scale.

use anyhow::{Result, bail};
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const BUILD: &str = "b99f876b74d4a77f";
struct Patch {
    offset: usize,
    before: Vec<u8>,
    after: Vec<u8>,
}

/// The shipped FSR path requires 720p on Series S. The half-scale
/// option selects the existing built-in upscaler and fixes its range.
fn half_resolution() -> [Patch; 3] {
    [
        Patch {
            offset: 0x7e9426,
            before: vec![0x0f, 0x45, 0xc1],
            after: vec![0x0f, 0x1f, 0x00],
        },
        Patch {
            offset: 0x28f1e7e,
            before: (2.0f32 / 3.0).to_le_bytes().to_vec(),
            after: 0.5f32.to_le_bytes().to_vec(),
        },
        Patch {
            offset: 0x28f1e87,
            before: vec![0xc5, 0xfa, 0x5f, 0x86, 0x90, 0, 0, 0],
            after: vec![0xc5, 0xfa, 0x10, 0x86, 0x90, 0, 0, 0],
        },
    ]
}

/// Applies the option before any title code runs. The loaded image is a
/// private mapping and the game files remain read-only.
///
/// # Safety
/// `base` is a newly mapped title image of the given size and build hash.
/// Its sections remain mapped and no other thread accesses them yet.
pub(crate) unsafe fn apply(base: usize, size: usize, hash: &blake3::Hash) -> Result<()> {
    let Ok(scale) = std::env::var("VICTORY_RENDER_SCALE") else {
        return Ok(());
    };
    if scale.trim().parse::<f32>().ok() != Some(0.5) {
        tracing::warn!("VICTORY_RENDER_SCALE supports 0.5 for this experiment");
        return Ok(());
    }
    if !hash.to_hex().starts_with(BUILD) {
        tracing::warn!("render scale skipped for an unsupported title build");
        return Ok(());
    }
    // SAFETY: the caller guarantees that the identified image is fully loaded.
    if unsafe { apply_patches(base, size, &half_resolution()) }? {
        tracing::info!("title built-in upscaler selected at render scale 0.5");
    }
    Ok(())
}

/// All in-bounds patch locations must be readable. No code can run from these
/// pages until the function returns successfully.
unsafe fn apply_patches(base: usize, size: usize, patches: &[Patch]) -> Result<bool> {
    // SAFETY: the checked locations are sections of the identified build.
    let agrees = |offset: usize, bytes: &[u8]| {
        offset
            .checked_add(bytes.len())
            .is_some_and(|end| end <= size)
            && unsafe { std::slice::from_raw_parts((base + offset) as *const u8, bytes.len()) }
                == bytes
    };
    if !patches
        .iter()
        .all(|p| p.before.len() == p.after.len() && agrees(p.offset, &p.before))
    {
        tracing::warn!("render scale skipped because the mapped bytes did not match");
        return Ok(false);
    }

    let mut protections = Vec::with_capacity(patches.len());
    for patch in patches {
        let address = (base + patch.offset) as *mut u8;
        let mut previous = 0;
        // SAFETY: preflight verified the mapped ranges. Each patch only
        // changes the protection while the title remains stopped.
        if unsafe {
            VirtualProtect(
                address.cast(),
                patch.after.len(),
                PAGE_EXECUTE_READWRITE,
                &mut previous,
            )
        } == 0
        {
            break;
        }
        protections.push((address, patch.after.len(), previous));
    }
    let ready = protections.len() == patches.len();
    // SAFETY: all expected bytes were verified before making any page
    // writable. Reverse restoration handles patches on the same page.
    unsafe {
        if ready {
            for (patch, &(address, len, _)) in patches.iter().zip(&protections) {
                std::ptr::copy_nonoverlapping(patch.after.as_ptr(), address, len);
            }
        }
        let mut restored = true;
        for &(address, len, previous) in protections.iter().rev() {
            let mut ignored = 0;
            restored &= VirtualProtect(address.cast(), len, previous, &mut ignored) != 0;
        }
        if !restored {
            bail!("failed to restore title image protections");
        }
        if ready {
            for &(address, len, _) in &protections {
                if FlushInstructionCache(GetCurrentProcess(), address.cast(), len) == 0 {
                    bail!("failed to flush the render-scale instruction cache");
                }
            }
        }
    }
    if !ready {
        tracing::warn!("render scale skipped because a mapped page could not be made writable");
    }
    Ok(ready)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
        PAGE_READWRITE, VirtualAlloc, VirtualFree, VirtualQuery,
    };

    #[test]
    fn half_scale_selects_the_built_in_upscaler() {
        let patches = half_resolution();
        assert_eq!(patches[0].after, [0x0f, 0x1f, 0x00]);
        assert_eq!(patches[1].after, 0.5f32.to_le_bytes());
        assert!(
            patches
                .iter()
                .all(|patch| patch.before.len() == patch.after.len())
        );
    }

    #[test]
    fn verifies_all_signatures_before_writing_and_restores_page_protection() {
        let patches = [
            Patch {
                offset: 0,
                before: vec![1],
                after: vec![3],
            },
            Patch {
                offset: 1,
                before: vec![2],
                after: vec![4],
            },
        ];
        // SAFETY: the fixture owns this page and never executes its contents.
        unsafe {
            let page = VirtualAlloc(
                std::ptr::null(),
                4096,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            );
            assert!(!page.is_null());
            let bytes = page.cast::<u8>();
            bytes.write(1);
            let mut previous = 0;
            assert_ne!(
                VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &mut previous),
                0
            );

            assert!(!apply_patches(page as usize, 4096, &patches).unwrap());
            assert_eq!(std::slice::from_raw_parts(bytes, 2), [1, 0]);

            let matching = [
                Patch {
                    offset: 0,
                    before: vec![1],
                    after: vec![3],
                },
                Patch {
                    offset: 1,
                    before: vec![0],
                    after: vec![4],
                },
            ];
            assert!(apply_patches(page as usize, 4096, &matching).unwrap());
            assert_eq!(std::slice::from_raw_parts(bytes, 2), [3, 4]);
            let mut region = MEMORY_BASIC_INFORMATION::default();
            assert_ne!(
                VirtualQuery(
                    page,
                    &mut region,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
                ),
                0
            );
            assert_eq!(region.Protect, PAGE_EXECUTE_READ);
            assert_ne!(VirtualFree(page, 0, MEM_RELEASE), 0);
        }
    }
}
