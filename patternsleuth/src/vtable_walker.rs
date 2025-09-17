use crate::{Image, MemoryAccessError, MemoryTrait};
use patternsleuth_scanner::{Xref, scan_xref};

#[derive(Debug, Clone)]
pub struct VTableEntry {
    pub offset: usize,
    pub address: u64,
    pub is_valid_function: bool,
}

#[derive(Debug)]
pub struct VTable {
    pub base_address: u64,
    pub entries: Vec<VTableEntry>,
    pub estimated_size: usize,
}

pub struct VTableWalker<'a> {
    image: &'a Image<'a>,
    /// Maximum entries to scan before giving up
    max_entries: usize,
}

impl<'a> VTableWalker<'a> {
    pub fn new(image: &'a Image<'a>) -> Self {
        Self {
            image,
            max_entries: 1000,
        }
    }

    /// Check if an address has any references pointing to it
    fn has_reference_to(&self, addr: u64) -> bool {
        // Scan all sections for references to this address
        let xref = Xref(addr as usize);
        for section in self.image.memory.sections() {
            let results = scan_xref(&[&xref], section.address() as usize, section.data());
            if !results[0].is_empty() {
                return true;
            }
        }
        false
    }

    /// Walk a vtable starting at the given address
    /// Based on praydog's heuristics:
    /// 1. Stop if vtable fn pointer is null or points to unreadable memory
    /// 2. Stop if the vtable entry address (&vtable[i]) has a reference (means we hit another vtable)
    pub fn walk_vtable(&mut self, vtable_addr: u64) -> Result<VTable, MemoryAccessError> {
        let mut entries = Vec::new();
        let mut offset = 0;

        loop {
            if offset >= self.max_entries {
                break;
            }

            let entry_address = vtable_addr + (offset * 8) as u64;

            // Try to read the function pointer
            let fn_ptr = match self.image.memory.read_u64(entry_address) {
                Ok(ptr) => ptr,
                Err(_) => {
                    // Can't read this entry, we've hit the end
                    break;
                }
            };

            // Check if function pointer is null
            if fn_ptr == 0 {
                break;
            }

            // Check if function pointer points to readable memory
            if self.image.memory.read_u64(fn_ptr).is_err() {
                break;
            }

            // Skip checking first entry for references (it always has refs)
            if offset > 0 {
                // Check if this vtable entry address has any references
                // If it does, we've likely hit the start of another vtable
                if self.has_reference_to(entry_address) {
                    break;
                }
            }

            // This is a valid vtable entry
            entries.push(VTableEntry {
                offset: offset * 8,
                address: fn_ptr,
                is_valid_function: true,
            });

            offset += 1;
        }

        Ok(VTable {
            base_address: vtable_addr,
            entries,
            estimated_size: entries.len() * 8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtable_walker_creation() {
        // Test would require a mock Image
    }
}