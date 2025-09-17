use crate::{Image, MemoryAccessError, MemoryTrait};

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

    /// Helper to identify section type based on name
    fn describe_section(name: &str) -> &'static str {
        match name {
            ".text" | "TEXT" | "__text" => "code section",
            ".data" | "DATA" | "__data" | "_DATA" => "initialized data section", 
            ".rdata" | "__const" | "_RDATA" => "read-only data section",
            ".bss" | "BSS" | "__bss" => "uninitialized data section",
            ".rodata" => "read-only data section",
            ".got" | ".got.plt" => "global offset table",
            ".plt" => "procedure linkage table",
            _ if name.contains("debug") => "debug section",
            _ if name.contains("rel") => "relocation section",
            _ => "unknown section type"
        }
    }

    /// Helper to identify if a section should be checked for references
    fn should_check_section(name: &str) -> bool {
        // Skip metadata, debug, and exception handling sections
        match name {
            // Exception/unwind data - not relevant for vtable references
            ".pdata" | "__pdata" | ".xdata" | "__xdata" => false,
            
            // Debug sections - not part of runtime
            _ if name.contains("debug") => false,
            
            // Relocation sections - not relevant
            _ if name.starts_with(".rel") => false,
            
            // Other metadata sections
            ".eh_frame" | "__eh_frame" => false,
            ".gcc_except_table" => false,
            ".rsrc" => false,  // Windows resource section
            ".msvcjmc" => false,  // MSVC Just My Code debugging
            
            // CHECK these sections (where vtable references typically are):
            // Note: We're looking for absolute pointers, so data sections are most important
            ".rdata" | "__const" | ".rodata" | "_RDATA" => true, // RTTI and vtables live here
            ".data" | "__data" | "DATA" | "_DATA" => true,      // Object instances
            ".bss" | "__bss" | "BSS" => true,                   // Uninitialized objects
            
            // Code sections might have vtable refs but less common for absolute pointers
            ".text" | "__text" | "TEXT" => false, // Skip code - it uses relative addressing
            
            // Default: skip unknown sections
            _ => {
                println!("       (Skipping unknown section: {})", name);
                false
            }
        }
    }

    /// Check if an address has any absolute pointer references to it within the target module
    /// This looks for 8-byte values that match the target address
    fn has_absolute_reference_to(&self, addr: u64) -> bool {
        let mut found_valid_ref = false;
        
        // Convert address to little-endian bytes for searching
        let target_bytes = addr.to_le_bytes();
        
        for section in self.image.memory.sections() {
            let section_name = section.name();
            
            // Skip sections we don't care about
            if !Self::should_check_section(section_name) {
                continue;
            }
            
            let section_type = Self::describe_section(section_name);
            let section_start = section.address();
            let section_data = section.data();
            let section_size = section_data.len();
            
            // Search for the 8-byte pattern in the section
            let mut search_pos = 0;
            let mut found_in_section = false;
            
            while search_pos + 8 <= section_size {
                // Check if we found our target address
                if &section_data[search_pos..search_pos + 8] == &target_bytes[..] {
                    if !found_in_section {
                        println!("    -> Found absolute reference(s) in section '{}' ({})", 
                                 section_name, section_type);
                        println!("       Section range: 0x{:016x} - 0x{:016x} (size: 0x{:x})", 
                                 section_start, section_start + section_size as u64, section_size);
                        found_in_section = true;
                    }
                    
                    let ref_addr = section_start + search_pos as u64;
                    println!("       Absolute pointer at 0x{:016x} (offset 0x{:x}) -> 0x{:016x}", 
                             ref_addr, search_pos, addr);
                    
                    // Show context (what's before and after this pointer)
                    if search_pos >= 8 && search_pos + 16 <= section_size {
                        let before = u64::from_le_bytes(section_data[search_pos - 8..search_pos].try_into().unwrap());
                        let after = u64::from_le_bytes(section_data[search_pos + 8..search_pos + 16].try_into().unwrap());
                        println!("         Context: [0x{:016x}] -> 0x{:016x} -> [0x{:016x}]", 
                                 before, addr, after);
                    }
                    
                    found_valid_ref = true;
                }
                
                search_pos += 1;
            }
        }
        
        found_valid_ref
    }

    /// Walk a vtable starting at the given address
    /// Based on praydog's heuristics:
    /// 1. Stop if vtable fn pointer is null or points to unreadable memory
    /// 2. Stop if the vtable entry address has absolute pointer references (means we hit another vtable)
    pub fn walk_vtable(&mut self, vtable_addr: u64) -> Result<VTable, MemoryAccessError> {
        let mut entries = Vec::new();
        let mut offset = 0;

        println!("Starting vtable walk at base address: 0x{:016x}", vtable_addr);
        println!("Scanning for absolute 64-bit pointer references in data sections");

        loop {
            if offset >= self.max_entries {
                println!("Stopping: Reached maximum entries limit ({})", self.max_entries);
                break;
            }

            let entry_address = vtable_addr + (offset * 8) as u64;
            println!("\n[Entry {}] Checking address 0x{:016x}", offset, entry_address);

            // Try to read the function pointer
            let fn_ptr = match self.image.memory.u64_le(entry_address) {
                Ok(ptr) => {
                    println!("  -> Function pointer: 0x{:016x}", ptr);
                    ptr
                },
                Err(e) => {
                    // Can't read this entry, we've hit the end
                    println!("  -> Cannot read memory at this address: {:?}", e);
                    println!("Stopping: Unreadable memory - likely hit end of vtable or unmapped region");
                    break;
                }
            };

            // Check if function pointer is null
            if fn_ptr == 0 {
                println!("  -> Function pointer is NULL");
                println!("Stopping: NULL function pointer - typical vtable terminator");
                break;
            }

            // Check if function pointer points to readable memory
            if let Err(e) = self.image.memory.u64_le(fn_ptr) {
                println!("  -> Function pointer 0x{:016x} points to unreadable memory: {:?}", fn_ptr, e);
                println!("Stopping: Invalid function pointer - doesn't point to executable code");
                break;
            }

            // Skip checking first few entries for references (they often have refs from objects)
            if offset > 2 {
                // Check if this vtable entry address has any absolute pointer references
                println!("  -> Checking for absolute pointer references to 0x{:016x}...", entry_address);
                if self.has_absolute_reference_to(entry_address) {
                    println!("  -> STOP: Found absolute pointer(s) to this entry address");
                    println!("     (This typically means another vtable or RTTI structure starts here)");
                    break;
                }
                println!("  -> No absolute references found (good - still in same vtable)");
            } else {
                println!("  -> Skipping reference check for entry {} (early entries often have object references)", offset);
            }

            // Additional safety check: Detect common sentinel/debug values
            if fn_ptr == 0xDEADBEEF || fn_ptr == 0xCCCCCCCCCCCCCCCC || fn_ptr == 0xFEFEFEFEFEFEFEFE {
                println!("  -> Found sentinel value: 0x{:016x}", fn_ptr);
                println!("Stopping: Debug/sentinel pattern detected");
                break;
            }

            // Check if pointer is suspiciously low (below typical code segment)
            if fn_ptr < 0x1000 && fn_ptr != 0 {
                println!("  -> Suspiciously low pointer value: 0x{:016x}", fn_ptr);
                println!("Stopping: Not a valid function address");
                break;
            }

            // This is a valid vtable entry
            println!("  -> Valid vtable entry!");
            entries.push(VTableEntry {
                offset: offset * 8,
                address: fn_ptr,
                is_valid_function: true,
            });

            offset += 1;
        }

        let estimated_size = entries.len() * 8;
        println!("\nVTable walk complete:");
        println!("  Base address: 0x{:016x}", vtable_addr);
        println!("  Total entries found: {}", entries.len());
        println!("  Estimated size: {} bytes", estimated_size);
        
        Ok(VTable {
            base_address: vtable_addr,
            entries,
            estimated_size,
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