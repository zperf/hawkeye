use anyhow::{anyhow, Result};
use object::{Object, ObjectSegment, ObjectSymbol};
use std::fs;

/// Find the file offset of a symbol in an ELF binary without relying on BTF.
/// Returns the file offset that can be used directly with uprobe attachment.
pub(crate) fn find_symbol_offset(binary_path: &str, symbol_name: &str) -> Result<u64> {
    let data = fs::read(binary_path)?;
    let file = object::File::parse(&*data)
        .map_err(|e| anyhow!("Failed to parse ELF binary '{}': {}", binary_path, e))?;

    // Search regular symbol table first, then dynamic symbols (for shared libraries).
    resolve_symbol(&file, file.symbols(), symbol_name)
        .or_else(|| resolve_symbol(&file, file.dynamic_symbols(), symbol_name))
        .ok_or_else(|| anyhow!("Symbol '{}' not found in '{}'", symbol_name, binary_path))
}

/// Look up `symbol_name` in the given symbol iterator and return its file offset.
fn resolve_symbol<'data, I>(
    file: &object::File<'data>,
    symbols: I,
    symbol_name: &str,
) -> Option<u64>
where
    I: Iterator<Item = object::Symbol<'data, 'data>>,
{
    for sym in symbols {
        if let Ok(name) = sym.name() {
            if name == symbol_name {
                return vaddr_to_file_offset(file, sym.address());
            }
        }
    }
    None
}

/// Convert a virtual address to a file offset by scanning ELF segments.
fn vaddr_to_file_offset(file: &object::File, vaddr: u64) -> Option<u64> {
    for seg in file.segments() {
        let seg_vaddr = seg.address();
        let seg_size = seg.size();
        let seg_offset = seg.file_range().0;
        if vaddr >= seg_vaddr && vaddr < seg_vaddr + seg_size {
            return Some(seg_offset + (vaddr - seg_vaddr));
        }
    }
    None
}
