//! Immutable indexed packs of node preimages.
//!
//! This module reads and writes MCHPACK1, used by transfs. Storage transport
//! and ref publication belong to the caller. Future pack formats can coexist
//! here.
use crate::Identity;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"MCHPACK1";
const HEADER_SIZE: usize = 20;
const INDEX_ENTRY_SIZE: usize = 48;

#[derive(Debug)]
pub struct PackError(&'static str);

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for PackError {}

pub type Result<T> = std::result::Result<T, PackError>;

fn identity(bytes: &[u8]) -> Identity {
    Sha256::digest(bytes).into()
}

/// Encodes unique, identity-sorted nodes. Each node must hash to its key.
pub fn encode(objects: &[(Identity, Vec<u8>)]) -> Result<Vec<u8>> {
    let count = u32::try_from(objects.len()).map_err(|_| PackError("too many objects in pack"))?;
    let data_size = objects.iter().try_fold(HEADER_SIZE, |size, (_, bytes)| {
        size.checked_add(bytes.len())
            .ok_or(PackError("pack size overflow"))
    })?;
    let index_size = objects
        .len()
        .checked_mul(INDEX_ENTRY_SIZE)
        .ok_or(PackError("pack index size overflow"))?;
    let capacity = data_size
        .checked_add(index_size)
        .ok_or(PackError("pack size overflow"))?;
    let index_offset = u64::try_from(data_size).map_err(|_| PackError("pack size overflow"))?;
    let mut pack = Vec::with_capacity(capacity);
    pack.extend_from_slice(MAGIC);
    pack.extend_from_slice(&count.to_be_bytes());
    pack.extend_from_slice(&index_offset.to_be_bytes());

    let mut offset = HEADER_SIZE;
    let mut previous = None;
    let mut index = Vec::with_capacity(index_size);
    for (id, bytes) in objects {
        if previous.is_some_and(|prev: Identity| prev >= *id) {
            return Err(PackError("pack identities must be unique and sorted"));
        }
        if identity(bytes) != *id {
            return Err(PackError("pack object identity mismatch"));
        }
        let data_offset = u64::try_from(offset).map_err(|_| PackError("pack size overflow"))?;
        let length = u64::try_from(bytes.len()).map_err(|_| PackError("pack object too large"))?;
        index.extend_from_slice(id);
        index.extend_from_slice(&data_offset.to_be_bytes());
        index.extend_from_slice(&length.to_be_bytes());
        pack.extend_from_slice(bytes);
        offset += bytes.len();
        previous = Some(*id);
    }
    pack.extend_from_slice(&index);
    Ok(pack)
}

/// Checks the complete index and every object's SHA-256 identity.
pub fn decode(pack: &[u8]) -> Result<Vec<(Identity, Vec<u8>)>> {
    if pack.len() < HEADER_SIZE || &pack[..8] != MAGIC {
        return Err(PackError("invalid pack header"));
    }
    let count = u32::from_be_bytes(pack[8..12].try_into().expect("header length")) as usize;
    let index_offset = u64::from_be_bytes(pack[12..20].try_into().expect("header length"));
    let index_offset =
        usize::try_from(index_offset).map_err(|_| PackError("pack index offset overflow"))?;
    let index_size = count
        .checked_mul(INDEX_ENTRY_SIZE)
        .ok_or(PackError("pack index size overflow"))?;
    if index_offset < HEADER_SIZE || index_offset.checked_add(index_size) != Some(pack.len()) {
        return Err(PackError("invalid pack index bounds"));
    }
    let mut objects = Vec::with_capacity(count);
    let mut expected_offset = HEADER_SIZE;
    let mut previous = None;
    for index in 0..count {
        let entry = index_offset + index * INDEX_ENTRY_SIZE;
        let id: Identity = pack[entry..entry + 32].try_into().expect("index bounds");
        if previous.is_some_and(|prev: Identity| prev >= id) {
            return Err(PackError("pack identities are not unique and sorted"));
        }
        let offset = u64::from_be_bytes(pack[entry + 32..entry + 40].try_into().unwrap());
        let length = u64::from_be_bytes(pack[entry + 40..entry + 48].try_into().unwrap());
        let offset =
            usize::try_from(offset).map_err(|_| PackError("pack object offset overflow"))?;
        let length =
            usize::try_from(length).map_err(|_| PackError("pack object length overflow"))?;
        if offset != expected_offset
            || offset
                .checked_add(length)
                .is_none_or(|end| end > index_offset)
        {
            return Err(PackError("invalid pack object bounds"));
        }
        let bytes = pack[offset..offset + length].to_vec();
        if identity(&bytes) != id {
            return Err(PackError("pack object identity mismatch"));
        }
        expected_offset = offset + length;
        previous = Some(id);
        objects.push((id, bytes));
    }
    if expected_offset != index_offset {
        return Err(PackError("unused bytes in pack data area"));
    }
    Ok(objects)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_stable_layout() {
        let bytes = b"merkle-champ/branch/v1\0\0\0\0\0\0\0\0".to_vec();
        let id = identity(&bytes);
        let pack = encode(&[(id, bytes.clone())]).unwrap();
        assert_eq!(&pack[..8], b"MCHPACK1");
        assert_eq!(&pack[8..12], &1u32.to_be_bytes());
        assert_eq!(
            &pack[12..20],
            &((HEADER_SIZE + bytes.len()) as u64).to_be_bytes()
        );
        assert_eq!(decode(&pack).unwrap(), vec![(id, bytes)]);
        assert_eq!(encode(&decode(&pack).unwrap()).unwrap(), pack);
    }

    #[test]
    fn rejects_corrupt_data_and_index() {
        let bytes = b"node preimage".to_vec();
        let id = identity(&bytes);
        let pack = encode(&[(id, bytes)]).unwrap();

        let mut damaged_data = pack.clone();
        damaged_data[HEADER_SIZE] ^= 1;
        assert!(decode(&damaged_data).is_err());

        let mut damaged_index = pack;
        let index_offset = HEADER_SIZE + b"node preimage".len();
        damaged_index[index_offset + 32] ^= 1;
        assert!(decode(&damaged_index).is_err());
    }
}
