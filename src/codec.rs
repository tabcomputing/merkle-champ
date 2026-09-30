//! Storing maps as bytes and reading them back (FORMAT.md, section 9).
//!
//! A stored node is exactly the bytes its identity hashes, so an object's
//! identity is the SHA-256 of its bytes and loading verifies itself. Nothing
//! here performs I/O: [`Objects`] is an in-memory collection, and moving its
//! contents to and from disk or a network is the caller's business.

use crate::Identity;
use sha2::{Digest, Sha256};
use std::any::{Any, TypeId};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

/// Where an encoding is written: a hasher when computing an identity, a byte
/// buffer when storing. The same encoder serves both, so the stored bytes and
/// the identity can never disagree.
///
/// A generic bound makes `update` callable inside an `Identify` impl without
/// importing `Sink`. Code that also imports `sha2::Digest` should leave
/// `Sink` unimported and name it by path, since both traits give `Sha256` an
/// `update` method:
///
/// ```
/// use merkle_champ::Identify;
/// use sha2::Digest; // also in scope, without ambiguity
///
/// struct Point(u64, u64);
/// impl Identify for Point {
///     fn identify<S: merkle_champ::Sink + ?Sized>(&self, sink: &mut S) {
///         sink.update(b"P");
///         sink.update(&self.0.to_le_bytes());
///         sink.update(&self.1.to_le_bytes());
///     }
/// }
/// let _ = sha2::Sha256::digest(b"unrelated use of Digest");
/// ```
pub trait Sink {
    fn update(&mut self, bytes: &[u8]);
}

impl Sink for Sha256 {
    #[inline]
    fn update(&mut self, bytes: &[u8]) {
        Digest::update(self, bytes);
    }
}

impl Sink for Vec<u8> {
    #[inline]
    fn update(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// Writes one tag byte, a little-endian `u64` byte length, and the bytes: the
/// shape of every provided encoding except `()` (FORMAT.md, section 5).
#[inline]
pub fn write_tagged<S: Sink + ?Sized>(sink: &mut S, tag: u8, bytes: &[u8]) {
    sink.update(&[tag]);
    sink.update(&(bytes.len() as u64).to_le_bytes());
    sink.update(bytes);
}

/// A set of stored objects, each keyed by the SHA-256 of its bytes.
///
/// The only way in is [`insert`](Self::insert), which computes the key, so an
/// `Objects` can never hold bytes that do not match their identity. Iteration
/// is in identity order, so equal sets iterate identically.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Objects {
    map: BTreeMap<Identity, Box<[u8]>>,
}

impl Objects {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an object and returns its identity, the SHA-256 of `bytes`.
    /// Adding bytes that are already present changes nothing.
    pub fn insert(&mut self, bytes: impl Into<Box<[u8]>>) -> Identity {
        let bytes = bytes.into();
        let id: Identity = Sha256::digest(&bytes).into();
        self.map.entry(id).or_insert(bytes);
        id
    }

    /// Adds bytes whose identity is already known because it was computed
    /// from these exact bytes (a node's cached identity), skipping the hash.
    pub(crate) fn insert_known(&mut self, id: Identity, bytes: Vec<u8>) {
        debug_assert_eq!(id, <Identity>::from(Sha256::digest(&bytes)));
        self.map.entry(id).or_insert_with(|| bytes.into());
    }

    pub fn get(&self, id: &Identity) -> Option<&[u8]> {
        self.map.get(id).map(|b| &b[..])
    }

    pub fn contains(&self, id: &Identity) -> bool {
        self.map.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Objects in identity order.
    pub fn iter(&self) -> impl Iterator<Item = (&Identity, &[u8])> {
        self.map.iter().map(|(id, b)| (id, &b[..]))
    }
}

impl fmt::Debug for Objects {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Objects({} objects)", self.map.len())
    }
}

/// Why stored bytes could not be read back as a map.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// An object the map refers to is not in the object set.
    Missing(Identity),
    /// The bytes are not a valid encoding.
    Malformed(&'static str),
    /// The bytes encode something, but not a canonical map.
    NonCanonical(&'static str),
    /// Maps are nested more than [`MAX_NESTING`] deep.
    TooDeep,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(id) => {
                write!(f, "missing object ")?;
                id.iter().take(8).try_for_each(|b| write!(f, "{b:02x}"))
            }
            Self::Malformed(why) => write!(f, "malformed: {why}"),
            Self::NonCanonical(why) => write!(f, "not canonical: {why}"),
            Self::TooDeep => write!(f, "maps nested more than {MAX_NESTING} deep"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// How deeply maps may nest inside stored values before loading gives up.
pub const MAX_NESTING: usize = 64;

/// State for one load: the object set, the nesting depth, and the nested maps
/// already loaded.
///
/// A nested map that occurs several times is loaded once and then shared, as
/// it would be in memory. That also bounds the work of a load by the number
/// of distinct objects, however often they are referenced.
pub struct Loader<'a> {
    objects: &'a Objects,
    nesting: usize,
    memo: HashMap<(Identity, TypeId), Box<dyn Any>>,
}

impl<'a> Loader<'a> {
    pub fn new(objects: &'a Objects) -> Self {
        Loader {
            objects,
            nesting: 0,
            memo: HashMap::new(),
        }
    }

    pub fn objects(&self) -> &'a Objects {
        self.objects
    }

    /// Loads the nested root `id` as a `T`, once per identity and type. Later
    /// requests return a clone of the first result, which for maps and sets
    /// shares the same nodes.
    pub fn nested<T: Clone + 'static>(
        &mut self,
        id: Identity,
        load: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<T, DecodeError> {
        let key = (id, TypeId::of::<T>());
        if let Some(done) = self.memo.get(&key) {
            return Ok(done
                .downcast_ref::<T>()
                .expect("memo entries are stored under their own type")
                .clone());
        }
        if self.nesting >= MAX_NESTING {
            return Err(DecodeError::TooDeep);
        }
        self.nesting += 1;
        let loaded = load(self);
        self.nesting -= 1;
        let value = loaded?;
        self.memo.insert(key, Box::new(value.clone()));
        Ok(value)
    }
}

/// Reads a value back from the encoding its [`Identify`](crate::Identify)
/// implementation writes.
///
/// An implementation must consume exactly one encoding from the front of
/// `input` and reject anything its `Identify` could not have written. Then a
/// stored map loads back equal to the map that was saved.
pub trait Decode: Sized {
    fn decode(input: &mut &[u8], loader: &mut Loader<'_>) -> Result<Self, DecodeError>;
}

/// Takes `n` bytes from the front of `input`.
pub fn read_bytes<'b>(input: &mut &'b [u8], n: usize) -> Result<&'b [u8], DecodeError> {
    if n > input.len() {
        return Err(DecodeError::Malformed("truncated input"));
    }
    let (head, rest) = input.split_at(n);
    *input = rest;
    Ok(head)
}

/// Takes an encoding written by [`write_tagged`] with the given tag, and
/// returns its payload.
pub fn read_tagged<'b>(input: &mut &'b [u8], tag: u8) -> Result<&'b [u8], DecodeError> {
    if read_bytes(input, 1)?[0] != tag {
        return Err(DecodeError::Malformed("unexpected type tag"));
    }
    let len = u64::from_le_bytes(read_bytes(input, 8)?.try_into().expect("8 bytes"));
    let len = usize::try_from(len).map_err(|_| DecodeError::Malformed("length too large"))?;
    read_bytes(input, len)
}

fn fixed<const N: usize>(input: &mut &[u8], tag: u8) -> Result<[u8; N], DecodeError> {
    read_tagged(input, tag)?
        .try_into()
        .map_err(|_| DecodeError::Malformed("wrong payload length"))
}

/// Reads a tagged 32-byte identity, as nested maps (`m`) and sets (`t`) write.
pub(crate) fn read_identity(input: &mut &[u8], tag: u8) -> Result<Identity, DecodeError> {
    fixed(input, tag)
}

impl Decode for String {
    fn decode(input: &mut &[u8], _: &mut Loader<'_>) -> Result<Self, DecodeError> {
        let bytes = read_tagged(input, b's')?;
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::Malformed("invalid UTF-8"))
    }
}

impl Decode for Vec<u8> {
    fn decode(input: &mut &[u8], _: &mut Loader<'_>) -> Result<Self, DecodeError> {
        Ok(read_tagged(input, b'b')?.to_vec())
    }
}

impl Decode for u64 {
    fn decode(input: &mut &[u8], _: &mut Loader<'_>) -> Result<Self, DecodeError> {
        Ok(u64::from_le_bytes(fixed(input, b'u')?))
    }
}

impl Decode for i64 {
    fn decode(input: &mut &[u8], _: &mut Loader<'_>) -> Result<Self, DecodeError> {
        Ok(i64::from_le_bytes(fixed(input, b'i')?))
    }
}

impl Decode for Identity {
    fn decode(input: &mut &[u8], _: &mut Loader<'_>) -> Result<Self, DecodeError> {
        fixed(input, b'#')
    }
}

impl Decode for () {
    fn decode(input: &mut &[u8], _: &mut Loader<'_>) -> Result<Self, DecodeError> {
        if read_bytes(input, 1)?[0] != b'0' {
            return Err(DecodeError::Malformed("unexpected type tag"));
        }
        Ok(())
    }
}
