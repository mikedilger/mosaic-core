use crate::{Error, InnerError, Tag};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

/// A sequence of `Tag`s, borrowed
///
/// See also `OwnedTagSet` for the owned variant.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct TagSet([u8]);

impl TagSet {
    // View a slice of bytes as a TagSet
    fn from_inner<S: AsRef<[u8]> + ?Sized>(s: &S) -> &TagSet {
        unsafe { &*(std::ptr::from_ref::<[u8]>(s.as_ref()) as *const TagSet) }
    }

    // View a mutable slice of bytes as a TagSet
    fn from_inner_mut(inner: &mut [u8]) -> &mut TagSet {
        // SAFETY: TagSet is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut TagSet is safe.
        unsafe { &mut *(std::ptr::from_mut::<[u8]>(inner) as *mut TagSet) }
    }

    /// Interpret a sequence of bytes as a `TagSet`.
    ///
    /// Does not tolerate trailing bytes after the data in the `input`.
    ///
    /// # Errors
    ///
    /// Returns an Err if the data is not valid.
    #[allow(clippy::missing_panics_doc)]
    pub fn from_bytes(input: &[u8]) -> Result<&TagSet, Error> {
        // We must have at least one tag
        if input.len() < 3 {
            return Err(InnerError::EndOfInput.into());
        }

        let mut p = 0;
        loop {
            let tag = Tag::from_bytes(&input[p..])?;
            let len = tag.as_bytes().len();
            p += len;
            if input.len() == p {
                return Ok(Self::from_inner(input));
            }
        }
    }

    /// Interpret a sequence of bytes as a `TagSet`.
    ///
    /// # Safety
    ///
    /// Bytes must be a valid `TagSet`, otherwise undefined results can occur including
    /// panics
    #[must_use]
    pub unsafe fn from_bytes_unchecked(input: &[u8]) -> &TagSet {
        Self::from_inner(input)
    }

    /// Copy to an allocated owned data type
    #[must_use]
    pub fn to_owned(&self) -> OwnedTagSet {
        OwnedTagSet(self.0.to_owned())
    }

    /// As bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Iterator over tags
    #[must_use]
    pub fn iter(&self) -> TagSetIter<'_> {
        TagSetIter {
            bytes: &self.0,
            p: 0,
        }
    }
}

impl<'a> IntoIterator for &'a TagSet {
    type Item = &'a Tag;
    type IntoIter = TagSetIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator of `Tag`s in `TagSet`
#[derive(Debug)]
pub struct TagSetIter<'a> {
    bytes: &'a [u8],
    p: usize,
}

impl<'a> Iterator for TagSetIter<'a> {
    type Item = &'a Tag;

    fn next(&mut self) -> Option<Self::Item> {
        if self.p >= self.bytes.len() {
            None
        } else {
            let tag = Tag::from_bytes(&self.bytes[self.p..]).unwrap();
            self.p += tag.as_bytes().len();
            Some(tag)
        }
    }
}

/// An owned set of `Tag`s
///
/// See `TagSet` for the borrowed variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct OwnedTagSet(Vec<u8>);

/// Empty `TagSet`
pub const EMPTY_TAG_SET: OwnedTagSet = OwnedTagSet(vec![]);

impl OwnedTagSet {
    /// Create a new `TagSet`
    #[must_use]
    pub fn new() -> OwnedTagSet {
        OwnedTagSet(Vec::new())
    }

    /// Create a new `TagSet` from an iterator over `Tag`s
    pub fn from_tags<'a, I>(input_tags: I) -> OwnedTagSet
    where
        I: IntoIterator<Item = &'a Tag>,
    {
        let mut tag_set = Self::new();
        for tag in input_tags {
            tag_set.add_tag(tag);
        }
        tag_set
    }

    /// Add a tag
    pub fn add_tag(&mut self, tag: &Tag) {
        self.0.extend(tag.as_bytes());
    }
}

impl Default for OwnedTagSet {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for OwnedTagSet {
    type Target = TagSet;

    fn deref(&self) -> &Self::Target {
        TagSet::from_inner(&self.0)
    }
}

impl DerefMut for OwnedTagSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        TagSet::from_inner_mut(&mut self.0)
    }
}

impl AsRef<TagSet> for OwnedTagSet {
    fn as_ref(&self) -> &TagSet {
        TagSet::from_inner(&self.0)
    }
}

impl AsMut<TagSet> for OwnedTagSet {
    fn as_mut(&mut self) -> &mut TagSet {
        TagSet::from_inner_mut(&mut self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{DuplicateHandling, KindFlags, ReadAccess};
    use crate::{Kind, OwnedTag, Reference, SecretKey, TagType};
    use rand::rngs::OsRng;

    #[test]
    fn test_tags() {
        let public_key = {
            let mut csprng = OsRng;
            let secret_key = SecretKey::generate(&mut csprng);
            secret_key.public()
        };
        let reference = {
            let printable = "moref01ge91q91o36bcfrk7qfhpnydyyobh88zknproi8j5791e5mekfez1ye6zrifbhh6m1dtizcsp4y5w";
            Reference::from_printable(printable).unwrap()
        };
        let url = "https://example.com/meme.jpg";
        let kind = Kind::from_parts(
            99,
            1,
            KindFlags::from_parts(DuplicateHandling::Versioned, ReadAccess::AuthorOnly, false),
        );
        let offset = 71;

        let mut tag_set = OwnedTagSet::new();
        let t1 = OwnedTag::new_notify_public_key(&public_key);
        tag_set.add_tag(&t1);
        let t2 = OwnedTag::new_reply(&reference, kind);
        tag_set.add_tag(&t2);
        let t3 = OwnedTag::new_content_segment_image(url, offset);
        tag_set.add_tag(&t3);

        let mut iter = tag_set.iter();
        assert_eq!(iter.next(), Some(&*t1));
        assert_eq!(iter.next(), Some(&*t2));
        assert_eq!(iter.next(), Some(&*t3));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_tags_iterator() {
        use crate::TagType;

        let example: Vec<u8> = vec![
            8, 0, // length
            1, 0, // type 1,
            10, 9, 8, 7, // data
            10, 0, // length
            2, 0, // type 2
            1, 2, 3, 4, 5, 6, // data
            7, 0, // length
            3, 1, // type
            3, 4, 5, // data
        ];

        let tag_set = TagSet::from_bytes(&example).unwrap();
        let mut iter = tag_set.iter();

        let tag0 = iter.next().unwrap();
        let tag1 = iter.next().unwrap();
        let tag2 = iter.next().unwrap();
        assert_eq!(iter.next(), None);

        assert_eq!(tag0.data_bytes(), &[10, 9, 8, 7]);
        assert_eq!(tag0.get_type(), TagType(1));
        assert_eq!(tag1.data_bytes(), &[1, 2, 3, 4, 5, 6]);
        assert_eq!(tag1.get_type(), TagType(2));
        assert_eq!(tag2.data_bytes(), &[3, 4, 5]);
        assert_eq!(tag2.get_type(), TagType(259));
    }

    #[test]
    fn test_owned_tag_set_from_owned_tags() {
        let mut csprng = OsRng;

        let secret_key = SecretKey::generate(&mut csprng);

        let tags = [
            OwnedTag::new_notify_public_key(&secret_key.public()),
            OwnedTag::new_nostr_sister(&[0; 32]),
            OwnedTag::new(TagType(100), b"testing").unwrap(),
            OwnedTag::new(TagType(101), b"more testing").unwrap(),
        ];

        let _owned_tag_set = OwnedTagSet::from_tags(tags.iter().map(|t| &**t));
    }
}
