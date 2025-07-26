use crate::{prelude::*, Hasher};
use sha2::{digest::FixedOutput, Digest, Sha256};

/// Sha256 implementation of the [`Hasher`] trait.
///
/// # Examples
///
/// ```
/// # use rs_merkle::{MerkleTree, MerkleProof, algorithms::Sha256, Hasher, Error, utils};
/// # use std::convert::TryFrom;
/// #
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///  let tree = MerkleTree::<Sha256>::new();
///  let other_tree: MerkleTree<Sha256> = MerkleTree::new();
///
/// let proof_bytes: Vec<u8> = vec![
///     46, 125, 44, 3, 169, 80, 122, 226, 101, 236, 245, 181, 53, 104, 133, 165, 51, 147, 162,
///     2, 157, 36, 19, 148, 153, 114, 101, 161, 162, 90, 239, 198, 37, 47, 16, 200, 54, 16,
///     235, 202, 26, 5, 156, 11, 174, 130, 85, 235, 162, 249, 91, 228, 209, 215, 188, 250,
///     137, 215, 36, 138, 130, 217, 241, 17, 229, 160, 31, 238, 20, 224, 237, 92, 72, 113, 79,
///     34, 24, 15, 37, 173, 131, 101, 181, 63, 151, 121, 247, 157, 196, 163, 215, 233, 57, 99,
///     249, 74,
/// ];
///
/// let proof_result = MerkleProof::<Sha256>::from_bytes(&proof_bytes);
/// # Ok(())
/// # }
/// ```
///
/// [`Hasher`]: crate::Hasher
#[derive(Clone)]
pub struct Sha256Algorithm {}

impl Hasher for Sha256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        <[u8; 32]>::from(Sha256::digest(data))
    }
}


#[cfg(test)]
mod test {
    use crate::{prelude::*, Hasher};
    use super::Sha256Algorithm;
    
    use sha2::{Digest, Sha256, digest::FixedOutput};

    #[test]
    fn test_sha256_with_regular_digest() {
        let buffer = b"hello world";
        
        let output = Sha256Algorithm::hash(&buffer[..]);

        let mut old_method = Sha256::new();
        old_method.update(&buffer);
        
        let expected = <[u8; 32]>::from(old_method.finalize_fixed())
        assert_eq!(output, expected)
    }
}
