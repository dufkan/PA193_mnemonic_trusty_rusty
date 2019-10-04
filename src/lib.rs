use sha2::{Sha256, Digest};

pub fn hello_hash() -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.input(b"Hello Library!");
    hasher.result().into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example() {
        hello_hash();
        assert_eq!(1 + 1, 2);
    }
}