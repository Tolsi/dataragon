use shamirsecretsharing::*;

fn main() {
    // Create a some shares over the secret data `[42, 42, 42, ...]`
    let data = vec![42; DATA_SIZE];
    let count = 5;
    let treshold = 4;
    let mut shares = create_shares(&data, count, treshold).unwrap();

    // Lose a share (for demonstrational purposes)
    shares.remove(3);

    // We still have 4 shares, so we should still be able to restore the secret
    let restored = combine_shares(&shares).unwrap();
    assert_eq!(restored, Some(data));

    // If we lose another share the secret is lost
    shares.remove(0);
    let restored2 = combine_shares(&shares).unwrap();
    assert_eq!(restored2, None);
}
