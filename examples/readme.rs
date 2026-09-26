//! The README usage example, kept compiling: `cargo run --example readme`.
use merkle_champ::{ChampMap, ChampSet};
fn main() {
    let v1: ChampMap<String, u64> = [("a".to_string(), 1), ("b".into(), 2)]
        .into_iter()
        .collect();
    let v2 = v1.update("a".into(), 10).without(&"b".to_string());
    assert_eq!(v1.get(&"a".into()), Some(&1)); // v1 is unchanged
    assert_eq!(v1.diff(&v2).len(), 2);
    let id = v2.identity(); // cached; later versions reuse subtrees
    assert_eq!(id, v2.identity());

    let effects: ChampSet<String> = ["io".to_string(), "clock".into()].into_iter().collect();
    let fewer = effects.without(&"clock".to_string());
    assert_eq!(effects.diff(&fewer).len(), 1);
}
