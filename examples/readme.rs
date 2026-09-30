//! The README usage examples, kept compiling: `cargo run --example readme`.
use merkle_champ::{ChampMap, ChampSet, Objects};
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

    // Storing and loading.
    let v1: ChampMap<String, u64> = (0..1000).map(|i| (format!("k{i}"), i)).collect();
    let mut objects = Objects::new();
    let root = v1.save(&mut objects); // the map's identity
    let v2 = v1.update("k7".into(), 0);
    v2.save(&mut objects); // adds only the changed path
    let loaded: ChampMap<String, u64> = ChampMap::load(&root, &objects).unwrap();
    assert_eq!(loaded, v1);
}
