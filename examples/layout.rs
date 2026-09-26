use merkle_champ::{ChampMap, hash_bytes};
use std::hint::black_box;
use std::time::Instant;
fn main() {
    let n = 1_000_000;
    let keys: Vec<String> = (0..n)
        .map(|i| format!("ns{:02}.word{}", i % 64, i))
        .collect();
    let m: ChampMap<String, u64> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), i as u64))
        .collect();
    let (e, nodes, slots) = m.layout_stats();
    println!(
        "entries by depth {e:?}\nnodes by depth {nodes:?}\nslots {slots} slot size {}",
        std::mem::size_of::<(String, u64)>()
    );
    let mut x = 0u64;
    let probes: Vec<usize> = (0..1024).map(|i| (i * 7919 + 13) % n).collect();
    let t = Instant::now();
    for _ in 0..100 {
        for &i in &probes {
            x = x.wrapping_add(hash_bytes(keys[i].as_bytes()));
        }
    }
    println!(
        "hash only: {:.1} ns",
        t.elapsed().as_nanos() as f64 / 102400.0
    );
    let t = Instant::now();
    for _ in 0..100 {
        for &i in &probes {
            x = x.wrapping_add(*m.get(&keys[i]).unwrap());
        }
    }
    println!("get: {:.1} ns", t.elapsed().as_nanos() as f64 / 102400.0);
    let im: imbl::HashMap<String, u64> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), i as u64))
        .collect();
    let t = Instant::now();
    for _ in 0..100 {
        for &i in &probes {
            x = x.wrapping_add(*im.get(&keys[i]).unwrap());
        }
    }
    println!(
        "imbl get (default hasher): {:.1} ns",
        t.elapsed().as_nanos() as f64 / 102400.0
    );
    // Random probes over the whole key set, one pass each (cold).
    let mut r = 0x1234_5678u64;
    let cold: Vec<usize> = (0..200_000)
        .map(|_| {
            r ^= r << 13;
            r ^= r >> 7;
            r ^= r << 17;
            (r % n as u64) as usize
        })
        .collect();
    let t = Instant::now();
    for &i in &cold {
        x = x.wrapping_add(*m.get(&keys[i]).unwrap());
    }
    println!(
        "champ cold get: {:.1} ns",
        t.elapsed().as_nanos() as f64 / cold.len() as f64
    );
    let t = Instant::now();
    for &i in &cold {
        x = x.wrapping_add(*im.get(&keys[i]).unwrap());
    }
    println!(
        "imbl cold get: {:.1} ns",
        t.elapsed().as_nanos() as f64 / cold.len() as f64
    );
    black_box(x);
}
