use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use kaonashi_api::merkle::{hash_leaf, merkle_proof, merkle_root, verify_merkle_proof};

fn generate_leaves(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| hash_leaf(format!("vote-{i}").as_bytes()))
        .collect()
}

fn bench_merkle_tree_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("Merkle Tree Construction");

    let sizes = [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

    for size in sizes {
        let leaves = generate_leaves(size);

        group.bench_with_input(BenchmarkId::from_parameter(size), &leaves, |b, leaves| {
            b.iter(|| {
                black_box(merkle_root(black_box(leaves)).expect("Merkle root generation failed"));
            });
        });
    }

    group.finish();
}

fn bench_merkle_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Merkle Proof Generation");

    let sizes = [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

    for size in sizes {
        let leaves = generate_leaves(size);

        // Testamos a folha central para manter o índice válido
        // em todos os tamanhos.
        let index = size / 2;

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &(&leaves, index),
            |b, (leaves, index)| {
                b.iter(|| {
                    black_box(
                        merkle_proof(black_box(leaves), black_box(*index))
                            .expect("Merkle proof generation failed"),
                    );
                });
            },
        );
    }

    group.finish();
}

fn bench_merkle_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Merkle Proof Verification");

    let sizes = [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

    for size in sizes {
        let leaves = generate_leaves(size);
        let index = size / 2;

        let root = merkle_root(&leaves).expect("Merkle root generation failed");

        let proof = merkle_proof(&leaves, index).expect("Merkle proof generation failed");

        let leaf = leaves[index].clone();

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &(leaf, proof, root),
            |b, (leaf, proof, root)| {
                b.iter(|| {
                    let is_valid =
                        verify_merkle_proof(black_box(leaf), black_box(proof), black_box(root));

                    black_box(is_valid);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_merkle_tree_construction,
    bench_merkle_proof_generation,
    bench_merkle_proof_verification
);

criterion_main!(benches);
