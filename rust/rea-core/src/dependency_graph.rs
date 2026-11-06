// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Symphony

//! Bounded dependency-graph normalization for auditable Rust metadata.

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Invalid dependency indices discovered before graph expansion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyGraphError {
    /// An edge points outside the package list.
    TargetOutOfBounds {
        /// Package containing the invalid edge.
        from: usize,
        /// Invalid target index.
        to: usize,
    },
}

/// Returns package indices that participate in a directed dependency cycle.
///
/// The result is sorted by package index. The caller owns the returned vector
/// and must enable the crate's `alloc` feature; the rest of `rea-core` remains
/// usable with `--no-default-features`.
#[cfg(feature = "alloc")]
pub fn cyclic_dependency_indices(edges: &[&[usize]]) -> Result<Vec<usize>, DependencyGraphError> {
    let mut reversed = vec![Vec::new(); edges.len()];
    for (from, targets) in edges.iter().enumerate() {
        for &to in *targets {
            if to >= edges.len() {
                return Err(DependencyGraphError::TargetOutOfBounds { from, to });
            }
            reversed[to].push(from);
        }
    }

    let mut order = Vec::with_capacity(edges.len());
    let mut visited = vec![false; edges.len()];
    for start in 0..edges.len() {
        if visited[start] {
            continue;
        }
        visited[start] = true;
        let mut stack = vec![(start, 0usize)];
        while let Some((node, next_edge)) = stack.last_mut() {
            if *next_edge == edges[*node].len() {
                order.push(*node);
                stack.pop();
                continue;
            }
            let next = edges[*node][*next_edge];
            *next_edge += 1;
            if !visited[next] {
                visited[next] = true;
                stack.push((next, 0));
            }
        }
    }

    let mut assigned = vec![false; edges.len()];
    let mut cyclic = Vec::new();
    for &start in order.iter().rev() {
        if assigned[start] {
            continue;
        }
        assigned[start] = true;
        let mut component = Vec::new();
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            component.push(node);
            for &next in &reversed[node] {
                if !assigned[next] {
                    assigned[next] = true;
                    stack.push(next);
                }
            }
        }
        let is_cycle = component.len() > 1 || edges[start].contains(&start);
        if is_cycle {
            cyclic.extend(component);
        }
    }
    cyclic.sort_unstable();
    Ok(cyclic)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn returns_only_nodes_in_cycles() {
        let edges: [&[usize]; 5] = [&[1], &[2], &[1, 3], &[], &[4]];
        assert_eq!(cyclic_dependency_indices(&edges), Ok(std::vec![1, 2, 4]));
    }

    #[test]
    fn recognizes_self_cycles_and_sorts_indices() {
        let edges: [&[usize]; 4] = [&[0], &[], &[3], &[2]];
        assert_eq!(cyclic_dependency_indices(&edges), Ok(std::vec![0, 2, 3]));
    }

    #[test]
    fn rejects_out_of_bounds_edges_before_expansion() {
        let edges: [&[usize]; 1] = [&[1]];
        assert_eq!(
            cyclic_dependency_indices(&edges),
            Err(DependencyGraphError::TargetOutOfBounds { from: 0, to: 1 })
        );
    }
}
