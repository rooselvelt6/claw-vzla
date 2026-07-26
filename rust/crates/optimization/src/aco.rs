//! Ant Colony Optimization (ACO) Implementation
//!
//! ACO is a metaheuristic inspired by the foraging behavior of ant colonies.
//! It solves optimization problems by simulating ants that deposit pheromones
//! on paths they traverse.
//!
//! **Application in Kraken**: Path discovery for code navigation

use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a node in the pheromone graph
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub node_type: NodeType,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    File,
    Function,
    Class,
    Module,
    Dependency,
}

/// Represents an edge with pheromone level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub pheromone: f64,
    pub distance: f64,
}

/// Pheromone graph for ACO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PheromoneGraph {
    nodes: HashMap<String, Node>,
    edges: HashMap<(String, String), Edge>,
    pheromone_decay: f64,
    pheromone_deposit: f64,
}

impl PheromoneGraph {
    /// Create a new empty pheromone graph
    pub fn new(pheromone_decay: f64, pheromone_deposit: f64) -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            pheromone_decay,
            pheromone_deposit,
        }
    }

    /// Add a node to the graph
    pub fn add_node(&mut self, id: String, node_type: NodeType) {
        let node = Node {
            id: id.clone(),
            node_type,
        };
        self.nodes.insert(id, node);
    }

    /// Add an edge between two nodes
    pub fn add_edge(&mut self, from: String, to: String, distance: f64) {
        let edge = Edge {
            from: from.clone(),
            to: to.clone(),
            pheromone: 1.0, // Initial pheromone
            distance,
        };
        self.edges.insert((from, to), edge);
    }

    /// Get pheromone level for an edge
    pub fn get_pheromone(&self, from: &str, to: &str) -> f64 {
        self.edges
            .get(&(from.to_string(), to.to_string()))
            .map(|e| e.pheromone)
            .unwrap_or(0.0)
    }

    /// Update pheromone levels (decay + deposit)
    pub fn update_pheromones(&mut self, paths: &[Vec<String>], fitness_values: &[f64]) {
        // First, decay all pheromones
        for edge in self.edges.values_mut() {
            edge.pheromone *= 1.0 - self.pheromone_decay;
        }

        // Then, deposit pheromones on successful paths
        for (path, fitness) in paths.iter().zip(fitness_values.iter()) {
            let deposit = self.pheromone_deposit * fitness;

            for i in 0..path.len().saturating_sub(1) {
                let key = (path[i].clone(), path[i + 1].clone());
                if let Some(edge) = self.edges.get_mut(&key) {
                    edge.pheromone += deposit;
                }
            }
        }
    }

    /// Get probability of moving from one node to another
    pub fn get_transition_probability(&self, from: &str, to: &str) -> f64 {
        let pheromone = self.get_pheromone(from, to);
        let edge = self.edges.get(&(from.to_string(), to.to_string()));
        let distance = edge.map(|e| e.distance).unwrap_or(1.0);

        // Higher pheromone and shorter distance = higher probability
        pheromone / distance
    }

    /// Get all edges from a node
    pub fn get_edges_from(&self, node: &str) -> Vec<String> {
        self.edges
            .keys()
            .filter(|(from, _)| from == node)
            .map(|(_, to)| to.clone())
            .collect()
    }

    /// Get node count
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get edge count
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

/// An ant that traverses the graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ant {
    pub current_node: String,
    pub visited: Vec<String>,
    pub path: Vec<String>,
    pub fitness: f64,
}

impl Ant {
    /// Create a new ant at a starting node
    pub fn new(start_node: String) -> Self {
        Self {
            current_node: start_node.clone(),
            visited: vec![start_node.clone()],
            path: vec![start_node],
            fitness: 0.0,
        }
    }

    /// Move to next node based on pheromone probabilities
    pub fn move_to(&mut self, graph: &PheromoneGraph, alpha: f64, beta: f64) -> bool {
        let available: Vec<String> = graph
            .get_edges_from(&self.current_node)
            .into_iter()
            .filter(|n| !self.visited.contains(n))
            .collect();

        if available.is_empty() {
            return false; // No more moves possible
        }

        // Calculate probabilities
        let mut probabilities: Vec<f64> = Vec::new();
        let mut total: f64 = 0.0;

        for node in &available {
            let pheromone = graph.get_pheromone(&self.current_node, node).powf(alpha);
            let edge = graph.edges.get(&(self.current_node.clone(), node.clone()));
            let heuristic = (1.0 / edge.map(|e| e.distance).unwrap_or(1.0)).powf(beta);

            let prob = pheromone * heuristic;
            probabilities.push(prob);
            total += prob;
        }

        // Roulette wheel selection
        if total > 0.0 {
            let mut rng = rand::rng();
            let mut r = rng.random::<f64>() * total;

            for (i, prob) in probabilities.iter().enumerate() {
                r -= prob;
                if r <= 0.0 {
                    let next_node = available[i].clone();
                    self.current_node = next_node.clone();
                    self.visited.push(next_node.clone());
                    self.path.push(next_node);
                    return true;
                }
            }
        }

        // Fallback: random selection
        if !available.is_empty() {
            let mut rng = rand::rng();
            let idx = rng.random_range(0..available.len());
            let next_node = available[idx].clone();
            self.current_node = next_node.clone();
            self.visited.push(next_node.clone());
            self.path.push(next_node);
            return true;
        }

        false
    }

    /// Reset ant to start at a new node
    pub fn reset(&mut self, start_node: String) {
        self.current_node = start_node.clone();
        self.visited = vec![start_node.clone()];
        self.path = vec![start_node];
        self.fitness = 0.0;
    }
}

/// ACO Path Finder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ACOPathFinder {
    graph: PheromoneGraph,
    ants: Vec<Ant>,
    alpha: f64, // Pheromone importance
    beta: f64,  // Heuristic importance
    ant_count: usize,
    max_iterations: usize,
    current_iteration: usize,
    best_path: Vec<String>,
    best_fitness: f64,
}

impl ACOPathFinder {
    /// Create a new ACO path finder
    pub fn new(ant_count: usize, max_iterations: usize, alpha: f64, beta: f64) -> Self {
        Self {
            graph: PheromoneGraph::new(0.5, 1.0),
            ants: Vec::with_capacity(ant_count),
            alpha,
            beta,
            ant_count,
            max_iterations,
            current_iteration: 0,
            best_path: Vec::new(),
            best_fitness: f64::NEG_INFINITY,
        }
    }

    /// Initialize the graph with nodes
    pub fn initialize_graph(&mut self, nodes: Vec<String>, node_types: Vec<NodeType>) {
        for (id, node_type) in nodes.into_iter().zip(node_types.into_iter()) {
            self.graph.add_node(id, node_type);
        }
    }

    /// Add connections between nodes
    pub fn add_connection(&mut self, from: String, to: String, distance: f64) {
        self.graph.add_edge(from, to, distance);
    }

    /// Run one iteration of ACO
    pub fn iterate<F>(&mut self, fitness_fn: F)
    where
        F: Fn(&[String]) -> f64 + Copy,
    {
        // Reset and spawn ants at random starting nodes
        let nodes: Vec<String> = self.graph.nodes.keys().cloned().collect();
        if nodes.is_empty() {
            return;
        }

        let mut rng = rand::rng();
        self.ants.clear();

        for _ in 0..self.ant_count {
            let start = nodes[rng.random_range(0..nodes.len())].clone();
            self.ants.push(Ant::new(start));
        }

        // Let ants traverse the graph
        let max_path_length = 10;
        let mut paths: Vec<Vec<String>> = Vec::new();

        for ant in &mut self.ants {
            let mut moves = 0;
            while moves < max_path_length && ant.move_to(&self.graph, self.alpha, self.beta) {
                moves += 1;
            }
            ant.fitness = fitness_fn(&ant.path);
            paths.push(ant.path.clone());

            // Track best
            if ant.fitness > self.best_fitness {
                self.best_fitness = ant.fitness;
                self.best_path = ant.path.clone();
            }
        }

        // Update pheromones
        let fitness_values: Vec<f64> = self.ants.iter().map(|a| a.fitness).collect();
        self.graph.update_pheromones(&paths, &fitness_values);

        self.current_iteration += 1;
    }

    /// Run full ACO optimization
    pub fn optimize<F>(&mut self, fitness_fn: F) -> Vec<String>
    where
        F: Fn(&[String]) -> f64 + Copy,
    {
        while self.current_iteration < self.max_iterations {
            self.iterate(fitness_fn);
        }

        self.best_path.clone()
    }

    /// Get best path found
    pub fn best_path(&self) -> &[String] {
        &self.best_path
    }

    /// Get best fitness
    pub fn best_fitness(&self) -> f64 {
        self.best_fitness
    }

    /// Get graph info
    pub fn graph_info(&self) -> (usize, usize) {
        (self.graph.node_count(), self.graph.edge_count())
    }
}

/// Path result from ACO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Path {
    pub nodes: Vec<String>,
    pub total_distance: f64,
    pub pheromone_level: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_creation() {
        let graph = PheromoneGraph::new(0.5, 1.0);
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_add_nodes_and_edges() {
        let mut graph = PheromoneGraph::new(0.5, 1.0);

        graph.add_node("file1.rs".to_string(), NodeType::File);
        graph.add_node("function_a".to_string(), NodeType::Function);

        graph.add_edge("file1.rs".to_string(), "function_a".to_string(), 1.0);

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn test_ant_movement() {
        let mut graph = PheromoneGraph::new(0.5, 1.0);
        graph.add_node("A".to_string(), NodeType::File);
        graph.add_node("B".to_string(), NodeType::File);
        graph.add_node("C".to_string(), NodeType::File);

        graph.add_edge("A".to_string(), "B".to_string(), 1.0);
        graph.add_edge("A".to_string(), "C".to_string(), 1.0);

        let mut ant = Ant::new("A".to_string());
        let moved = ant.move_to(&graph, 1.0, 1.0);

        assert!(moved);
        assert!(ant.visited.contains(&"B".to_string()) || ant.visited.contains(&"C".to_string()));
    }

    #[test]
    fn test_aco_path_finding() {
        let mut aco = ACOPathFinder::new(10, 20, 1.0, 1.0);

        // Simple graph: A -> B -> C -> D
        aco.initialize_graph(
            vec![
                "A".to_string(),
                "B".to_string(),
                "C".to_string(),
                "D".to_string(),
            ],
            vec![NodeType::File; 4],
        );

        aco.add_connection("A".to_string(), "B".to_string(), 1.0);
        aco.add_connection("B".to_string(), "C".to_string(), 1.0);
        aco.add_connection("C".to_string(), "D".to_string(), 1.0);

        // Fitness: prefer longer paths with all nodes
        let fitness_fn = |path: &[String]| -> f64 { path.len() as f64 };

        let result = aco.optimize(fitness_fn);

        // Should have found some path
        assert!(!result.is_empty());
    }

    #[test]
    fn test_pheromone_graph_missing_edge() {
        let graph = PheromoneGraph::new(0.5, 1.0);
        assert_eq!(graph.get_pheromone("X", "Y"), 0.0);
    }

    #[test]
    fn test_pheromone_graph_get_edges_from() {
        let mut graph = PheromoneGraph::new(0.5, 1.0);
        graph.add_node("A".to_string(), NodeType::File);
        graph.add_node("B".to_string(), NodeType::File);
        graph.add_node("C".to_string(), NodeType::File);
        graph.add_edge("A".to_string(), "B".to_string(), 1.0);
        graph.add_edge("A".to_string(), "C".to_string(), 2.0);

        let mut edges = graph.get_edges_from("A");
        edges.sort();
        assert_eq!(edges, vec!["B".to_string(), "C".to_string()]);
    }

    #[test]
    fn test_pheromone_graph_update_pheromones() {
        let mut graph = PheromoneGraph::new(0.5, 1.0);
        graph.add_node("A".to_string(), NodeType::File);
        graph.add_node("B".to_string(), NodeType::File);
        graph.add_edge("A".to_string(), "B".to_string(), 1.0);

        let initial = graph.get_pheromone("A", "B");
        assert_eq!(initial, 1.0);

        let paths = vec![vec!["A".to_string(), "B".to_string()]];
        let fitness_values = vec![1.0];
        graph.update_pheromones(&paths, &fitness_values);

        let after = graph.get_pheromone("A", "B");
        // decay: 1.0 * (1 - 0.5) = 0.5, then deposit 1.0 * 1.0 = 1.0, total = 1.5
        assert!(after > initial);
    }

    #[test]
    fn test_pheromone_graph_get_transition_probability() {
        let mut graph = PheromoneGraph::new(0.5, 1.0);
        graph.add_node("A".to_string(), NodeType::File);
        graph.add_node("B".to_string(), NodeType::File);
        graph.add_edge("A".to_string(), "B".to_string(), 2.0);

        // pheromone=1.0, distance=2.0 -> prob = 1.0 / 2.0 = 0.5
        let prob = graph.get_transition_probability("A", "B");
        assert!((prob - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_ant_new() {
        let ant = Ant::new("start".to_string());
        assert_eq!(ant.current_node, "start");
        assert_eq!(ant.visited, vec!["start".to_string()]);
        assert_eq!(ant.path, vec!["start".to_string()]);
        assert_eq!(ant.fitness, 0.0);
    }

    #[test]
    fn test_ant_reset() {
        let mut ant = Ant::new("A".to_string());
        ant.path = vec!["A".to_string(), "B".to_string(), "C".to_string()];
        ant.visited = vec!["A".to_string(), "B".to_string(), "C".to_string()];
        ant.fitness = 42.0;

        ant.reset("X".to_string());
        assert_eq!(ant.current_node, "X");
        assert_eq!(ant.path, vec!["X".to_string()]);
        assert_eq!(ant.visited, vec!["X".to_string()]);
        assert_eq!(ant.fitness, 0.0);
    }

    #[test]
    fn test_aco_graph_info() {
        let mut aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
        aco.initialize_graph(
            vec!["A".to_string(), "B".to_string(), "C".to_string()],
            vec![NodeType::File; 3],
        );
        aco.add_connection("A".to_string(), "B".to_string(), 1.0);
        aco.add_connection("B".to_string(), "C".to_string(), 1.0);

        let (nodes, edges) = aco.graph_info();
        assert_eq!(nodes, 3);
        assert_eq!(edges, 2);
    }

    #[test]
    fn test_node_types() {
        let types = vec![
            NodeType::File,
            NodeType::Function,
            NodeType::Class,
            NodeType::Module,
            NodeType::Dependency,
        ];
        assert_eq!(types.len(), 5);
        assert!(matches!(types[0], NodeType::File));
        assert!(matches!(types[4], NodeType::Dependency));
    }

    #[test]
    fn test_pheromone_graph_update_pheromones_empty() {
        let mut graph = PheromoneGraph::new(0.5, 1.0);
        graph.add_node("A".to_string(), NodeType::File);
        graph.update_pheromones(&[], &[]);
        assert_eq!(graph.get_pheromone("A", "B"), 0.0);
    }

    #[test]
    fn test_pheromone_graph_get_transition_probability_missing() {
        let graph = PheromoneGraph::new(0.5, 1.0);
        let prob = graph.get_transition_probability("X", "Y");
        assert_eq!(prob, 0.0);
    }

    #[test]
    fn test_ant_no_moves_available() {
        let mut graph = PheromoneGraph::new(0.5, 1.0);
        graph.add_node("A".to_string(), NodeType::File);
        let mut ant = Ant::new("A".to_string());
        let moved = ant.move_to(&graph, 1.0, 1.0);
        assert!(!moved);
    }

    #[test]
    fn test_ant_move_already_visited() {
        let mut graph = PheromoneGraph::new(0.5, 1.0);
        graph.add_node("A".to_string(), NodeType::File);
        graph.add_node("B".to_string(), NodeType::File);
        graph.add_edge("A".to_string(), "B".to_string(), 1.0);
        let mut ant = Ant::new("A".to_string());
        ant.move_to(&graph, 1.0, 1.0);
        let moved = ant.move_to(&graph, 1.0, 1.0);
        assert!(!moved);
    }

    #[test]
    fn test_aco_iterate_empty_graph() {
        let mut aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
        let fitness_fn = |path: &[String]| -> f64 { path.len() as f64 };
        aco.iterate(fitness_fn);
        assert_eq!(aco.best_path().len(), 0);
    }

    #[test]
    fn test_path_struct() {
        let path = Path {
            nodes: vec!["A".to_string(), "B".to_string()],
            total_distance: 5.0,
            pheromone_level: 0.75,
        };
        assert_eq!(path.nodes.len(), 2);
        assert_eq!(path.total_distance, 5.0);
        assert_eq!(path.pheromone_level, 0.75);
    }

    #[test]
    fn test_aco_best_fitness_initial() {
        let aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
        assert_eq!(aco.best_fitness(), f64::NEG_INFINITY);
    }

    #[test]
    fn test_aco_best_path_initial() {
        let aco = ACOPathFinder::new(5, 10, 1.0, 1.0);
        assert!(aco.best_path().is_empty());
    }

    #[test]
    fn test_pheromone_graph_node_types() {
        let mut graph = PheromoneGraph::new(0.3, 2.0);
        graph.add_node("f1".to_string(), NodeType::File);
        graph.add_node("fn1".to_string(), NodeType::Function);
        graph.add_node("cls1".to_string(), NodeType::Class);
        graph.add_node("mod1".to_string(), NodeType::Module);
        graph.add_node("dep1".to_string(), NodeType::Dependency);
        assert_eq!(graph.node_count(), 5);
    }

    #[test]
    fn test_pheromone_graph_multiple_edges_from_node() {
        let mut graph = PheromoneGraph::new(0.5, 1.0);
        graph.add_node("A".to_string(), NodeType::File);
        graph.add_node("B".to_string(), NodeType::File);
        graph.add_node("C".to_string(), NodeType::File);
        graph.add_node("D".to_string(), NodeType::File);
        graph.add_edge("A".to_string(), "B".to_string(), 1.0);
        graph.add_edge("A".to_string(), "C".to_string(), 2.0);
        graph.add_edge("A".to_string(), "D".to_string(), 3.0);
        assert_eq!(graph.edge_count(), 3);
        let edges = graph.get_edges_from("A");
        assert_eq!(edges.len(), 3);
    }
}
