//! Simulated Annealing (SA) Implementation
//!
//! Simulated annealing is a metaheuristic used to approximate global optimum
//! in large search spaces. It inspired by the process of annealing in metallurgy.
//!
//! **Application in Kraken**: Escape from local optima during refactoring decisions.

use rand::RngExt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedAnnealer {
    current_solution: Vec<f64>,
    best_solution: Vec<f64>,
    current_energy: f64,
    best_energy: f64,
    temperature: f64,
    cooling_rate: f64,
    min_temperature: f64,
    iterations_per_temp: usize,
}

impl SimulatedAnnealer {
    pub fn new(
        dimensions: usize,
        initial_temperature: f64,
        cooling_rate: f64,
        min_temperature: f64,
        iterations_per_temp: usize,
    ) -> Self {
        let mut rng = rand::rng();

        let current_solution: Vec<f64> = (0..dimensions).map(|_| rng.random()).collect();
        let current_energy = f64::INFINITY;

        Self {
            current_solution: current_solution.clone(),
            best_solution: current_solution,
            current_energy,
            best_energy: f64::INFINITY,
            temperature: initial_temperature,
            cooling_rate,
            min_temperature,
            iterations_per_temp,
        }
    }

    pub fn with_default_params(dimensions: usize) -> Self {
        Self::new(dimensions, 1000.0, 0.995, 0.001, 100)
    }

    pub fn set_initial_solution(&mut self, solution: Vec<f64>) {
        self.current_solution = solution.clone();
        self.best_solution = solution;
    }

    pub fn run_iteration<F>(&mut self, energy_fn: F)
    where
        F: Fn(&[f64]) -> f64 + Copy,
    {
        let mut rng = rand::rng();

        // Evaluate current solution
        self.current_energy = energy_fn(&self.current_solution);

        // Track best
        if self.current_energy < self.best_energy {
            self.best_energy = self.current_energy;
            self.best_solution = self.current_solution.clone();
        }

        // Generate neighbor
        let mut neighbor = self.current_solution.clone();
        let idx = rng.random_range(0..neighbor.len());
        neighbor[idx] += rng.random_range(-0.1..0.1);
        neighbor[idx] = neighbor[idx].clamp(0.0, 1.0);

        // Calculate delta
        let neighbor_energy = energy_fn(&neighbor);
        let delta = neighbor_energy - self.current_energy;

        // Acceptance criterion
        let accept = if delta < 0.0 {
            true
        } else {
            let probability = (-delta / self.temperature).exp();
            rng.random::<f64>() < probability
        };

        if accept {
            self.current_solution = neighbor;
            self.current_energy = neighbor_energy;
        }

        // Cool down
        self.temperature *= self.cooling_rate;
    }

    pub fn optimize<F>(&mut self, energy_fn: F) -> Vec<f64>
    where
        F: Fn(&[f64]) -> f64 + Copy,
    {
        while self.temperature > self.min_temperature {
            for _ in 0..self.iterations_per_temp {
                self.run_iteration(energy_fn);
            }
        }
        self.best_solution.clone()
    }

    pub fn get_best(&self) -> Vec<f64> {
        self.best_solution.clone()
    }

    pub fn get_best_energy(&self) -> f64 {
        self.best_energy
    }

    pub fn get_temperature(&self) -> f64 {
        self.temperature
    }

    pub fn has_converged(&self) -> bool {
        self.temperature <= self.min_temperature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sa_creation() {
        let sa = SimulatedAnnealer::with_default_params(5);
        assert_eq!(sa.current_solution.len(), 5);
        assert!(sa.temperature > 0.0);
    }

    #[test]
    fn test_sa_optimization() {
        let energy_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| (x - 0.5).powi(2)).sum() };

        let mut sa = SimulatedAnnealer::new(3, 100.0, 0.99, 0.01, 10);
        let result = sa.optimize(energy_fn);

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_sa_new() {
        let sa = SimulatedAnnealer::new(4, 500.0, 0.95, 0.1, 50);
        assert_eq!(sa.current_solution.len(), 4);
        assert_eq!(sa.temperature, 500.0);
        assert_eq!(sa.cooling_rate, 0.95);
        assert_eq!(sa.min_temperature, 0.1);
        assert_eq!(sa.iterations_per_temp, 50);
        assert_eq!(sa.best_energy, f64::INFINITY);
        assert_eq!(sa.current_energy, f64::INFINITY);
    }

    #[test]
    fn test_sa_set_initial_solution() {
        let mut sa = SimulatedAnnealer::with_default_params(3);
        sa.set_initial_solution(vec![0.1, 0.2, 0.3]);
        assert_eq!(sa.current_solution, vec![0.1, 0.2, 0.3]);
        assert_eq!(sa.best_solution, vec![0.1, 0.2, 0.3]);
    }

    #[test]
    fn test_sa_get_best_energy() {
        let energy_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| x * x).sum() };
        let mut sa = SimulatedAnnealer::new(2, 10.0, 0.5, 1.0, 5);
        sa.optimize(energy_fn);
        assert!(sa.get_best_energy() < f64::INFINITY);
        assert!(sa.get_best_energy() >= 0.0);
    }

    #[test]
    fn test_sa_get_temperature() {
        let mut sa = SimulatedAnnealer::new(2, 100.0, 0.9, 1.0, 5);
        let initial_temp = sa.get_temperature();
        assert_eq!(initial_temp, 100.0);
        sa.run_iteration(|_| 1.0);
        assert!(sa.get_temperature() < initial_temp);
    }

    #[test]
    fn test_sa_has_converged() {
        let mut sa = SimulatedAnnealer::new(2, 0.1, 0.5, 1.0, 1);
        assert!(sa.has_converged());
    }

    #[test]
    fn test_sa_has_not_converged() {
        let sa = SimulatedAnnealer::new(2, 1000.0, 0.99, 0.001, 100);
        assert!(!sa.has_converged());
    }

    #[test]
    fn test_sa_get_best() {
        let mut sa = SimulatedAnnealer::with_default_params(3);
        sa.set_initial_solution(vec![0.1, 0.2, 0.3]);
        let best = sa.get_best();
        assert_eq!(best, vec![0.1, 0.2, 0.3]);
    }

    #[test]
    fn test_sa_with_default_params() {
        let sa = SimulatedAnnealer::with_default_params(5);
        assert_eq!(sa.temperature, 1000.0);
        assert_eq!(sa.cooling_rate, 0.995);
        assert_eq!(sa.min_temperature, 0.001);
        assert_eq!(sa.iterations_per_temp, 100);
    }

    #[test]
    fn test_sa_cooling_rate() {
        let mut sa = SimulatedAnnealer::new(2, 100.0, 0.5, 0.01, 1);
        let initial = sa.get_temperature();
        sa.run_iteration(|_| 1.0);
        assert!((sa.get_temperature() - initial * 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_sa_run_iteration_tracks_best() {
        let mut sa = SimulatedAnnealer::new(2, 10.0, 0.5, 0.01, 10);
        sa.set_initial_solution(vec![0.9, 0.9]);
        let energy_fn = |pos: &[f64]| -> f64 { pos.iter().map(|x| x * x).sum() };
        for _ in 0..20 {
            sa.run_iteration(energy_fn);
        }
        assert!(sa.get_best_energy() <= 2.0);
    }
}
