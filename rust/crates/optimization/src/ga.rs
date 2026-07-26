//! Genetic Algorithm (GA) Implementation
//!
//! GA is a metaheuristic inspired by the process of natural selection.
//! It optimizes a problem by evolving a population of candidate solutions.
//!
//! **Application in Kraken**: Evolution of coding strategies

use rand::RngExt;
use serde::{Deserialize, Serialize};

/// Represents a chromosome (solution) in the genetic algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chromosome {
    /// Genes representing the solution
    pub genes: Vec<f64>,
    /// Fitness score (higher is better)
    pub fitness: f64,
}

impl Chromosome {
    /// Create a new random chromosome
    pub fn new(gene_count: usize) -> Self {
        let mut rng = rand::rng();
        let genes: Vec<f64> = (0..gene_count).map(|_| rng.random()).collect();

        Self {
            genes,
            fitness: 0.0,
        }
    }

    /// Create a chromosome from specific genes
    pub fn from_genes(genes: Vec<f64>) -> Self {
        Self {
            genes,
            fitness: 0.0,
        }
    }

    /// Get a specific gene
    pub fn gene(&self, index: usize) -> Option<f64> {
        self.genes.get(index).copied()
    }

    /// Set a specific gene
    pub fn set_gene(&mut self, index: usize, value: f64) {
        if index < self.genes.len() {
            self.genes[index] = value;
        }
    }

    /// Mutate a random gene
    pub fn mutate(&mut self, mutation_rate: f64) {
        let mut rng = rand::rng();

        for gene in &mut self.genes {
            if rng.random::<f64>() < mutation_rate {
                *gene = rng.random();
            }
        }
    }

    /// Crossover with another chromosome (single-point crossover)
    pub fn crossover(&self, other: &Chromosome) -> (Chromosome, Chromosome) {
        let mut rng = rand::rng();
        let crossover_point = rng.random_range(1..self.genes.len());

        let mut child1_genes = self.genes[..crossover_point].to_vec();
        child1_genes.extend_from_slice(&other.genes[crossover_point..]);

        let mut child2_genes = other.genes[..crossover_point].to_vec();
        child2_genes.extend_from_slice(&self.genes[crossover_point..]);

        (
            Chromosome::from_genes(child1_genes),
            Chromosome::from_genes(child2_genes),
        )
    }
}

/// Fitness evaluation function type
pub type FitnessFn = dyn Fn(&Chromosome) -> f64 + Send + Sync;

/// Genetic Algorithm Optimizer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneticOptimizer {
    population: Vec<Chromosome>,
    population_size: usize,
    gene_count: usize,
    mutation_rate: f64,
    crossover_rate: f64,
    elite_count: usize,
    max_iterations: usize,
    current_iteration: usize,
    best_chromosome: Chromosome,
}

impl GeneticOptimizer {
    /// Create a new genetic optimizer
    pub fn new(
        population_size: usize,
        gene_count: usize,
        mutation_rate: f64,
        crossover_rate: f64,
        max_iterations: usize,
    ) -> Self {
        let elite_count = (population_size as f64 * 0.1) as usize; // Top 10%

        let mut population = Vec::with_capacity(population_size);
        for _ in 0..population_size {
            population.push(Chromosome::new(gene_count));
        }

        let best_chromosome = Chromosome::new(gene_count);

        Self {
            population,
            population_size,
            gene_count,
            mutation_rate,
            crossover_rate,
            elite_count,
            max_iterations,
            current_iteration: 0,
            best_chromosome,
        }
    }

    /// Evaluate fitness for all chromosomes
    pub fn evaluate<F>(&mut self, fitness_fn: &F)
    where
        F: Fn(&Chromosome) -> f64 + Send + Sync,
    {
        for chromosome in &mut self.population {
            chromosome.fitness = fitness_fn(chromosome);

            // Track best
            if chromosome.fitness > self.best_chromosome.fitness {
                self.best_chromosome = chromosome.clone();
            }
        }

        // Sort by fitness (descending)
        self.population
            .sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap());
    }

    /// Perform selection (tournament selection)
    fn select(&self) -> Chromosome {
        let mut rng = rand::rng();
        let tournament_size = 3;

        let mut best = &self.population[rng.random_range(0..self.population.len())];

        for _ in 0..tournament_size - 1 {
            let candidate = &self.population[rng.random_range(0..self.population.len())];
            if candidate.fitness > best.fitness {
                best = candidate;
            }
        }

        best.clone()
    }

    /// Create next generation
    fn reproduce(&self) -> Vec<Chromosome> {
        let mut rng = rand::rng();
        let mut new_population = Vec::with_capacity(self.population_size);

        // Keep elite chromosomes
        for i in 0..self.elite_count {
            new_population.push(self.population[i].clone());
        }

        // Fill rest with crossover and mutation
        while new_population.len() < self.population_size {
            let parent1 = self.select();
            let parent2 = self.select();

            let mut child1: Chromosome;
            let mut child2: Chromosome;

            if rng.random::<f64>() < self.crossover_rate {
                (child1, child2) = parent1.crossover(&parent2);
            } else {
                child1 = parent1.clone();
                child2 = parent2.clone();
            }

            child1.mutate(self.mutation_rate);
            child2.mutate(self.mutation_rate);

            new_population.push(child1);
            if new_population.len() < self.population_size {
                new_population.push(child2);
            }
        }

        new_population
    }

    /// Run one iteration of GA
    pub fn iterate<F>(&mut self, fitness_fn: &F)
    where
        F: Fn(&Chromosome) -> f64 + Send + Sync,
    {
        self.evaluate(fitness_fn);
        self.population = self.reproduce();
        self.current_iteration += 1;
    }

    /// Run full GA optimization
    pub fn optimize<F>(&mut self, fitness_fn: &F) -> Vec<f64>
    where
        F: Fn(&Chromosome) -> f64 + Send + Sync,
    {
        // Initial evaluation
        self.evaluate(fitness_fn);

        while self.current_iteration < self.max_iterations {
            self.iterate(fitness_fn);
        }

        // Final evaluation to get best
        self.evaluate(fitness_fn);

        self.best_chromosome.genes.clone()
    }

    /// Get the best solution found
    pub fn best_solution(&self) -> &Chromosome {
        &self.best_chromosome
    }

    /// Get best fitness value
    pub fn best_fitness(&self) -> f64 {
        self.best_chromosome.fitness
    }

    /// Get current iteration
    pub fn iteration(&self) -> usize {
        self.current_iteration
    }

    /// Get population statistics
    pub fn stats(&self) -> GAStats {
        let fitness_values: Vec<f64> = self.population.iter().map(|c| c.fitness).collect();
        let sum: f64 = fitness_values.iter().sum();
        let mean = sum / fitness_values.len() as f64;

        GAStats {
            iteration: self.current_iteration,
            best_fitness: self.best_chromosome.fitness,
            average_fitness: mean,
            population_size: self.population_size,
        }
    }
}

/// Statistics about the GA population
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GAStats {
    pub iteration: usize,
    pub best_fitness: f64,
    pub average_fitness: f64,
    pub population_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ga_creation() {
        let ga = GeneticOptimizer::new(50, 10, 0.01, 0.8, 100);
        assert_eq!(ga.population_size, 50);
        assert_eq!(ga.gene_count, 10);
    }

    #[test]
    fn test_crossover() {
        let chrom1 = Chromosome::from_genes(vec![0.0, 0.0, 0.0, 0.0]);
        let chrom2 = Chromosome::from_genes(vec![1.0, 1.0, 1.0, 1.0]);

        let (child1, child2) = chrom1.crossover(&chrom2);

        assert_eq!(child1.genes.len(), 4);
        assert_eq!(child2.genes.len(), 4);
    }

    #[test]
    fn test_optimization() {
        // Maximize sum of genes (should converge to 1.0)
        let fitness_fn = |chrom: &Chromosome| -> f64 {
            chrom.genes.iter().sum::<f64>() / chrom.genes.len() as f64
        };

        let mut ga = GeneticOptimizer::new(50, 5, 0.1, 0.8, 50);
        let result = ga.optimize(&fitness_fn);

        assert_eq!(result.len(), 5);

        // Best fitness should be reasonable (genes close to 1.0)
        assert!(ga.best_fitness() > 0.5);
    }

    #[test]
    fn test_chromosome_from_genes() {
        let genes = vec![0.1, 0.2, 0.3];
        let chrom = Chromosome::from_genes(genes.clone());
        assert_eq!(chrom.genes, genes);
        assert_eq!(chrom.fitness, 0.0);
    }

    #[test]
    fn test_chromosome_gene_in_bounds() {
        let chrom = Chromosome::from_genes(vec![1.0, 2.0, 3.0]);
        assert_eq!(chrom.gene(1), Some(2.0));
    }

    #[test]
    fn test_chromosome_gene_out_of_bounds() {
        let chrom = Chromosome::from_genes(vec![1.0, 2.0]);
        assert_eq!(chrom.gene(5), None);
    }

    #[test]
    fn test_chromosome_set_gene() {
        let mut chrom = Chromosome::from_genes(vec![0.0, 0.0, 0.0]);
        chrom.set_gene(1, 42.0);
        assert_eq!(chrom.gene(1), Some(42.0));
    }

    #[test]
    fn test_chromosome_mutate_high_rate() {
        let mut chrom = Chromosome::from_genes(vec![0.0, 0.0, 0.0, 0.0, 0.0]);
        // Mutation rate = 1.0 guarantees every gene changes
        chrom.mutate(1.0);
        // At least some genes should differ (almost certainly all)
        let changed = chrom.genes.iter().any(|&g| g != 0.0);
        assert!(changed);
    }

    #[test]
    fn test_ga_evaluate() {
        let fitness_fn = |chrom: &Chromosome| -> f64 {
            chrom.genes.iter().sum::<f64>()
        };

        let mut ga = GeneticOptimizer::new(10, 3, 0.0, 0.0, 10);
        ga.evaluate(&fitness_fn);

        // After evaluate, population is sorted descending by fitness
        for i in 1..ga.population.len() {
            assert!(ga.population[i - 1].fitness >= ga.population[i].fitness);
        }
    }

    #[test]
    fn test_ga_iteration_starts_zero() {
        let ga = GeneticOptimizer::new(10, 3, 0.01, 0.8, 50);
        assert_eq!(ga.iteration(), 0);
    }

    #[test]
    fn test_ga_stats() {
        let fitness_fn = |chrom: &Chromosome| -> f64 {
            chrom.genes.iter().sum::<f64>()
        };

        let mut ga = GeneticOptimizer::new(20, 4, 0.0, 0.8, 10);
        ga.evaluate(&fitness_fn);

        let s = ga.stats();
        assert_eq!(s.population_size, 20);
        assert_eq!(s.iteration, 0);
        assert!(s.best_fitness >= 0.0);
        assert!(s.average_fitness >= 0.0);
    }

    #[test]
    fn test_ga_crossover_length() {
        let c1 = Chromosome::from_genes(vec![1.0; 8]);
        let c2 = Chromosome::from_genes(vec![2.0; 8]);
        let (child1, child2) = c1.crossover(&c2);
        assert_eq!(child1.genes.len(), 8);
        assert_eq!(child2.genes.len(), 8);
    }

    #[test]
    fn test_chromosome_new_length() {
        let chrom = Chromosome::new(7);
        assert_eq!(chrom.genes.len(), 7);
        assert_eq!(chrom.fitness, 0.0);
    }

    #[test]
    fn test_chromosome_set_gene_out_of_bounds() {
        let mut chrom = Chromosome::from_genes(vec![0.0, 0.0]);
        chrom.set_gene(5, 42.0);
        assert_eq!(chrom.gene(0), Some(0.0));
    }

    #[test]
    fn test_chromosome_crossover_preserves_length() {
        let c1 = Chromosome::from_genes(vec![0.1; 10]);
        let c2 = Chromosome::from_genes(vec![0.9; 10]);
        let (child1, child2) = c1.crossover(&c2);
        assert_eq!(child1.genes.len(), 10);
        assert_eq!(child2.genes.len(), 10);
    }

    #[test]
    fn test_chromosome_crossover_combines_genes() {
        let c1 = Chromosome::from_genes(vec![0.0; 4]);
        let c2 = Chromosome::from_genes(vec![1.0; 4]);
        let (child1, child2) = c1.crossover(&c2);
        for g in &child1.genes {
            assert!(*g == 0.0 || *g == 1.0);
        }
        for g in &child2.genes {
            assert!(*g == 0.0 || *g == 1.0);
        }
    }

    #[test]
    fn test_ga_evaluate_sorts_descending() {
        let fitness_fn = |chrom: &Chromosome| -> f64 { chrom.genes.iter().sum() };
        let mut ga = GeneticOptimizer::new(10, 3, 0.0, 0.0, 10);
        ga.evaluate(&fitness_fn);
        for i in 1..ga.population.len() {
            assert!(ga.population[i - 1].fitness >= ga.population[i].fitness);
        }
    }

    #[test]
    fn test_ga_iterate_increments() {
        let fitness_fn = |chrom: &Chromosome| -> f64 {
            chrom.genes.iter().sum::<f64>() / chrom.genes.len() as f64
        };
        let mut ga = GeneticOptimizer::new(10, 3, 0.1, 0.8, 100);
        assert_eq!(ga.iteration(), 0);
        ga.iterate(&fitness_fn);
        assert_eq!(ga.iteration(), 1);
        ga.iterate(&fitness_fn);
        assert_eq!(ga.iteration(), 2);
    }

    #[test]
    fn test_ga_stats_after_evaluate() {
        let fitness_fn = |chrom: &Chromosome| -> f64 { chrom.genes.iter().sum() };
        let mut ga = GeneticOptimizer::new(20, 5, 0.0, 0.8, 10);
        ga.evaluate(&fitness_fn);
        let s = ga.stats();
        assert_eq!(s.iteration, 0);
        assert_eq!(s.population_size, 20);
        assert!(s.average_fitness >= 0.0);
    }

    #[test]
    fn test_ga_optimize_returns_genes() {
        let fitness_fn = |chrom: &Chromosome| -> f64 {
            chrom.genes.iter().sum::<f64>() / chrom.genes.len() as f64
        };
        let mut ga = GeneticOptimizer::new(20, 5, 0.1, 0.8, 30);
        let genes = ga.optimize(&fitness_fn);
        assert_eq!(genes.len(), 5);
    }

    #[test]
    fn test_ga_best_fitness() {
        let fitness_fn = |chrom: &Chromosome| -> f64 { chrom.genes.iter().sum() };
        let mut ga = GeneticOptimizer::new(10, 3, 0.0, 0.0, 10);
        let initial = ga.best_fitness();
        ga.evaluate(&fitness_fn);
        assert!(ga.best_fitness() >= initial);
    }

    #[test]
    fn test_ga_best_solution() {
        let fitness_fn = |chrom: &Chromosome| -> f64 { chrom.genes.iter().sum() };
        let mut ga = GeneticOptimizer::new(10, 3, 0.0, 0.0, 10);
        ga.evaluate(&fitness_fn);
        let best = ga.best_solution();
        assert_eq!(best.genes.len(), 3);
        assert!(best.fitness >= 0.0);
    }

    #[test]
    fn test_ga_stats_iteration() {
        let fitness_fn = |chrom: &Chromosome| -> f64 { chrom.genes.iter().sum() };
        let mut ga = GeneticOptimizer::new(10, 3, 0.0, 0.8, 100);
        ga.iterate(&fitness_fn);
        let s = ga.stats();
        assert_eq!(s.iteration, 1);
    }

    #[test]
    fn test_chromosome_mutate_zero_rate() {
        let original = vec![0.5, 0.5, 0.5];
        let mut chrom = Chromosome::from_genes(original.clone());
        chrom.mutate(0.0);
        assert_eq!(chrom.genes, original);
    }
}
