use kraken_errors::PasswordError;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

#[derive(Debug, Clone)]
pub struct WordlistGenerator {
    pub min_len: usize,
    pub max_len: usize,
    pub charset: String,
}

impl Default for WordlistGenerator {
    fn default() -> Self {
        WordlistGenerator {
            min_len: 1,
            max_len: 4,
            charset: "abcdefghijklmnopqrstuvwxyz".to_string(),
        }
    }
}

impl WordlistGenerator {
    pub fn new(min_len: usize, max_len: usize, charset: &str) -> Self {
        WordlistGenerator {
            min_len,
            max_len,
            charset: charset.to_string(),
        }
    }

    pub fn generate(&self) -> Vec<String> {
        let mut words = Vec::new();
        let chars: Vec<char> = self.charset.chars().collect();
        for len in self.min_len..=self.max_len {
            Self::generate_recursive(&chars, len, String::new(), &mut words);
        }
        words
    }

    fn generate_recursive(chars: &[char], remaining: usize, current: String, result: &mut Vec<String>) {
        if remaining == 0 {
            result.push(current);
            return;
        }
        for &c in chars {
            let mut next = current.clone();
            next.push(c);
            Self::generate_recursive(chars, remaining - 1, next, result);
        }
    }

    pub fn generate_padded(min_len: usize, max_len: usize, custom: &str) -> Vec<String> {
        let gen = WordlistGenerator::new(min_len, max_len, custom);
        gen.generate()
    }

    pub fn crunch(min_len: usize, max_len: usize, charset: &str) -> Vec<String> {
        let gen = WordlistGenerator::new(min_len, max_len, charset);
        gen.generate()
    }

    pub fn crunch_with_pattern(pattern: &str, charset: &str) -> Vec<String> {
        let chars: Vec<char> = charset.chars().collect();
        let mut result = Vec::new();
        let fixed_len = pattern.chars().count();
        Self::generate_recursive(&chars, fixed_len, String::new(), &mut result);
        result
    }

    pub fn to_file(&self, path: &str) -> Result<usize, PasswordError> {
        let words = self.generate();
        let mut file = File::create(path).map_err(PasswordError::Io)?;
        for word in &words {
            writeln!(file, "{}", word).map_err(PasswordError::Io)?;
        }
        Ok(words.len())
    }
}

pub fn cewl(url: &str, min_word_len: usize, max_words: usize) -> Result<Vec<String>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let response = client.get(url)
        .send()
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let html = response.text().map_err(|e| format!("HTTP read failed: {}", e))?;

    let document = scraper::Html::parse_document(&html);

    let text_selector = scraper::Selector::parse("p, span, div, a, li, td, th, h1, h2, h3, h4, h5, h6, strong, em, b, i, title, meta[name=description], meta[name=keywords]")
        .map_err(|_| "Invalid selector".to_string())?;

    let mut words = Vec::new();
    let mut seen = HashSet::new();

    for element in document.select(&text_selector) {
        if words.len() >= max_words {
            break;
        }
        let text = element.text().collect::<String>();
        for token in text.split(|c: char| !c.is_alphanumeric() && c != '\'') {
            let token = token.trim().to_lowercase();
            if token.len() >= min_word_len && !token.is_empty() && !seen.contains(&token) {
                seen.insert(token.clone());
                words.push(token);
                if words.len() >= max_words {
                    break;
                }
            }
        }
    }

    let meta_selector = scraper::Selector::parse("meta[name=keywords]").unwrap();
    let meta_content = document.select(&meta_selector);
    for element in meta_content {
        if let Some(content) = element.value().attr("content") {
            for keyword in content.split(',') {
                let keyword = keyword.trim().to_lowercase();
                if keyword.len() >= min_word_len && !seen.contains(&keyword) {
                    seen.insert(keyword.clone());
                    words.push(keyword);
                }
            }
        }
    }

    Ok(words)
}

#[derive(Debug, Clone, Default)]
pub struct PasswordStats {
    pub total: usize,
    pub unique: usize,
    pub min_length: usize,
    pub max_length: usize,
    pub avg_length: f64,
    pub char_class_counts: HashMap<String, usize>,
    pub top_passwords: Vec<(String, usize)>,
    pub base10_count: usize,
    pub base16_count: usize,
    pub base36_count: usize,
    pub base64_count: usize,
    pub digit_only: usize,
    pub alpha_only: usize,
    pub alphanumeric: usize,
    pub special_char: usize,
    pub uppercase_only: usize,
    pub lowercase_only: usize,
    pub repeated_chars: usize,
    pub sequential_chars: usize,
}

pub fn analyze_passwords(passwords: &[String]) -> PasswordStats {
    let mut stats = PasswordStats::default();
    let total = passwords.len();
    stats.total = total;

    let unique: HashSet<&str> = passwords.iter().map(|s| s.as_str()).collect();
    stats.unique = unique.len();

    if total == 0 {
        return stats;
    }

    let lengths: Vec<usize> = passwords.iter().map(|p| p.len()).collect();
    stats.min_length = *lengths.iter().min().unwrap_or(&0);
    stats.max_length = *lengths.iter().max().unwrap_or(&0);
    stats.avg_length = lengths.iter().sum::<usize>() as f64 / total as f64;

    let mut freq: HashMap<String, usize> = HashMap::new();
    for pw in passwords {
        *freq.entry(pw.clone()).or_insert(0) += 1;
    }
    let mut freq_vec: Vec<(String, usize)> = freq.into_iter().collect();
    freq_vec.sort_by_key(|b| std::cmp::Reverse(b.1));
    stats.top_passwords = freq_vec.into_iter().take(20).collect();

    for pw in passwords {
        let has_digit = pw.chars().any(|c| c.is_ascii_digit());
        let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
        let _has_lower = pw.chars().any(|c| c.is_ascii_lowercase());
        let has_special = pw.chars().any(|c| !c.is_alphanumeric());
        let all_digits = pw.chars().all(|c| c.is_ascii_digit());
        let all_alpha = pw.chars().all(|c| c.is_ascii_alphabetic());
        let all_upper = pw.chars().all(|c| c.is_ascii_uppercase());
        let all_lower = pw.chars().all(|c| c.is_ascii_lowercase());

        if has_digit { stats.base10_count += 1; }
        if has_upper { stats.base16_count += 1; }
        if has_upper || has_digit { stats.base36_count += 1; }
        if has_special { stats.base64_count += 1; }
        if all_digits { stats.digit_only += 1; }
        if all_alpha { stats.alpha_only += 1; }
        if all_digits || all_alpha { stats.alphanumeric += 1; }
        if has_special { stats.special_char += 1; }
        if all_upper { stats.uppercase_only += 1; }
        if all_lower { stats.lowercase_only += 1; }

        let chars: Vec<char> = pw.chars().collect();
        for i in 0..chars.len().saturating_sub(2) {
            if chars[i] == chars[i + 1] && chars[i + 1] == chars[i + 2] {
                stats.repeated_chars += 1;
                break;
            }
        }
        for i in 0..chars.len().saturating_sub(2) {
            if (chars[i] as u8 + 1) == chars[i + 1] as u8 && (chars[i + 1] as u8 + 1) == chars[i + 2] as u8 {
                stats.sequential_chars += 1;
                break;
            }
        }
    }

    stats
}

pub fn analyze_passwords_from_file(path: &str) -> Result<PasswordStats, String> {
    let file = File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;
    let reader = BufReader::new(file);
    let passwords: Vec<String> = reader.lines()
        .map_while(Result::ok)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    Ok(analyze_passwords(&passwords))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_generator_basic() {
        let gen = WordlistGenerator::new(1, 2, "ab");
        let words = gen.generate();
        assert_eq!(words.len(), 6);
        assert!(words.contains(&"a".to_string()));
        assert!(words.contains(&"b".to_string()));
        assert!(words.contains(&"aa".to_string()));
        assert!(words.contains(&"ab".to_string()));
        assert!(words.contains(&"ba".to_string()));
        assert!(words.contains(&"bb".to_string()));
    }

    #[test]
    fn test_crunch_style() {
        let words = WordlistGenerator::crunch(1, 3, "01");
        assert_eq!(words.len(), 14);
        assert!(words.contains(&"0".to_string()));
        assert!(words.contains(&"1".to_string()));
        assert!(words.contains(&"000".to_string()));
        assert!(words.contains(&"111".to_string()));
    }

    #[test]
    fn test_analyze_passwords_empty() {
        let stats = analyze_passwords(&[]);
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn test_analyze_passwords_basic() {
        let pws = vec!["hello".to_string(), "world".to_string(), "hello".to_string(), "12345".to_string()];
        let stats = analyze_passwords(&pws);
        assert_eq!(stats.total, 4);
        assert_eq!(stats.unique, 3);
        assert_eq!(stats.min_length, 5);
        assert_eq!(stats.max_length, 5);
        assert!(stats.avg_length > 0.0);
        assert_eq!(stats.top_passwords[0].0, "hello");
        assert_eq!(stats.top_passwords[0].1, 2);
    }

    #[test]
    fn test_analyze_passwords_digit_only() {
        let pws = vec!["12345".to_string(), "abc".to_string()];
        let stats = analyze_passwords(&pws);
        assert_eq!(stats.digit_only, 1);
        assert_eq!(stats.alpha_only, 1);
    }

    #[test]
    fn test_cewl_requires_real_url() {
        let result = cewl("http://nonexistent.invalid", 3, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_password_stats_repeated() {
        let pws = vec!["aaabbb".to_string(), "abcdef".to_string()];
        let stats = analyze_passwords(&pws);
        assert_eq!(stats.repeated_chars, 1);
    }

    #[test]
    fn test_wordlist_to_file() {
        let gen = WordlistGenerator::new(1, 2, "ab");
        let path = "/tmp/test_wordlist.txt";
        let count = gen.to_file(path).unwrap();
        assert_eq!(count, 6);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_generate_padded() {
        let words = WordlistGenerator::generate_padded(2, 2, "xyz");
        assert_eq!(words.len(), 9);
        assert!(words.contains(&"xx".to_string()));
        assert!(words.contains(&"zz".to_string()));
    }
}
