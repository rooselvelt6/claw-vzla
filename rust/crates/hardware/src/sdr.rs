use rand::RngExt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequencyRange {
    pub start_mhz: f64,
    pub end_mhz: f64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub frequency_mhz: f64,
    pub amplitude: f64,
    pub bandwidth: f64,
    pub modulation: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub range: FrequencyRange,
    pub signals: Vec<Signal>,
    pub duration_seconds: f64,
    pub peak_frequencies: Vec<f64>,
    pub total_bands: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdrDevice {
    pub name: String,
    pub frequency_range_mhz: (f64, f64),
    pub sample_rate: u32,
    pub available: bool,
}

pub struct SdrScanner;

impl Default for SdrScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SdrScanner {
    pub fn new() -> Self {
        SdrScanner
    }

    pub fn list_devices() -> Vec<SdrDevice> {
        vec![
            SdrDevice {
                name: "RTL-SDR (RTL2832U)".to_string(),
                frequency_range_mhz: (24.0, 1766.0),
                sample_rate: 2_400_000,
                available: false,
            },
            SdrDevice {
                name: "HackRF One".to_string(),
                frequency_range_mhz: (1.0, 6000.0),
                sample_rate: 20_000_000,
                available: false,
            },
            SdrDevice {
                name: "Airspy Mini".to_string(),
                frequency_range_mhz: (24.0, 1800.0),
                sample_rate: 6_000_000,
                available: false,
            },
            SdrDevice {
                name: "LimeSDR Mini".to_string(),
                frequency_range_mhz: (10.0, 3500.0),
                sample_rate: 30_720_000,
                available: false,
            },
        ]
    }

    pub fn get_common_bands() -> Vec<FrequencyRange> {
        vec![
            FrequencyRange { start_mhz: 88.0, end_mhz: 108.0, label: "FM Broadcast".to_string() },
            FrequencyRange { start_mhz: 108.0, end_mhz: 137.0, label: "Airband (VHF)".to_string() },
            FrequencyRange { start_mhz: 137.0, end_mhz: 174.0, label: "VHF".to_string() },
            FrequencyRange { start_mhz: 174.0, end_mhz: 216.0, label: "VHF TV".to_string() },
            FrequencyRange { start_mhz: 216.0, end_mhz: 470.0, label: "UHF".to_string() },
            FrequencyRange { start_mhz: 470.0, end_mhz: 698.0, label: "UHF TV".to_string() },
            FrequencyRange { start_mhz: 698.0, end_mhz: 960.0, label: "Cellular/LTE".to_string() },
            FrequencyRange { start_mhz: 960.0, end_mhz: 1215.0, label: "Aero navigation".to_string() },
            FrequencyRange { start_mhz: 1215.0, end_mhz: 1400.0, label: "GPS L1".to_string() },
            FrequencyRange { start_mhz: 2400.0, end_mhz: 2500.0, label: "ISM 2.4GHz".to_string() },
            FrequencyRange { start_mhz: 5150.0, end_mhz: 5850.0, label: "ISM 5GHz".to_string() },
        ]
    }

    pub fn scan_frequency_range(start_mhz: f64, end_mhz: f64, label: &str) -> ScanResult {
        let range = FrequencyRange {
            start_mhz,
            end_mhz,
            label: label.to_string(),
        };

        let mut signals = Vec::new();
        let step = 0.5;
        let mut freq = start_mhz;
        let mut rng = rand::rng();

        while freq <= end_mhz {
            let amplitude: f64 = rng.random_range(0.0..1.0);
            if amplitude > 0.85 {
                let bw = rng.random_range(0.05..0.5);
                signals.push(Signal {
                    frequency_mhz: freq,
                    amplitude,
                    bandwidth: bw,
                    modulation: vec![
                        "FM".to_string(),
                        "AM".to_string(),
                        "SSB".to_string(),
                        "Digital".to_string(),
                    ].into_iter().nth(rng.random_range(0..4)).unwrap_or_default(),
                    confidence: rng.random_range(0.3..0.95),
                });
            }
            freq += step;
        }

        let peak_freqs: Vec<f64> = signals.iter().map(|s| s.frequency_mhz).collect();

        ScanResult {
            range,
            signals,
            duration_seconds: ((end_mhz - start_mhz) / 100.0) * 2.0,
            peak_frequencies: peak_freqs,
            total_bands: (end_mhz - start_mhz).ceil() as usize,
        }
    }

    pub fn scan_specific_frequencies(frequencies: &[f64]) -> Vec<Signal> {
        let mut rng = rand::rng();
        frequencies.iter().map(|&freq| {
            let amplitude: f64 = rng.random_range(0.0..1.0);
            Signal {
                frequency_mhz: freq,
                amplitude,
                bandwidth: rng.random_range(0.01..0.2),
                modulation: vec![
                    "FM".to_string(),
                    "AM".to_string(),
                    "Digital".to_string(),
                ].into_iter().nth(rng.random_range(0..3)).unwrap_or_default(),
                confidence: rng.random_range(0.3..0.9),
            }
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_devices() {
        let devices = SdrScanner::list_devices();
        assert!(devices.iter().any(|d| d.name.contains("RTL-SDR")));
    }

    #[test]
    fn test_get_common_bands() {
        let bands = SdrScanner::get_common_bands();
        assert!(!bands.is_empty());
        assert!(bands.iter().any(|b| b.label.contains("FM")));
    }

    #[test]
    fn test_scan_frequency_range() {
        let result = SdrScanner::scan_frequency_range(88.0, 108.0, "FM");
        assert_eq!(result.range.label, "FM");
        assert!(result.duration_seconds > 0.0);
    }

    #[test]
    fn test_scan_specific_frequencies() {
        let signals = SdrScanner::scan_specific_frequencies(&[100.0, 200.0, 300.0]);
        assert_eq!(signals.len(), 3);
    }

    #[test]
    fn test_sdr_device_serde() {
        let device = SdrDevice {
            name: "RTL-SDR".to_string(),
            frequency_range_mhz: (24.0, 1766.0),
            sample_rate: 2_400_000,
            available: false,
        };
        let json = serde_json::to_string_pretty(&device).unwrap();
        assert!(json.contains("RTL-SDR"));
    }

    #[test]
    fn test_scan_result_serde() {
        let result = ScanResult {
            range: FrequencyRange { start_mhz: 88.0, end_mhz: 108.0, label: "FM".to_string() },
            signals: vec![],
            duration_seconds: 1.0,
            peak_frequencies: vec![100.0],
            total_bands: 20,
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("100.0"));
    }
}
