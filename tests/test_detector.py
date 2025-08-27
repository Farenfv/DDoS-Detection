"""
Unit tests for DDoS detection engine.
"""

import unittest
import time
from unittest.mock import Mock, patch
import numpy as np

from src.core.detector import DDoSDetector, TrafficFeatures, DetectionResult


class TestDDoSDetector(unittest.TestCase):
    """Test cases for DDoS detection engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = DDoSDetector()
        
    def test_extract_features_valid_packets(self):
        """Test feature extraction with valid packet data."""
        packets = [
            {'timestamp': time.time(), 'size': 64, 'src_port': 80, 'dst_port': 443},
            {'timestamp': time.time(), 'size': 128, 'src_port': 80, 'dst_port': 443},
            {'timestamp': time.time(), 'size': 256, 'src_port': 443, 'dst_port': 80}
        ]
        
        features = self.detector.extract_features('192.168.1.1', packets, time.time())
        
        self.assertIsInstance(features, TrafficFeatures)
        self.assertGreater(features.request_count, 0)
        self.assertGreater(features.request_rate, 0)
        self.assertGreater(features.avg_packet_size, 0)
        
    def test_extract_features_empty_packets(self):
        """Test feature extraction with empty packet list."""
        features = self.detector.extract_features('192.168.1.1', [], time.time())
        self.assertIsNone(features)
        
    def test_detect_anomaly_normal_traffic(self):
        """Test anomaly detection with normal traffic patterns."""
        features = TrafficFeatures(
            request_rate=10.0,
            request_count=100,
            avg_packet_size=64.0,
            unique_ports=2,
            time_variance=0.1,
            burst_score=0.2
        )
        
        result = self.detector.detect_anomaly('192.168.1.1', features)
        
        self.assertIsInstance(result, DetectionResult)
        self.assertIn(result.threat_level, ['low', 'medium', 'high', 'critical'])
        
    def test_baseline_update(self):
        """Test baseline statistics update."""
        features = TrafficFeatures(
            request_rate=5.0,
            request_count=50,
            avg_packet_size=64.0,
            unique_ports=2,
            time_variance=0.1,
            burst_score=0.1
        )
        
        # Update baseline multiple times
        for _ in range(15):
            self.detector.update_baseline('192.168.1.1', features)
            
        # Check if baseline was created
        self.assertIn('192.168.1.1', self.detector.baseline_stats)
        baseline = self.detector.baseline_stats['192.168.1.1']
        self.assertIn('avg_rate', baseline)
        self.assertIn('std_rate', baseline)


if __name__ == '__main__':
    unittest.main()
