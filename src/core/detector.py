"""
DDoS Detection Engine

Core detection logic using machine learning and statistical analysis
to identify potential DDoS attacks in real-time network traffic.
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict, deque
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import config


@dataclass
class TrafficFeatures:
    """Traffic features for ML analysis."""
    request_rate: float
    request_count: int
    avg_packet_size: float
    unique_ports: int
    time_variance: float
    burst_score: float


@dataclass
class DetectionResult:
    """Result of DDoS detection analysis."""
    is_anomaly: bool
    confidence: float
    threat_level: str  # 'low', 'medium', 'high', 'critical'
    features: TrafficFeatures
    timestamp: float


class DDoSDetector:
    """
    Advanced DDoS detection engine using machine learning.
    
    Combines statistical analysis with isolation forest algorithm
    to detect anomalous traffic patterns indicative of DDoS attacks.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.model = IsolationForest(
            contamination=config.ANOMALY_THRESHOLD,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.training_data = deque(maxlen=1000)
        self.baseline_stats = {}
        self._lock = threading.Lock()
        
        # Traffic history for baseline calculation
        self.traffic_history = defaultdict(lambda: deque(maxlen=100))
        
    def extract_features(self, ip: str, packets: List[Dict], current_time: float) -> Optional[TrafficFeatures]:
        """
        Extract traffic features for ML analysis.
        
        Args:
            ip: Source IP address
            packets: List of packet data
            current_time: Current timestamp
            
        Returns:
            TrafficFeatures object or None if insufficient data
        """
        if not packets:
            return None
            
        try:
            # Filter recent packets
            recent_packets = [
                pkt for pkt in packets 
                if current_time - pkt['timestamp'] <= config.TIME_WINDOW
            ]
            
            if not recent_packets:
                return None
                
            # Calculate basic metrics
            request_count = len(recent_packets)
            request_rate = request_count / config.TIME_WINDOW
            
            # Packet size analysis
            sizes = [pkt.get('size', 0) for pkt in recent_packets]
            avg_packet_size = np.mean(sizes) if sizes else 0
            
            # Port diversity
            ports = set()
            for pkt in recent_packets:
                ports.add(pkt.get('src_port', 0))
                ports.add(pkt.get('dst_port', 0))
            unique_ports = len(ports)
            
            # Temporal analysis
            timestamps = [pkt['timestamp'] for pkt in recent_packets]
            time_variance = np.var(timestamps) if len(timestamps) > 1 else 0
            
            # Burst detection
            burst_score = self._calculate_burst_score(timestamps)
            
            return TrafficFeatures(
                request_rate=request_rate,
                request_count=request_count,
                avg_packet_size=avg_packet_size,
                unique_ports=unique_ports,
                time_variance=time_variance,
                burst_score=burst_score
            )
            
        except Exception as e:
            self.logger.error(f"Error extracting features for {ip}: {e}")
            return None
    
    def _calculate_burst_score(self, timestamps: List[float]) -> float:
        """Calculate burst score based on temporal clustering."""
        if len(timestamps) < 3:
            return 0.0
            
        # Calculate inter-arrival times
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if not intervals:
            return 0.0
            
        # Burst score based on variance of intervals
        mean_interval = np.mean(intervals)
        if mean_interval == 0:
            return 1.0
            
        variance_ratio = np.var(intervals) / (mean_interval ** 2)
        return min(variance_ratio, 1.0)
    
    def update_baseline(self, ip: str, features: TrafficFeatures):
        """Update baseline statistics for an IP."""
        with self._lock:
            self.traffic_history[ip].append({
                'timestamp': time.time(),
                'request_rate': features.request_rate,
                'packet_size': features.avg_packet_size,
                'burst_score': features.burst_score
            })
            
            # Update baseline stats
            history = list(self.traffic_history[ip])
            if len(history) >= 10:  # Minimum samples for baseline
                rates = [h['request_rate'] for h in history]
                self.baseline_stats[ip] = {
                    'avg_rate': np.mean(rates),
                    'std_rate': np.std(rates),
                    'max_rate': np.max(rates),
                    'updated': time.time()
                }
    
    def detect_anomaly(self, ip: str, features: TrafficFeatures) -> DetectionResult:
        """
        Detect if traffic features indicate a DDoS attack.
        
        Args:
            ip: Source IP address
            features: Extracted traffic features
            
        Returns:
            DetectionResult with analysis results
        """
        try:
            # Update baseline first
            self.update_baseline(ip, features)
            
            # Prepare feature vector for ML model
            feature_vector = np.array([[
                features.request_rate,
                features.request_count,
                features.avg_packet_size,
                features.unique_ports,
                features.time_variance,
                features.burst_score
            ]])
            
            # Statistical analysis
            is_statistical_anomaly, stat_confidence = self._statistical_analysis(ip, features)
            
            # ML analysis (if model is trained)
            is_ml_anomaly, ml_confidence = self._ml_analysis(feature_vector)
            
            # Combine results
            is_anomaly = is_statistical_anomaly or is_ml_anomaly
            confidence = max(stat_confidence, ml_confidence)
            
            # Determine threat level
            threat_level = self._calculate_threat_level(confidence, features)
            
            return DetectionResult(
                is_anomaly=is_anomaly,
                confidence=confidence,
                threat_level=threat_level,
                features=features,
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection for {ip}: {e}")
            return DetectionResult(
                is_anomaly=False,
                confidence=0.0,
                threat_level='low',
                features=features,
                timestamp=time.time()
            )
    
    def _statistical_analysis(self, ip: str, features: TrafficFeatures) -> Tuple[bool, float]:
        """Perform statistical anomaly detection."""
        baseline = self.baseline_stats.get(ip)
        if not baseline:
            return False, 0.0
            
        # Rate-based detection
        rate_threshold = baseline['avg_rate'] + (config.REQUEST_THRESHOLD_MULTIPLIER * baseline['std_rate'])
        rate_anomaly = features.request_rate > rate_threshold
        
        # Calculate confidence based on deviation
        if baseline['std_rate'] > 0:
            deviation = (features.request_rate - baseline['avg_rate']) / baseline['std_rate']
            confidence = min(abs(deviation) / config.REQUEST_THRESHOLD_MULTIPLIER, 1.0)
        else:
            confidence = 1.0 if rate_anomaly else 0.0
            
        # Burst detection
        burst_anomaly = features.burst_score > 0.7
        
        is_anomaly = rate_anomaly or burst_anomaly
        final_confidence = confidence if rate_anomaly else (features.burst_score if burst_anomaly else 0.0)
        
        return is_anomaly, final_confidence
    
    def _ml_analysis(self, feature_vector: np.ndarray) -> Tuple[bool, float]:
        """Perform ML-based anomaly detection."""
        if not self.is_trained:
            # Add to training data
            self.training_data.append(feature_vector[0])
            
            # Train model when we have enough data
            if len(self.training_data) >= 50:
                self._train_model()
            
            return False, 0.0
        
        try:
            # Scale features
            scaled_features = self.scaler.transform(feature_vector)
            
            # Predict anomaly
            prediction = self.model.predict(scaled_features)[0]
            anomaly_score = self.model.decision_function(scaled_features)[0]
            
            is_anomaly = prediction == -1
            confidence = abs(anomaly_score) if is_anomaly else 0.0
            
            return is_anomaly, confidence
            
        except Exception as e:
            self.logger.error(f"Error in ML analysis: {e}")
            return False, 0.0
    
    def _train_model(self):
        """Train the ML model with collected data."""
        try:
            if len(self.training_data) < 20:
                return
                
            training_array = np.array(list(self.training_data))
            
            # Fit scaler
            self.scaler.fit(training_array)
            
            # Scale data
            scaled_data = self.scaler.transform(training_array)
            
            # Train model
            self.model.fit(scaled_data)
            self.is_trained = True
            
            self.logger.info(f"ML model trained with {len(self.training_data)} samples")
            
        except Exception as e:
            self.logger.error(f"Error training ML model: {e}")
    
    def _calculate_threat_level(self, confidence: float, features: TrafficFeatures) -> str:
        """Calculate threat level based on confidence and features."""
        if confidence < 0.3:
            return 'low'
        elif confidence < 0.6:
            return 'medium'
        elif confidence < 0.8:
            return 'high'
        else:
            return 'critical'
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics."""
        with self._lock:
            return {
                'is_trained': self.is_trained,
                'training_samples': len(self.training_data),
                'monitored_ips': len(self.baseline_stats),
                'baseline_stats': dict(self.baseline_stats)
            }
