import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import pickle
import json
from pathlib import Path

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import joblib

import structlog

logger = structlog.get_logger()


@dataclass
class AnomalyScore:
    timestamp: datetime
    score: float
    is_anomaly: bool
    confidence: float
    feature_contributions: Dict[str, float]
    anomaly_type: str
    explanation: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'score': self.score,
            'is_anomaly': self.is_anomaly,
            'confidence': self.confidence,
            'feature_contributions': self.feature_contributions,
            'anomaly_type': self.anomaly_type,
            'explanation': self.explanation
        }


class AnomalyDetector:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = Path(model_path) if model_path else Path("models/anomaly_detector.pkl")
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.isolation_forest = None
        self.random_forest = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        self.feature_names = [
            'packet_rate', 'byte_rate', 'unique_dst_ports', 'unique_src_ips',
            'avg_packet_size', 'tcp_ratio', 'udp_ratio', 'icmp_ratio',
            'syn_flag_ratio', 'ack_flag_ratio', 'port_scan_score',
            'dns_query_length', 'http_request_rate', 'ssl_ratio',
            'outbound_ratio', 'night_time_activity', 'weekend_activity',
            'burst_score', 'entropy_score', 'protocol_diversity'
        ]
        
        self.baseline_stats = {
            'packet_rate': {'mean': 100, 'std': 50},
            'byte_rate': {'mean': 10000, 'std': 5000},
            'unique_dst_ports': {'mean': 10, 'std': 5},
            'avg_packet_size': {'mean': 500, 'std': 200}
        }
        
        self.anomaly_threshold = -0.1
        self.training_data = []
        self.is_trained = False
        
        if model_path and Path(model_path).exists():
            self.load_model()
        else:
            self._initialize_models()
    
    def _initialize_models(self):
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            bootstrap=False
        )
        
        self.random_forest = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        logger.info("ML models initialized")
    
    def extract_features(self, traffic_data: List[Dict[str, Any]], 
                        window_seconds: int = 60) -> np.ndarray:
        
        if not traffic_data:
            return np.zeros((1, len(self.feature_names)))
        
        features = {}
        
        current_time = datetime.now()
        window_start = current_time - timedelta(seconds=window_seconds)
        
        window_data = [
            d for d in traffic_data 
            if datetime.fromtimestamp(d.get('timestamp', 0)) > window_start
        ]
        
        if not window_data:
            return np.zeros((1, len(self.feature_names)))
        
        features['packet_rate'] = len(window_data) / window_seconds
        features['byte_rate'] = sum(d.get('size', 0) for d in window_data) / window_seconds
        
        unique_dst_ports = set(d.get('dst_port') for d in window_data if d.get('dst_port'))
        features['unique_dst_ports'] = len(unique_dst_ports)
        
        unique_src_ips = set(d.get('src_ip') for d in window_data if d.get('src_ip'))
        features['unique_src_ips'] = len(unique_src_ips)
        
        packet_sizes = [d.get('size', 0) for d in window_data]
        features['avg_packet_size'] = np.mean(packet_sizes) if packet_sizes else 0
        
        protocols = [d.get('protocol', '') for d in window_data]
        total_packets = len(protocols)
        features['tcp_ratio'] = protocols.count('TCP') / total_packets if total_packets else 0
        features['udp_ratio'] = protocols.count('UDP') / total_packets if total_packets else 0
        features['icmp_ratio'] = protocols.count('ICMP') / total_packets if total_packets else 0
        
        tcp_packets = [d for d in window_data if d.get('protocol') == 'TCP']
        syn_count = sum(1 for d in tcp_packets if d.get('flags', {}).get('syn'))
        ack_count = sum(1 for d in tcp_packets if d.get('flags', {}).get('ack'))
        
        features['syn_flag_ratio'] = syn_count / len(tcp_packets) if tcp_packets else 0
        features['ack_flag_ratio'] = ack_count / len(tcp_packets) if tcp_packets else 0
        
        features['port_scan_score'] = self._calculate_port_scan_score(window_data)
        
        dns_queries = [d.get('dns_query', '') for d in window_data if d.get('dns_query')]
        features['dns_query_length'] = np.mean([len(q) for q in dns_queries]) if dns_queries else 0
        
        http_packets = [d for d in window_data if d.get('protocol') == 'HTTP']
        features['http_request_rate'] = len(http_packets) / window_seconds
        
        ssl_packets = [d for d in window_data if d.get('protocol') in ['HTTPS', 'TLS/SSL']]
        features['ssl_ratio'] = len(ssl_packets) / total_packets if total_packets else 0
        
        outbound = sum(1 for d in window_data if self._is_outbound(d.get('dst_ip', '')))
        features['outbound_ratio'] = outbound / total_packets if total_packets else 0
        
        hour = current_time.hour
        features['night_time_activity'] = 1 if 0 <= hour < 6 else 0
        features['weekend_activity'] = 1 if current_time.weekday() >= 5 else 0
        
        features['burst_score'] = self._calculate_burst_score(window_data)
        features['entropy_score'] = self._calculate_entropy_score(window_data)
        features['protocol_diversity'] = len(set(protocols)) / 10
        
        feature_vector = np.array([features.get(name, 0) for name in self.feature_names])
        return feature_vector.reshape(1, -1)
    
    def _calculate_port_scan_score(self, traffic_data: List[Dict[str, Any]]) -> float:
        src_to_ports = {}
        for packet in traffic_data:
            src_ip = packet.get('src_ip')
            dst_port = packet.get('dst_port')
            if src_ip and dst_port:
                if src_ip not in src_to_ports:
                    src_to_ports[src_ip] = set()
                src_to_ports[src_ip].add(dst_port)
        
        if not src_to_ports:
            return 0
        
        max_ports = max(len(ports) for ports in src_to_ports.values())
        return min(max_ports / 100, 1.0)
    
    def _is_outbound(self, ip: str) -> bool:
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback)
        except:
            return False
    
    def _calculate_burst_score(self, traffic_data: List[Dict[str, Any]]) -> float:
        if len(traffic_data) < 10:
            return 0
        
        timestamps = sorted([d.get('timestamp', 0) for d in traffic_data])
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if not intervals:
            return 0
        
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        if mean_interval == 0:
            return 1.0
        
        burst_score = std_interval / mean_interval if mean_interval > 0 else 0
        return min(burst_score, 1.0)
    
    def _calculate_entropy_score(self, traffic_data: List[Dict[str, Any]]) -> float:
        import math
        
        dst_ips = [d.get('dst_ip', '') for d in traffic_data]
        if not dst_ips:
            return 0
        
        ip_counts = {}
        for ip in dst_ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        total = len(dst_ips)
        entropy = 0
        for count in ip_counts.values():
            if count > 0:
                probability = count / total
                entropy -= probability * math.log2(probability)
        
        max_entropy = math.log2(len(ip_counts)) if len(ip_counts) > 1 else 1
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
        
        return normalized_entropy
    
    def train(self, training_data: List[Dict[str, Any]], labels: Optional[List[int]] = None):
        logger.info("Training anomaly detection models...")
        
        if not training_data:
            logger.error("No training data provided")
            return
        
        X = []
        for i in range(0, len(training_data), 100):
            batch = training_data[i:i+100]
            features = self.extract_features(batch)
            X.append(features[0])
        
        X = np.array(X)
        
        X_scaled = self.scaler.fit_transform(X)
        
        self.isolation_forest.fit(X_scaled)
        
        if labels and len(labels) == len(X):
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, labels, test_size=0.2, random_state=42
            )
            
            self.random_forest.fit(X_train, y_train)
            
            y_pred = self.random_forest.predict(X_test)
            report = classification_report(y_test, y_pred)
            logger.info(f"Random Forest Classification Report:\n{report}")
        
        self.is_trained = True
        logger.info("Model training completed")
        
        self.save_model()
    
    def detect(self, traffic_data: List[Dict[str, Any]]) -> AnomalyScore:
        if not self.is_trained:
            logger.warning("Model not trained, using rule-based detection")
            return self._rule_based_detection(traffic_data)
        
        features = self.extract_features(traffic_data)
        features_scaled = self.scaler.transform(features)
        
        isolation_score = self.isolation_forest.decision_function(features_scaled)[0]
        
        is_anomaly = isolation_score < self.anomaly_threshold
        
        confidence = abs(isolation_score) / 0.5
        confidence = min(confidence, 1.0)
        
        if hasattr(self, 'random_forest') and self.random_forest:
            try:
                rf_prob = self.random_forest.predict_proba(features_scaled)[0]
                if len(rf_prob) > 1:
                    confidence = (confidence + rf_prob[1]) / 2
            except:
                pass
        
        feature_contributions = self._calculate_feature_importance(features[0])
        
        anomaly_type = self._classify_anomaly_type(features[0], feature_contributions)
        
        explanation = self._generate_explanation(
            is_anomaly, anomaly_type, feature_contributions, features[0]
        )
        
        return AnomalyScore(
            timestamp=datetime.now(),
            score=isolation_score,
            is_anomaly=is_anomaly,
            confidence=confidence,
            feature_contributions=feature_contributions,
            anomaly_type=anomaly_type,
            explanation=explanation
        )
    
    def _rule_based_detection(self, traffic_data: List[Dict[str, Any]]) -> AnomalyScore:
        features = self.extract_features(traffic_data)
        feature_vector = features[0]
        
        anomaly_indicators = []
        
        if feature_vector[0] > 1000:
            anomaly_indicators.append("High packet rate")
        
        if feature_vector[2] > 50:
            anomaly_indicators.append("Scanning multiple ports")
        
        if feature_vector[10] > 0.5:
            anomaly_indicators.append("Port scan pattern detected")
        
        if feature_vector[11] > 100:
            anomaly_indicators.append("Suspicious DNS queries")
        
        if feature_vector[17] > 0.8:
            anomaly_indicators.append("Traffic burst detected")
        
        is_anomaly = len(anomaly_indicators) > 0
        confidence = min(len(anomaly_indicators) * 0.25, 1.0)
        
        return AnomalyScore(
            timestamp=datetime.now(),
            score=-0.5 if is_anomaly else 0.5,
            is_anomaly=is_anomaly,
            confidence=confidence,
            feature_contributions={},
            anomaly_type="Rule-based detection",
            explanation="; ".join(anomaly_indicators) if anomaly_indicators else "Normal traffic"
        )
    
    def _calculate_feature_importance(self, features: np.ndarray) -> Dict[str, float]:
        importances = {}
        
        for i, (feature_name, feature_value) in enumerate(zip(self.feature_names, features)):
            if feature_name in self.baseline_stats:
                baseline = self.baseline_stats[feature_name]
                z_score = abs((feature_value - baseline['mean']) / baseline['std'])
                importances[feature_name] = z_score
            else:
                importances[feature_name] = abs(feature_value)
        
        total = sum(importances.values())
        if total > 0:
            importances = {k: v/total for k, v in importances.items()}
        
        return dict(sorted(importances.items(), key=lambda x: x[1], reverse=True)[:5])
    
    def _classify_anomaly_type(self, features: np.ndarray, 
                              contributions: Dict[str, float]) -> str:
        
        top_feature = max(contributions.items(), key=lambda x: x[1])[0] if contributions else None
        
        if top_feature == 'port_scan_score' or features[10] > 0.5:
            return "Port Scanning"
        elif top_feature == 'packet_rate' and features[0] > 1000:
            return "DDoS Attack"
        elif top_feature == 'dns_query_length' and features[11] > 50:
            return "DNS Tunneling"
        elif top_feature == 'night_time_activity' and features[15] == 1:
            return "Suspicious Night Activity"
        elif top_feature == 'outbound_ratio' and features[14] > 0.8:
            return "Data Exfiltration"
        elif top_feature == 'burst_score' and features[17] > 0.7:
            return "Traffic Burst"
        elif top_feature == 'entropy_score' and features[18] > 0.9:
            return "Distributed Attack"
        else:
            return "General Anomaly"
    
    def _generate_explanation(self, is_anomaly: bool, anomaly_type: str,
                             contributions: Dict[str, float],
                             features: np.ndarray) -> str:
        
        if not is_anomaly:
            return "Traffic patterns are within normal parameters"
        
        explanations = []
        
        for feature_name, contribution in list(contributions.items())[:3]:
            idx = self.feature_names.index(feature_name)
            value = features[idx]
            
            if feature_name == 'packet_rate':
                explanations.append(f"Packet rate: {value:.1f} packets/sec (unusual)")
            elif feature_name == 'unique_dst_ports':
                explanations.append(f"Targeting {int(value)} different ports")
            elif feature_name == 'burst_score':
                explanations.append(f"Traffic burst detected (score: {value:.2f})")
            elif feature_name == 'dns_query_length':
                explanations.append(f"Abnormal DNS query length: {value:.1f} chars")
        
        explanation = f"{anomaly_type} detected. " + "; ".join(explanations)
        return explanation
    
    def update_baseline(self, normal_traffic_data: List[Dict[str, Any]]):
        logger.info("Updating baseline statistics...")
        
        feature_arrays = []
        for i in range(0, len(normal_traffic_data), 100):
            batch = normal_traffic_data[i:i+100]
            features = self.extract_features(batch)
            feature_arrays.append(features[0])
        
        feature_arrays = np.array(feature_arrays)
        
        for i, feature_name in enumerate(self.feature_names[:4]):
            values = feature_arrays[:, i]
            self.baseline_stats[feature_name] = {
                'mean': float(np.mean(values)),
                'std': float(np.std(values))
            }
        
        logger.info("Baseline statistics updated")
    
    def predict_future_anomalies(self, historical_data: List[AnomalyScore],
                                horizon_minutes: int = 30) -> List[Dict[str, Any]]:
        
        if len(historical_data) < 10:
            return []
        
        anomaly_times = [a.timestamp for a in historical_data if a.is_anomaly]
        
        if len(anomaly_times) < 2:
            return []
        
        intervals = []
        for i in range(1, len(anomaly_times)):
            interval = (anomaly_times[i] - anomaly_times[i-1]).total_seconds() / 60
            intervals.append(interval)
        
        avg_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        predictions = []
        last_anomaly = anomaly_times[-1]
        current_time = datetime.now()
        
        for i in range(1, 4):
            predicted_time = last_anomaly + timedelta(minutes=avg_interval * i)
            if predicted_time > current_time + timedelta(minutes=horizon_minutes):
                break
            
            confidence = max(0, 1 - (std_interval / avg_interval)) if avg_interval > 0 else 0
            
            predictions.append({
                'predicted_time': predicted_time.isoformat(),
                'confidence': confidence,
                'expected_type': historical_data[-1].anomaly_type
            })
        
        return predictions
    
    def save_model(self):
        model_data = {
            'isolation_forest': self.isolation_forest,
            'random_forest': self.random_forest,
            'scaler': self.scaler,
            'baseline_stats': self.baseline_stats,
            'is_trained': self.is_trained
        }
        
        joblib.dump(model_data, self.model_path)
        logger.info(f"Model saved to {self.model_path}")
    
    def load_model(self):
        try:
            model_data = joblib.load(self.model_path)
            self.isolation_forest = model_data['isolation_forest']
            self.random_forest = model_data['random_forest']
            self.scaler = model_data['scaler']
            self.baseline_stats = model_data['baseline_stats']
            self.is_trained = model_data['is_trained']
            logger.info(f"Model loaded from {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self._initialize_models()