#!/usr/bin/env python3
"""
Smart Network Security Monitor with Anomaly Detection
Main entry point for the application
"""

import asyncio
import sys
import os
import signal
import argparse
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.network_monitor import NetworkMonitor
from src.core.packet_analyzer import PacketAnalyzer
from src.security.threat_detector import ThreatDetector
from src.ml.anomaly_detector import AnomalyDetector
from src.api.server import create_app
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityMonitorApp:
    def __init__(self, interface='en0', api_only=False):
        self.interface = interface
        self.api_only = api_only
        self.monitor = None
        self.analyzer = None
        self.threat_detector = None
        self.anomaly_detector = None
        self.app = None
        self.running = False
        
    async def initialize(self):
        """Initialize all components"""
        try:
            if not self.api_only:
                logger.info(f"Initializing network monitor on interface: {self.interface}")
                self.monitor = NetworkMonitor(interface=self.interface)
                self.analyzer = PacketAnalyzer()
                self.threat_detector = ThreatDetector()
                self.anomaly_detector = AnomalyDetector()
                
                # Load pre-trained model if exists
                try:
                    self.anomaly_detector.load_model()
                    logger.info("Loaded pre-trained anomaly detection model")
                except:
                    logger.warning("No pre-trained model found, will use default settings")
            
            # Create FastAPI app
            self.app = create_app()
            logger.info("API server initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize: {e}")
            raise
    
    async def start_monitoring(self):
        """Start packet capture and monitoring"""
        if self.api_only:
            return
            
        try:
            logger.info("Starting packet capture...")
            await self.monitor.start_capture()
            
            while self.running:
                # Process packets
                packets = await self.monitor.get_packets()
                if packets:
                    for packet in packets:
                        # Analyze packet
                        analysis = self.analyzer.analyze(packet)
                        
                        # Check for threats
                        threats = self.threat_detector.detect(analysis)
                        if threats:
                            logger.warning(f"Threats detected: {threats}")
                        
                        # Check for anomalies
                        if self.anomaly_detector.is_trained():
                            is_anomaly = self.anomaly_detector.predict(analysis)
                            if is_anomaly:
                                logger.warning(f"Anomaly detected in packet: {analysis}")
                
                await asyncio.sleep(0.1)
                
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
            raise
    
    async def start_api(self, host='0.0.0.0', port=8000):
        """Start the API server"""
        config = uvicorn.Config(
            app=self.app,
            host=host,
            port=port,
            log_level="info"
        )
        server = uvicorn.Server(config)
        await server.serve()
    
    async def run(self, host='0.0.0.0', port=8000):
        """Run the application"""
        self.running = True
        await self.initialize()
        
        # Create tasks
        tasks = []
        
        if not self.api_only:
            tasks.append(asyncio.create_task(self.start_monitoring()))
        
        tasks.append(asyncio.create_task(self.start_api(host, port)))
        
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.running = False
            for task in tasks:
                task.cancel()
    
    def stop(self):
        """Stop the application"""
        self.running = False
        if self.monitor:
            self.monitor.stop()


def main():
    parser = argparse.ArgumentParser(description='Smart Network Security Monitor')
    parser.add_argument('-i', '--interface', default='en0', help='Network interface to monitor')
    parser.add_argument('-p', '--port', type=int, default=8000, help='API server port')
    parser.add_argument('--host', default='0.0.0.0', help='API server host')
    parser.add_argument('--api-only', action='store_true', help='Run API server only (no packet capture)')
    
    args = parser.parse_args()
    
    # Check for root privileges if not API-only mode
    if not args.api_only and os.geteuid() != 0:
        logger.error("This application requires root privileges for packet capture.")
        logger.info("Please run with sudo or use --api-only flag for API-only mode")
        sys.exit(1)
    
    # Create and run the application
    app = SecurityMonitorApp(interface=args.interface, api_only=args.api_only)
    
    # Handle signals
    def signal_handler(sig, frame):
        logger.info("Received interrupt signal, shutting down...")
        app.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the application
    try:
        logger.info("Starting Smart Network Security Monitor...")
        logger.info(f"Interface: {args.interface}")
        logger.info(f"API Server: http://{args.host}:{args.port}")
        logger.info(f"API Docs: http://{args.host}:{args.port}/docs")
        
        asyncio.run(app.run(host=args.host, port=args.port))
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()