"""
Production-Ready FastAPI Server for Intrusion Detection
Real-time API endpoints for threat detection and monitoring
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import joblib
import logging
from datetime import datetime
import numpy as np
import json
import asyncio
from collections import deque

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Intrusion Detection System API",
    description="Production-ready API for real-time network threat detection",
    version="1.0.0"
)

# ============================================================
# Pydantic Models
# ============================================================

class NetworkPacket(BaseModel):
    """Single network packet data"""
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int = Field(..., description="Source port")
    dst_port: int = Field(..., description="Destination port")
    protocol: str = Field(..., description="Protocol (TCP/UDP/ICMP)")
    packet_length: int = Field(..., description="Packet length in bytes")
    pkt_count: int = Field(default=1, description="Packet count in flow")
    bytes: int = Field(..., description="Total bytes in flow")
    duration: float = Field(..., description="Flow duration in seconds")
    rate: float = Field(..., description="Packet rate")
    timestamp: Optional[str] = Field(default_factory=lambda: datetime.now().isoformat())


class BatchPredictionRequest(BaseModel):
    """Batch prediction request"""
    packets: List[NetworkPacket] = Field(..., description="List of network packets")
    return_probabilities: bool = Field(default=True, description="Return prediction probabilities")


class PredictionResponse(BaseModel):
    """Single prediction response"""
    packet_id: int
    src_ip: str
    dst_ip: str
    prediction: str  # "BENIGN" or "ATTACK"
    confidence: float
    risk_score: float  # 0-100
    threat_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    timestamp: str


class BatchPredictionResponse(BaseModel):
    """Batch prediction response"""
    request_id: str
    total_packets: int
    predictions: List[PredictionResponse]
    summary: Dict[str, Any]
    processing_time_ms: float


class AlertNotification(BaseModel):
    """Alert notification for anomalies"""
    alert_id: str
    severity: str  # "INFO", "WARNING", "CRITICAL"
    attack_type: str
    description: str
    source_ip: str
    dest_ip: str
    packet_count: int
    timestamp: str


class HealthCheckResponse(BaseModel):
    """Health check response"""
    status: str
    model_loaded: bool
    uptime_seconds: float
    alerts_generated: int
    requests_processed: int


# ============================================================
# Global State
# ============================================================

class ModelManager:
    """Manage model loading and predictions"""
    
    def __init__(self):
        self.model = None
        self.selector = None
        self.model_loaded = False
        self.load_model()
    
    def load_model(self):
        """Load trained model from disk"""
        try:
            self.model = joblib.load("models/final_ids_model.pkl")
            self.selector = joblib.load("models/feature_selector.pkl")
            self.model_loaded = True
            logger.info("✅ Model loaded successfully")
        except Exception as e:
            logger.error(f"❌ Failed to load model: {e}")
            self.model_loaded = False
    
    def apply_feature_selection(self, X):
        """Apply same feature selection as training"""
        if self.selector is None:
            return X
        
        X_var = self.selector["variance_selector"].transform(X)
        return X_var[:, self.selector["top_feature_indices"]]
    
    def predict(self, X):
        """Make predictions"""
        if not self.model_loaded:
            raise Exception("Model not loaded")
        
        X_selected = self.apply_feature_selection(X)
        predictions = self.model.predict(X_selected)
        probabilities = self.model.predict_proba(X_selected)
        
        return predictions, probabilities


class AlertManager:
    """Manage threat alerts"""
    
    def __init__(self, max_alerts=1000):
        self.alerts = deque(maxlen=max_alerts)
        self.alert_count = 0
    
    def create_alert(self, packet: NetworkPacket, prediction: str, confidence: float):
        """Create alert for suspicious packet"""
        if prediction == "ATTACK":
            self.alert_count += 1
            alert = AlertNotification(
                alert_id=f"alert_{self.alert_count}",
                severity=self._get_severity(confidence),
                attack_type="Unknown",
                description=f"Suspicious traffic detected from {packet.src_ip}",
                source_ip=packet.src_ip,
                dest_ip=packet.dst_ip,
                packet_count=packet.pkt_count,
                timestamp=datetime.now().isoformat()
            )
            self.alerts.append(alert)
            logger.warning(f"🚨 Alert: {alert.alert_id} - {alert.severity}")
            return alert
        return None
    
    @staticmethod
    def _get_severity(confidence: float) -> str:
        """Map confidence to severity level"""
        if confidence >= 0.95:
            return "CRITICAL"
        elif confidence >= 0.85:
            return "WARNING"
        else:
            return "INFO"
    
    def get_recent_alerts(self, limit: int = 100) -> List[AlertNotification]:
        """Get recent alerts"""
        return list(self.alerts)[-limit:]


# Initialize global managers
model_manager = ModelManager()
alert_manager = AlertManager()

start_time = datetime.now()
request_count = 0


# ============================================================
# API Endpoints
# ============================================================

@app.get("/", tags=["Info"])
async def root():
    """API information endpoint"""
    return {
        "api": "AI Intrusion Detection System",
        "version": "1.0.0",
        "endpoints": {
            "predict": "/api/v1/predict",
            "predict_batch": "/api/v1/predict/batch",
            "health": "/api/v1/health",
            "alerts": "/api/v1/alerts",
            "stats": "/api/v1/stats",
            "websocket": "/ws/monitor"
        }
    }


@app.get("/api/v1/health", tags=["Health"], response_model=HealthCheckResponse)
async def health_check():
    """Health check endpoint"""
    global request_count
    uptime = (datetime.now() - start_time).total_seconds()
    
    return HealthCheckResponse(
        status="healthy" if model_manager.model_loaded else "unhealthy",
        model_loaded=model_manager.model_loaded,
        uptime_seconds=uptime,
        alerts_generated=alert_manager.alert_count,
        requests_processed=request_count
    )


@app.post("/api/v1/predict", tags=["Prediction"], response_model=PredictionResponse)
async def predict_single(packet: NetworkPacket):
    """
    Predict threat level for a single network packet
    
    Example request:
    ```
    {
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "packet_length": 1500,
        "pkt_count": 5,
        "bytes": 75000,
        "duration": 30.5,
        "rate": 0.16
    }
    ```
    """
    global request_count
    request_count += 1
    
    if not model_manager.model_loaded:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        # Prepare feature vector (must match training features)
        X = np.array([[
            packet.src_port,
            packet.dst_port,
            packet.packet_length,
            packet.pkt_count,
            packet.bytes,
            packet.duration,
            packet.rate,
            1.0 if packet.protocol == "TCP" else (0.0 if packet.protocol == "UDP" else 0.5)
        ]])
        
        # Make prediction
        predictions, probabilities = model_manager.predict(X)
        
        # Extract confidence
        confidence = float(np.max(probabilities[0]))
        is_attack = predictions[0] == 1
        risk_score = float(probabilities[0][1] * 100) if is_attack else float(probabilities[0][0] * 100)
        
        # Determine threat level
        if is_attack:
            threat_level = "CRITICAL" if confidence >= 0.95 else "HIGH"
        else:
            threat_level = "LOW"
        
        prediction_label = "ATTACK" if is_attack else "BENIGN"
        
        # Create alert if necessary
        if is_attack:
            alert_manager.create_alert(packet, prediction_label, confidence)
        
        return PredictionResponse(
            packet_id=request_count,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            prediction=prediction_label,
            confidence=confidence,
            risk_score=risk_score,
            threat_level=threat_level,
            timestamp=datetime.now().isoformat()
        )
    
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/predict/batch", tags=["Prediction"], response_model=BatchPredictionResponse)
async def predict_batch(request: BatchPredictionRequest):
    """
    Batch predict threat levels for multiple packets
    Recommended for high-volume predictions
    """
    global request_count
    start_batch_time = datetime.now()
    request_count += 1
    
    if not model_manager.model_loaded:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        batch_size = len(request.packets)
        
        # Prepare feature vectors
        X = []
        for packet in request.packets:
            features = [
                packet.src_port,
                packet.dst_port,
                packet.packet_length,
                packet.pkt_count,
                packet.bytes,
                packet.duration,
                packet.rate,
                1.0 if packet.protocol == "TCP" else (0.0 if packet.protocol == "UDP" else 0.5)
            ]
            X.append(features)
        
        X = np.array(X)
        
        # Make predictions
        predictions, probabilities = model_manager.predict(X)
        
        # Build response
        response_predictions = []
        attack_count = 0
        
        for i, (packet, pred, probs) in enumerate(zip(request.packets, predictions, probabilities)):
            is_attack = pred == 1
            confidence = float(np.max(probs))
            risk_score = float(probs[1] * 100) if is_attack else float(probs[0] * 100)
            
            if is_attack:
                threat_level = "CRITICAL" if confidence >= 0.95 else "HIGH"
                attack_count += 1
            else:
                threat_level = "LOW"
            
            prediction_label = "ATTACK" if is_attack else "BENIGN"
            
            response_predictions.append(PredictionResponse(
                packet_id=i,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                prediction=prediction_label,
                confidence=confidence,
                risk_score=risk_score,
                threat_level=threat_level,
                timestamp=datetime.now().isoformat()
            ))
        
        processing_time = (datetime.now() - start_batch_time).total_seconds() * 1000
        
        return BatchPredictionResponse(
            request_id=f"batch_{request_count}",
            total_packets=batch_size,
            predictions=response_predictions,
            summary={
                "benign_count": batch_size - attack_count,
                "attack_count": attack_count,
                "attack_percentage": (attack_count / batch_size * 100) if batch_size > 0 else 0,
                "avg_confidence": float(np.mean([p.confidence for p in response_predictions]))
            },
            processing_time_ms=processing_time
        )
    
    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/alerts", tags=["Alerts"])
async def get_alerts(limit: int = 100):
    """Get recent threat alerts"""
    alerts = alert_manager.get_recent_alerts(limit)
    return {
        "total_alerts": len(alerts),
        "alerts": [alert.dict() for alert in alerts]
    }


@app.get("/api/v1/alerts/critical", tags=["Alerts"])
async def get_critical_alerts():
    """Get critical-level alerts only"""
    all_alerts = alert_manager.get_recent_alerts(1000)
    critical_alerts = [a for a in all_alerts if a.severity == "CRITICAL"]
    
    return {
        "critical_alert_count": len(critical_alerts),
        "alerts": [alert.dict() for alert in critical_alerts[-50:]]  # Last 50
    }


@app.get("/api/v1/stats", tags=["Stats"])
async def get_statistics():
    """Get system statistics"""
    uptime = (datetime.now() - start_time).total_seconds()
    alerts = alert_manager.get_recent_alerts(10000)
    
    severity_dist = {
        "CRITICAL": len([a for a in alerts if a.severity == "CRITICAL"]),
        "WARNING": len([a for a in alerts if a.severity == "WARNING"]),
        "INFO": len([a for a in alerts if a.severity == "INFO"])
    }
    
    return {
        "uptime_hours": uptime / 3600,
        "total_requests": request_count,
        "total_alerts": alert_manager.alert_count,
        "severity_distribution": severity_dist,
        "model_status": "loaded" if model_manager.model_loaded else "not_loaded"
    }


@app.websocket("/ws/monitor")
async def websocket_monitor(websocket: WebSocket):
    """WebSocket endpoint for real-time monitoring"""
    await websocket.accept()
    logger.info("WebSocket connection established")
    
    try:
        while True:
            # Get recent alerts
            alerts = alert_manager.get_recent_alerts(10)
            
            # Send to client
            await websocket.send_json({
                "timestamp": datetime.now().isoformat(),
                "alerts_count": len(alerts),
                "recent_alerts": [a.dict() for a in alerts],
                "uptime_seconds": (datetime.now() - start_time).total_seconds(),
                "requests_processed": request_count
            })
            
            # Update every 2 seconds
            await asyncio.sleep(2)
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()


# ============================================================
# Startup/Shutdown
# ============================================================

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    logger.info("🚀 AI IDS API Server starting...")
    logger.info(f"Model loaded: {model_manager.model_loaded}")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🛑 AI IDS API Server shutting down...")
    logger.info(f"Total requests processed: {request_count}")
    logger.info(f"Total alerts generated: {alert_manager.alert_count}")


if __name__ == "__main__":
    import uvicorn
    
    # Run server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
