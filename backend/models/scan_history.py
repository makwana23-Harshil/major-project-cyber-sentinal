import uuid
from datetime import datetime, timezone

class ScanHistory:
    @staticmethod
    def create_document(scan_type, input_preview, raw_input, prediction, confidence, risk_score, risk_level, class_probabilities=None, indicators=None, xai_data=None, metadata_info=None):
        """Generates a structured dictionary to insert into MongoDB"""
        return {
            "id": str(uuid.uuid4()),
            "scan_type": scan_type,
            "input_preview": input_preview,
            "raw_input": raw_input,
            "prediction": prediction,
            "confidence": round(confidence, 1),
            "risk_score": round(risk_score, 1),
            "risk_level": risk_level,
            "class_probabilities": class_probabilities or {},
            "indicators": indicators or [],
            "xai_data": xai_data or {},
            "metadata_info": metadata_info or {},
            "created_at": datetime.now(timezone.utc)
        }