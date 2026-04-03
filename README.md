🛡️ Megidai Backend — M-Egide-AI

Official backend of the Megidai project, a Privacy-First digital shield powered by decentralized artificial intelligence.

🚀 About

Megidai is a cybersecurity solution designed to protect digital citizens from modern threats (phishing, fraud, data breaches) while strictly respecting their privacy.

This backend forms the core of the infrastructure by handling:

- AI model aggregation (Federated Learning)
- URL & SMS threat analysis (NLP + Machine Learning)
- Community-based reputation system
- Data breach detection (HIBP integration)
- Guardian Mode notifications for family protection

🧠 Architecture

The backend is based on a Federated Learning architecture:

- The model is sent to user devices
- Training happens locally (Edge AI)
- Gradients are sent back to the server
- Secure aggregation (FedAvg) with Differential Privacy
- Global model is updated

👉 No raw personal data is ever collected.

⚙️ Tech Stack

**Backend Framework:** FastAPI (Python 3.11+)
**Database:** SQLite + SQLAlchemy (async)
**AI / ML:**
- Transformers (NLP for phishing detection)
- Scikit-learn (URL classification)
- TensorFlow (TFLite export)
- Joblib (model persistence)

**Notifications:** Firebase Cloud Messaging (FCM)
**HTTP Client:** HTTPX, aiohttp (async requests)
**Security:** python-jose, passlib, cryptography

🔐 Security Principles

Megidai follows a Security & Privacy by Design approach:

- ❌ No storage of sensitive personal data
- 📱 Data stored locally on the device
- 🔒 End-to-end encrypted communications
- 🧠 Learning without data collection (Federated Learning)
- 🛡 Server breach resilience (no exploitable user database)
- 🔐 Differential Privacy on gradients (ε=1.0)

📦 Core Features

**🧩 1. AI Aggregation (Federated Learning)**
- Receive local gradients from devices
- Secure aggregation (FedAvg algorithm)
- Apply Differential Privacy
- Global model updates
- Model versioning

**🔍 2. Threat Analysis**
- **URL Analyzer:** Multi-criteria scoring
  - Syntax analysis (homoglyphs, TLD detection)
  - Whitelist/blacklist checking
  - Community reputation
  - ML-based classification (Random Forest)
  - Risk score output
- **NLP Analyzer:** Phishing detection
  - SMS/email text analysis
  - Suspicion indicators detection
  - Confidence scoring

**📊 3. Community Reputation**
- URL reporting by users
- Blacklist management with flagging
- Community stats (total reports, threats blocked, active users)
- Report history tracking

**👼 4. Guardian Mode (Family Protection)**
- Pair protected devices with guardians
- Alert system on threat detection
- FCM push notifications
- Configurable sensitivity modes (strict/balanced/relaxed)
- Alert logging and history

**🔐 5. Data Breach Detection**
- Check emails against HIBP (Have I Been Pwned)
- K-Anonymity privacy protection (email prefix only)
- Password breach detection via hash prefixes

📁 Project Structure

```
megidai-backend/
│
├── main.py                    # FastAPI app entry point + lifespan management
├── database.py                # SQLAlchemy models & async engine (SQLite)
│
├── routers/                   # API endpoints
│   ├── __init__.py
│   ├── reputation.py          # POST /reputation/scan — URL analysis
│   ├── federated.py           # POST /federated/gradients, GET /federated/model
│   ├── guardian.py            # Guardian Mode endpoints
│   ├── community.py           # GET /community/stats
│   ├── hibp.py                # POST /hibp/check-email, check-password
│   └── nlp.py                 # POST /nlp/analyze — phishing detection
│
├── services/                  # Business logic
│   ├── __init__.py
│   ├── url_analyzer.py        # URL threat scoring (multi-criteria)
│   ├── fed_averaging.py       # FedAvg algorithm + Differential Privacy
│   ├── nlp_analyzer.py        # NLP-based phishing detection
│   ├── hibp_service.py        # HIBP API integration with k-anonymity
│   ├── db_service.py          # Database CRUD operations
│   └── notification.py        # FCM notification service
│
├── models/                    # Data models (Pydantic + SQLAlchemy)
│   ├── __init__.py
│   ├── gradient.py            # Federated Learning gradient request/response
│   ├── report.py              # Scan & report Pydantic models
│   ├── fed_metadata.json      # Model metadata
│   └── url_classifier_metadata.json
│
├── ai/                        # AI training & export scripts
│   ├── train_url.py           # Train URL classifier (Scikit-learn Random Forest)
│   └── export_tflite.py       # Export model to TensorFlow Lite format
│
├── requirements.txt           # Python dependencies
└── README.md
```

▶️ Installation

1. **Clone the project**
```bash
git clone https://github.com/your-username/megidai-backend.git
cd megidai-backend
```

2. **Create a virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**

Create a `.env` file in the root directory:
```env
# Firebase Cloud Messaging for Guardian Mode
FCM_API_KEY=your_fcm_api_key
FCM_PROJECT_ID=your_project_id

# HIBP API for data breach detection
HIBP_API_KEY=your_hibp_api_key

# Server config
DEBUG=True
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
```

5. **Run the server**
```bash
uvicorn main:app --reload
```

The server will start on `http://0.0.0.0:8000`
Interactive API documentation: `http://localhost:8000/docs` (Swagger UI)

📡 API Endpoints

**Reputation & URL Analysis**
```
POST /reputation/scan
{
  "url": "https://example.com",
  "user_id": "device_123"
}

Response:
{
  "url": "https://example.com",
  "risk_score": 45,
  "threat_type": "low_risk",
  "is_blacklisted": false,
  "confidence": 0.92,
  "analysis": {
    "url_analysis": {...},
    "community_data": {...}
  }
}
```

**Federated Learning**
```
POST /federated/gradients
{
  "device_id": "device_123",
  "gradients": [[0.1, 0.5, ...], ...],
  "num_samples": 100,
  "model_version": "v1.0"
}

Response:
{
  "status": "received",
  "device_id": "device_123",
  "aggregation_status": "pending",
  "global_model_version": "v1.0"
}
```

```
GET /federated/model
Response: Binary model file (TFLite format)
```

**Guardian Mode (Family Protection)**
```
POST /guardian/register
{
  "protected_device_id": "device_456",
  "guardian_device_id": "device_123",
  "guardian_fcm_token": "fcm_token_xxx",
  "protected_name": "My Child",
  "sensitivity_mode": "strict"
}
```

```
POST /guardian/alert
{
  "protected_device_id": "device_456",
  "threat_type": "phishing_sms",
  "threat_data": {
    "sender": "+1234567890",
    "message": "Click here to verify account"
  }
}
```

**Community Stats**
```
GET /community/stats
Response:
{
  "total_reports": 1250,
  "threats_blocked_today": 45,
  "active_users": 890
}
```

**Data Breach Detection (HIBP)**
```
POST /hibp/check-email
{
  "email": "user@example.com"
}

Response:
{
  "email": "user@example.com",
  "is_breached": true,
  "breach_count": 3,
  "breaches": [
    {"name": "LinkedIn", "date": "2021-06-01"},
    ...
  ]
}
```

```
POST /hibp/check-password
{
  "password": "user_password"
}

Response:
{
  "is_compromised": false,
  "occurrences": 0
}
```

**NLP Analysis (Phishing Detection)**
```
POST /nlp/analyze
{
  "text": "Click here to verify your account: ...",
  "type": "sms"
}

Response:
{
  "phishing_score": 0.85,
  "confidence": 0.92,
  "is_phishing": true,
  "indicators": ["urgency_language", "suspicious_link", "account_verification"]
}
```

🧪 AI & Machine Learning

**URL Classifier Training**
```bash
python ai/train_url.py
```
Trains a Scikit-learn Random Forest model on URL features:
- Syntactic features (length, special chars, TLD)
- Domain reputation
- URL structure analysis

**Export to TensorFlow Lite**
```bash
python ai/export_tflite.py
```
Converts the trained model to TFLite format for mobile deployment.

📊 Technical Performance

⚡ **Latency:** < 300ms target for threat analysis
🔋 **Resource Usage:** Optimized for async operations (FastAPI)
🔒 **Privacy:** Zero personal data stored, all analysis local
📦 **Scalability:** Async SQLite with connection pooling
🔐 **Security:** Differential Privacy (ε=1.0) on gradients

🤝 Contributing

We welcome contributions! Please ensure:
- Code follows PEP 8 style guidelines
- All new features include tests
- Privacy-first design principles
- Clear commit messages


🌍 Vision

"Building accessible, intelligent, and sovereign cybersecurity for everyone."

Megidai aims to become a leading cybersecurity solution in Africa and emerging markets by providing protection that is:
- **Local** — Analysis happens on devices
- **Private** — Zero data collection
- **Intelligent** — AI-powered threat detection
- **Affordable** — Accessible to all

📄 License

MIT License — See LICENSE file

📧 Contact

For questions or support, please open an issue on the GitHub repository.
