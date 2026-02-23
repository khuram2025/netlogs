# NetLogs AI Integration

## Overview

NetLogs now includes AI-powered features using Large Language Models (LLMs) to enhance security analysis capabilities. The platform supports multiple LLM providers, allowing you to choose the best solution for your environment.

## Supported LLM Providers

### 1. **Claude (Anthropic)** - Recommended
- **Models**: `claude-sonnet-4-5-20250929`, `claude-opus-4-6-20250820`, `claude-haiku-4-5-20251001`
- **Pricing**: ~$3-15 per 1000 alerts (depending on model)
- **Best for**: Production deployments, highest quality analysis
- **API Key**: Get from [Anthropic Console](https://console.anthropic.com/)

### 2. **OpenAI**
- **Models**: `gpt-4`, `gpt-4-turbo`, `gpt-4o`, `gpt-3.5-turbo`
- **Pricing**: Variable based on model
- **Best for**: Alternative to Claude, established ecosystem
- **API Key**: Get from [OpenAI Platform](https://platform.openai.com/)

### 3. **Ollama (Local)** - Air-Gapped Deployments
- **Models**: `llama3.2:8b`, `mixtral:8x7b`, `codellama:13b`
- **Pricing**: Free (self-hosted)
- **Best for**: Air-gapped environments, data privacy requirements
- **Setup**: Install Ollama locally (http://localhost:11434)

### 4. **Google Gemini**
- **Models**: `gemini-1.5-pro`, `gemini-1.5-flash`, `gemini-pro`
- **Pricing**: Competitive pricing, free tier available
- **Best for**: Google Cloud integrations
- **API Key**: Get from [Google AI Studio](https://makersuite.google.com/app/apikey)

### 5. **Azure OpenAI**
- **Models**: `gpt-4`, `gpt-35-turbo`
- **Pricing**: Enterprise pricing with Azure credits
- **Best for**: Enterprise Azure customers
- **Setup**: Requires Azure resource URL and deployment name

---

## AI Features

### 1. **Alert Summarization** ✅ Available Now
- **What it does**: Analyzes security alerts and generates:
  - **Executive Summary**: 2-3 sentence overview of the incident
  - **Risk Assessment**: Low/Medium/High/Critical with reasoning
  - **Recommended Actions**: Prioritized list of response steps
  - **MITRE Context**: Explanation of the attack technique
  - **Confidence Score**: AI confidence in the analysis (0-100%)

- **How to use**:
  1. Navigate to **Alerts** dashboard
  2. Click on any alert to view details
  3. Click **"AI Summary"** button in the modal
  4. AI generates insights in ~2-5 seconds

- **Example Output**:
  ```
  Executive Summary:
  Detected 234 failed SSH authentication attempts from 12 Chinese IP addresses
  targeting admin@192.168.1.5 over 15 minutes. This indicates a credential
  brute force attack targeting administrative accounts.

  Risk Assessment: HIGH
  The attack targets privileged accounts and originates from known malicious
  infrastructure. High volume suggests automated tooling.

  Recommended Actions:
  1. Block all source IPs via EDL auto-block list
  2. Force password reset for admin account
  3. Enable MFA for all administrative accounts
  4. Review authentication logs for successful logins from these IPs
  5. Alert IR team for potential account compromise investigation

  MITRE ATT&CK Context:
  T1110.001 - Brute Force: Password Guessing. Attackers systematically attempt
  common credentials to gain initial access to systems.

  Confidence: 92%
  ```

### 2. **Natural Language Search** 🚧 Coming Soon
- Convert plain English queries to NetLogs Query Language (NQL)
- Example: *"Show me all blocked traffic from China to my database servers in the last hour"*
- Automatically generates: `country:CN AND action:deny AND dstip:10.50.0.0/24 AND timestamp > now-1h`

### 3. **IOC Extraction from Reports** 🚧 Coming Soon
- Upload PDF/text threat intel reports
- AI automatically extracts IPs, domains, hashes
- Auto-populate EDL lists with categorization
- MITRE technique tagging

### 4. **Anomaly Detection** 🚧 Coming Soon
- ML-based behavioral analytics
- Detects unusual patterns not covered by signature rules
- Zero-day threat detection

---

## Configuration

### Step 1: Access AI Settings
1. Log in as **ADMIN** user
2. Navigate to sidebar: **Admin** → **AI Settings**
3. Click **"Add LLM Provider"**

### Step 2: Configure Your Provider

#### For Claude (Recommended):
```
Provider: Claude (Anthropic)
Model: claude-sonnet-4-5-20250929
API Key: sk-ant-api03-xxxxx (from Anthropic Console)
Max Tokens: 2048
Temperature: 0 (deterministic) or 30 (creative)
```

#### For Ollama (Local):
```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull a model
ollama pull llama3.2:8b

# 3. Configure in NetLogs
Provider: Ollama (Local)
Model: llama3.2:8b
Base URL: http://localhost:11434
API Key: (leave empty)
Max Tokens: 2048
Temperature: 0
```

#### For Azure OpenAI:
```
Provider: Azure OpenAI
Model: gpt-4
API Key: <your-azure-api-key>
Base URL: https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT/chat/completions?api-version=2024-02-01
Max Tokens: 2048
Temperature: 0
```

### Step 3: Test Configuration
1. Click **"Test"** button on your configured provider
2. AI will respond to: *"Explain what a port scan is in one sentence."*
3. If successful, you'll see the AI response
4. Click **"Activate"** to make this the active provider

### Step 4: Use AI Features
- AI will now be used for all AI-powered features
- Switch providers anytime by activating a different configuration
- Multiple configs can be stored, but only one active at a time

---

## Architecture

### Components

```
fastapi_app/
├── models/
│   └── llm_config.py          # LLM configuration database model
├── services/ai/
│   ├── __init__.py
│   ├── client.py              # Multi-provider AI client abstraction
│   └── alert_summarizer.py   # Alert summarization logic
├── api/
│   ├── llm_config.py          # LLM config CRUD endpoints
│   └── alerts.py              # Enhanced with /ai-summary endpoint
└── templates/
    ├── llm_config.html        # AI Settings UI
    └── alerts/
        └── alert_dashboard.html  # Enhanced with AI Summary button
```

### API Client Flow

```
Alert Detail Request
    ↓
GET /api/alerts/{id}/ai-summary
    ↓
AIClient.complete(prompt, system_prompt)
    ↓
┌─────────────────────────────────────┐
│ Route to Active Provider:           │
│ • Claude → Anthropic API             │
│ • OpenAI → OpenAI API                │
│ • Ollama → Local Ollama Server       │
│ • Gemini → Google Generative AI      │
│ • Azure → Azure OpenAI Resource      │
└─────────────────────────────────────┘
    ↓
Parse JSON Response
    ↓
Return { summary, risk_assessment, recommended_actions, mitre_context, confidence }
```

### Database Schema

```sql
CREATE TABLE llm_configs (
    id SERIAL PRIMARY KEY,
    provider VARCHAR NOT NULL,  -- 'claude', 'openai', 'ollama', 'gemini', 'azure_openai'
    model_name VARCHAR(100) NOT NULL,
    api_key TEXT,
    api_base_url VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    max_tokens INTEGER DEFAULT 2048,
    temperature INTEGER DEFAULT 0,  -- 0-100 (converted to 0.0-1.0)
    created_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE
);
```

---

## Cost Estimation

### Claude (Recommended for Production)

| Model | Input Cost (1M tokens) | Output Cost (1M tokens) | Cost per Alert* |
|-------|------------------------|-------------------------|-----------------|
| Claude Haiku 4.5 | $0.25 | $1.25 | $0.003 |
| Claude Sonnet 4.5 | $3.00 | $15.00 | $0.03 |
| Claude Opus 4.6 | $15.00 | $75.00 | $0.15 |

*Estimated for typical alert with enrichment data (~500 input tokens, 300 output tokens)

### Example Monthly Costs

| Alerts per Day | Haiku | Sonnet | Opus |
|----------------|-------|--------|------|
| 10 | $0.90/mo | $9/mo | $45/mo |
| 50 | $4.50/mo | $45/mo | $225/mo |
| 100 | $9/mo | $90/mo | $450/mo |

### OpenAI

| Model | Input Cost (1M tokens) | Output Cost (1M tokens) | Cost per Alert* |
|-------|------------------------|-------------------------|-----------------|
| GPT-4 Turbo | $10.00 | $30.00 | $0.06 |
| GPT-4o | $2.50 | $10.00 | $0.02 |
| GPT-3.5 Turbo | $0.50 | $1.50 | $0.003 |

### Ollama (Self-Hosted)
- **Cost**: Free (hardware costs only)
- **Hardware Requirements**:
  - **llama3.2:3b**: 4GB RAM, CPU-only OK
  - **llama3.2:8b**: 8GB RAM, CPU-only OK
  - **mixtral:8x7b**: 32GB RAM, GPU recommended

---

## Security & Privacy

### Data Handling
- **Alert data is sent to the LLM provider** for analysis
- Includes: alert details, enrichment data (IPs, ports, event counts)
- **Does NOT include**: Raw log messages, credentials, API keys

### Recommendations by Deployment Type

#### Public Cloud / SaaS:
- ✅ Use **Claude** or **OpenAI** for best results
- ✅ Ensure compliance with data residency requirements
- ✅ Review LLM provider's data retention policies

#### Air-Gapped / On-Premises:
- ✅ Use **Ollama** for local inference
- ✅ No data leaves your network
- ⚠️ Lower quality than cloud models
- ⚠️ Requires GPU for larger models

#### Hybrid:
- ✅ Use **Ollama** for sensitive alerts
- ✅ Use **Claude** for non-sensitive analysis
- ✅ Configure per-rule AI routing (coming soon)

### API Key Security
- API keys stored in PostgreSQL database
- Encrypted at rest (production deployments)
- Only ADMIN role can view/edit LLM configs
- Keys never logged or exposed in UI

---

## Troubleshooting

### "AI not configured" Error
**Problem**: No active LLM configuration found

**Solution**:
1. Navigate to **Admin** → **AI Settings**
2. Add an LLM provider configuration
3. Click **"Activate"** on the configuration
4. Test with the **"Test"** button

### "API key invalid" Error
**Problem**: LLM provider rejected the API key

**Solution**:
1. Verify API key is correct (check for spaces/newlines)
2. Ensure API key has necessary permissions
3. Check billing is active on provider account
4. For Azure: Verify resource URL includes deployment name

### Ollama Connection Failed
**Problem**: Cannot connect to local Ollama instance

**Solution**:
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not running, start it
ollama serve

# Pull the model you configured
ollama pull llama3.2:8b

# Test inference
ollama run llama3.2:8b "What is a port scan?"
```

### Slow AI Response Times
**Problem**: AI summary takes >30 seconds

**Solution**:
1. **For Cloud APIs**: Network latency issue
   - Check internet connectivity
   - Use regional API endpoints if available

2. **For Ollama**: Model too large for hardware
   - Switch to smaller model (3b instead of 8b)
   - Add GPU support
   - Increase RAM allocation

3. **Reduce max_tokens**: Lower from 2048 to 1024

### JSON Parsing Errors
**Problem**: "Failed to parse AI response as JSON"

**Solution**:
1. Check AI provider compatibility (some may not follow JSON format)
2. Increase `temperature` to 0 for more deterministic output
3. Switch to Claude/OpenAI (best JSON compliance)

---

## Roadmap

### Phase 1: Alert Intelligence ✅ COMPLETE
- [x] Multi-provider LLM integration
- [x] Alert summarization with risk assessment
- [x] MITRE context explanations
- [x] Confidence scoring

### Phase 2: Interactive Analysis 🚧 IN PROGRESS
- [ ] Natural language log search (NQL translation)
- [ ] IOC extraction from threat reports
- [ ] Conversational threat hunting

### Phase 3: Automation 🔮 PLANNED
- [ ] Automated playbook generation
- [ ] Response action suggestions
- [ ] Incident timeline reconstruction
- [ ] Root cause analysis

### Phase 4: Learning & Optimization 🔮 PLANNED
- [ ] Anomaly detection ML models
- [ ] Correlation rule auto-generation
- [ ] False positive reduction
- [ ] Custom model fine-tuning

---

## API Reference

### Get AI Summary for Alert
```http
GET /api/alerts/{alert_id}/ai-summary
```

**Response**:
```json
{
  "success": true,
  "ai_summary": {
    "summary": "Detected 234 failed SSH attempts...",
    "risk_assessment": "HIGH - Attack targets privileged accounts...",
    "recommended_actions": [
      "Block source IPs via EDL",
      "Force password reset",
      "Enable MFA"
    ],
    "mitre_context": "T1110.001 - Brute Force: Password Guessing...",
    "confidence": 0.92
  }
}
```

### Test LLM Configuration
```http
POST /api/llm-config/test/
Content-Type: application/json

{
  "test_prompt": "Explain what a port scan is in one sentence."
}
```

**Response**:
```json
{
  "status": "success",
  "response": "A port scan is a reconnaissance technique...",
  "prompt": "Explain what a port scan is in one sentence."
}
```

---

## Support

- **Documentation**: This file
- **Issues**: https://github.com/anthropics/claude-code/issues (if using Claude)
- **Feature Requests**: Submit to NetLogs project repository

---

## Credits

Built with:
- [Anthropic Claude](https://www.anthropic.com/claude) - AI analysis
- [FastAPI](https://fastapi.tiangolo.com/) - Web framework
- [httpx](https://www.python-httpx.org/) - HTTP client
- [Ollama](https://ollama.com/) - Local LLM inference

---

**Last Updated**: February 2026
**Version**: 3.1.0
