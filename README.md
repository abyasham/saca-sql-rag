# SACA-SQL-RAG

🛡️ **Security Audit Compliance Assistant with SQL Query and RAG**

A comprehensive Retrieval-Augmented Generation (RAG) system for security audit analysis using Large Language Models (LLMs). SACA combines network traffic analysis, SQL query generation, and intelligent document processing to provide insights from security audit data and policy compliance.

## 🚀 Features

- **🔍 Network Traffic Analysis**: Analyze CSV audit data with intelligent SQL query generation
- **📋 Policy Document Processing**: RAG-based analysis of security policy documents (PDF, DOCX, TXT, JSON)
- **🤖 Dual AI Support**: 
  - Online API models (OpenRouter with multiple LLM options)
  - Local Hugging Face models for offline operation
- **🎯 Accuracy Testing**: Built-in evaluation system with ground truth security scenarios
- **💬 Interactive Chat Interface**: Streamlit-based UI for seamless interaction
- **🔒 Security-First Design**: Automated detection of unauthorized access, failed connections, and policy violations

## 🏗️ Architecture

SACA (Security Audit Compliance Assistant) implements a sophisticated RAG architecture:

1. **📊 Data Ingestion**: CSV audit data and policy documents are processed and indexed
2. **🧠 Intelligent Query Processing**: Natural language questions are converted to SQL queries
3. **🔍 RAG Document Search**: Semantic search through policy documents with relevance scoring
4. **🤖 LLM Integration**: Multiple AI models for contextual analysis and response generation
5. **📈 Accuracy Evaluation**: Continuous assessment against security audit benchmarks

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/abyasham/saca-sql-rag.git
   cd saca-sql-rag
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment** (for online models):
   ```bash
   cp .env.example .env
   # Edit .env and add your OpenRouter API key
   ```

## 🚀 Usage

### Basic Usage
```bash
streamlit run saca_sql_rag_local.py
```

### LLMware Integration (Advanced)
```bash
streamlit run saca_sql.py
```

## 📁 Project Structure

```
saca-sql-rag/
├── saca_sql_rag_local.py    # Main Streamlit application
├── saca_sql.py              # LLMware-based implementation
├── requirements.txt         # Python dependencies
├── .env.example            # Environment configuration template
├── .gitignore              # Git ignore rules
├── README.md               # This file
├── SETUP_GUIDE.md          # Detailed setup instructions
├── csv_data/               # Sample audit data
│   ├── sampled_toniot_dataset.csv
│   └── nayaone-sec.pdf
├── llmware_data/           # LLMware model cache
└── scshot-saca-sql/        # Application screenshots
```

## 🎯 Security Analysis Categories

- **🚫 Unauthorized Access Detection**: Identify connections to non-standard ports
- **❌ Failed Connection Analysis**: Detect potential brute force attacks
- **📈 High Volume Traffic**: Find sources of suspicious data transfer
- **🔍 Protocol Analysis**: Identify unusual network protocols
- **🚪 Backdoor Detection**: Discover potential backdoor connections
- **📊 Compliance Reporting**: Generate security violation summaries

## 🤖 Supported AI Models

### Online Models (via OpenRouter)
- 🆓 **Free Models**: Qwen 2.5, Llama 3.1, DeepSeek, Gemma 2, Mistral 7B
- 💳 **Premium Models**: Claude 3.5 Sonnet, GPT-4, Gemini Pro

### Local Models (Hugging Face)
- SecurityLLM, DialoGPT variants, BlenderBot models
- Full offline operation with CUDA/CPU support

## 📊 Data Requirements

- **Audit Data**: CSV format with network traffic logs
- **Policy Documents**: PDF, DOCX, TXT, or JSON security policies
- **Sample Data**: Included in `csv_data/` directory

## 🔧 Configuration

### Environment Variables
```bash
OPENROUTER_API_KEY=your_api_key_here
DEFAULT_MODEL=qwen/qwen-2.5-72b-instruct
```

### Model Selection
- Choose between online API models or local Hugging Face models
- Automatic fallback and error handling
- GPU acceleration support when available

## 🎯 Accuracy Testing

SACA includes a comprehensive evaluation system:
- Ground truth security scenarios
- SQL query similarity scoring
- Response quality assessment
- Category-based accuracy metrics

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is open source. Please check the repository for license details.

## 🆘 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check the `SETUP_GUIDE.md` for detailed configuration help
- Review the sample data and screenshots for usage examples

## 🔒 Security Note

This tool is designed for security audit analysis. Always ensure:
- Sensitive data is properly handled
- API keys are kept secure
- Audit logs are processed in compliance with your organization's policies
