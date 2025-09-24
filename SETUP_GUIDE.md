# SACA SQL Setup Guide - Ubuntu/Linux

This guide will help you fix the requirements.txt issues and properly set up the Security Audit Compliance Agent (SACA) SQL application.

## Problem Analysis

The main issue with your current `requirements.txt` is that it includes `sqlite3` on line 5, which is a built-in Python standard library module and cannot be installed via pip. This causes the installation to fail.

## System Requirements

- Python 3.8-3.10 (confirmed compatible)
- Ubuntu/Linux operating system
- At least 16GB RAM (recommended 32GB for optimal performance)
- Internet connection for downloading models

## Step 1: System Dependencies

First, install required system packages:

```bash
sudo apt update
sudo apt install -y python3-dev python3-pip build-essential
sudo apt install -y libsqlite3-dev  # For SQLite support
sudo apt install -y git curl wget   # For downloading models
```

## Step 2: Corrected Requirements File

Create a new `requirements_corrected.txt` file with the following content:

```txt
# Core dependencies for Security Audit Compliance Agent (SACA)
streamlit>=1.28.0
pandas>=2.0.0
numpy>=1.24.0
# NOTE: sqlite3 is built-in to Python - DO NOT include it in requirements

# LLMware - Main AI/ML framework
llmware>=0.2.15

# Machine Learning and AI models
torch>=2.0.0
transformers>=4.30.0
accelerate>=0.20.0

# Document processing
PyPDF2>=3.0.0
python-docx>=0.8.11

# Environment and configuration
python-dotenv>=1.0.0

# Additional utilities
requests>=2.31.0
urllib3>=2.0.0
charset-normalizer>=3.2.0

# Development and debugging
ipython>=8.0.0
jupyter>=1.0.0

# Additional dependencies for llmware functionality
sentence-transformers>=2.2.0
faiss-cpu>=1.7.0
pymongo>=4.0.0
chromadb>=0.4.0
```

## Step 3: Installation Process

### Option A: Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv saca_env
source saca_env/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install corrected requirements
pip install -r requirements_corrected.txt
```

### Option B: System-wide Installation

```bash
# Upgrade pip
pip3 install --upgrade pip

# Install corrected requirements
pip3 install -r requirements_corrected.txt
```

## Step 4: LLMware Setup

LLMware requires additional setup for models:

```bash
# Create llmware data directory (as specified in your code)
mkdir -p /home/wistara/llmware_data

# Or create it in your user directory if /home/wistara doesn't exist
mkdir -p ~/llmware_data
```

**Important**: Update the paths in your `saca_sql.py` file:
- Line 12: `LLMWareConfig().llmware_path = "/home/wistara/llmware_data"`
- Line 272: `LLMWareConfig().llmware_path = "/home/wistara/llmware_data"`
- Line 348: `LLMWareConfig().llmware_path = "/home/wistara/llmware_data"`

Change these to your actual user directory or a directory you have write access to.

## Step 5: Model Downloads

The application uses these models that will be downloaded automatically on first run:
- `bling-phi-3-gguf` - Core RAG question-answer model
- `slim-sql-tool` - Text-to-SQL model
- `jina-reranker-turbo` - Reranking model

## Step 6: Data Directory Setup

Ensure your data directories exist:

```bash
# Create CSV data directory (as referenced in your code)
mkdir -p /home/abyasa/bsegolily/csv_data

# Copy your data files
cp csv_data/sampled_toniot_dataset.csv /home/abyasa/bsegolily/csv_data/
cp csv_data/nayaone-sec.pdf /home/abyasa/bsegolily/csv_data/
```

## Step 7: Running the Application

```bash
# Activate virtual environment (if using)
source saca_env/bin/activate

# Run the Streamlit application
streamlit run saca_sql.py
```

## Troubleshooting

### Common Issues and Solutions

1. **"No module named 'sqlite3'" Error**
   - Solution: Remove `sqlite3` from requirements.txt (it's built-in)

2. **LLMware Installation Issues**
   - Try: `pip install llmware --no-cache-dir`
   - Or: `pip install llmware==0.2.15` (specific version)

3. **Permission Denied for /home/wistara/llmware_data**
   - Update paths in `saca_sql.py` to use your home directory
   - Or create the directory with proper permissions

4. **Model Download Failures**
   - Ensure stable internet connection
   - Check available disk space (models can be several GB)
   - Try running with `--verbose` flag for debugging

5. **Memory Issues**
   - Ensure at least 16GB RAM available
   - Close other applications
   - Consider using smaller models if available

### Verification Commands

```bash
# Check Python version
python3 --version

# Check installed packages
pip list | grep -E "(streamlit|llmware|torch)"

# Test imports
python3 -c "import streamlit, llmware; print('All imports successful')"
```

## Next Steps

1. Fix the requirements.txt file by removing the `sqlite3` line
2. Install dependencies using the corrected requirements
3. Update file paths in `saca_sql.py` to match your system
4. Test the application with `streamlit run saca_sql.py`

## Performance Notes

- First run will be slower due to model downloads
- Subsequent runs should be faster
- Consider using GPU acceleration if available
- Monitor memory usage during operation

## Support

If you encounter issues:
1. Check the error messages carefully
2. Verify all file paths exist and are accessible
3. Ensure sufficient system resources
4. Consider using a virtual environment for isolation