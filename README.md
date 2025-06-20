# SACA-SQL-RAG

This project implements a Retrieval-Augmented Generation (RAG) system for SQL queries using a Large Language Model (LLM). It leverages a combination of packet capture analysis (PCAP), SQL query generation, and LLM-based response generation to provide insights from network traffic data.

## Key Components

- **PCAP Analysis:**  Analyzes network packet captures (PCAP files) to extract relevant data.
- **SQL Query Generation:**  Generates SQL queries based on the extracted data and user prompts.
- **LLM Integration:**  Utilizes a Large Language Model to generate human-readable responses to SQL queries.

## Dependencies

- Python 3.x
- Libraries listed in `requirements.txt`

## Usage

1. Install dependencies: `pip install -r requirements.txt`
2. Run the main script: `python saca_sql.py`

## Data

- Sample PCAP data is available in the `csv_data` directory.
- Example screenshots are available in the `scshot-saca-sql` directory.

## Analysis

The `saca_sql_rag_ok.ipynb` notebook contains the core analysis and experimentation for this project. It demonstrates the process of extracting data from PCAP files, generating SQL queries, and utilizing an LLM to provide insightful responses. Key steps include data preprocessing, feature engineering, model training, and evaluation.
