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

## Architectural Design

SACA (Security Audit Contextual Assistant) is designed as a Retrieval-Augmented Generation (RAG) system to enhance security audits through intelligent data analysis. The architecture consists of the following key components:

1.  **Data Ingestion:** PCAP files are ingested and parsed to extract relevant network traffic data.
2.  **Data Preprocessing:** Extracted data is cleaned, transformed, and prepared for analysis.
3.  **SQL Query Generation:** Based on user prompts or predefined security audit questions, SQL queries are generated to retrieve specific information from the processed data.
4.  **LLM Integration:** A Large Language Model (LLM) is used to interpret the SQL query results and generate human-readable, contextualized responses.
5.  **Output & Reporting:** The LLM-generated responses are presented to the user, providing insights into potential security vulnerabilities or anomalies.

This architecture allows SACA to provide a more comprehensive and contextualized security audit experience by leveraging the power of LLMs and the precision of SQL queries.
