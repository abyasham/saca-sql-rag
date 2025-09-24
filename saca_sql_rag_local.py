import streamlit as st
import pandas as pd
import sqlite3
import os
import json
import requests
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import PyPDF2
import docx
import re
import difflib
import numpy as np
from dotenv import load_dotenv
from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
import torch

# Load environment variables
load_dotenv()

class AccuracyEvaluator:
    def __init__(self):
        self.ground_truth_qa = self._load_ground_truth()
        self.evaluation_results = []
    
    def _load_ground_truth(self) -> List[Dict]:
        """Load predefined ground truth question-answer pairs for security auditing"""
        return [
            {
                "question": "Find connections to unauthorized ports (not 80, 443, 22, 53)",
                "expected_sql": "SELECT DISTINCT dst_port, COUNT(*) as count FROM audit_data WHERE dst_port NOT IN (80, 443, 22, 53) GROUP BY dst_port ORDER BY count DESC",
                "category": "unauthorized_access",
                "description": "Identify connections to non-standard ports that may indicate unauthorized access"
            },
            {
                "question": "Show sources with high failed connection attempts",
                "expected_sql": "SELECT src_ip, COUNT(*) as failed_attempts FROM audit_data WHERE conn_state = 'REJ' OR conn_state = 'FAILED' GROUP BY src_ip HAVING failed_attempts > 10 ORDER BY failed_attempts DESC",
                "category": "failed_connections",
                "description": "Detect potential brute force attacks or scanning activities"
            },
            {
                "question": "Identify sources generating high volume traffic",
                "expected_sql": "SELECT src_ip, COUNT(*) as connection_count, SUM(src_bytes) as total_bytes FROM audit_data GROUP BY src_ip HAVING connection_count > 100 ORDER BY connection_count DESC",
                "category": "high_volume",
                "description": "Find sources that may be performing data exfiltration or DDoS attacks"
            },
            {
                "question": "Find suspicious protocol usage",
                "expected_sql": "SELECT proto, service, COUNT(*) as count FROM audit_data WHERE proto NOT IN ('tcp', 'udp', 'icmp') GROUP BY proto, service ORDER BY count DESC",
                "category": "suspicious_protocols",
                "description": "Identify unusual protocols that may indicate malicious activity"
            },
            {
                "question": "Show backdoor type connections",
                "expected_sql": "SELECT src_ip, dst_ip, dst_port, COUNT(*) as count FROM audit_data WHERE type = 'backdoor' GROUP BY src_ip, dst_ip, dst_port ORDER BY count DESC",
                "category": "backdoor_detection",
                "description": "Detect backdoor connections in the network traffic"
            },
            {
                "question": "Count total security violations by type",
                "expected_sql": "SELECT type, COUNT(*) as violation_count FROM audit_data WHERE label = 1 GROUP BY type ORDER BY violation_count DESC",
                "category": "violation_summary",
                "description": "Summarize all security violations by their type"
            },
            {
                "question": "Find connections with zero bytes transferred",
                "expected_sql": "SELECT src_ip, dst_ip, dst_port, COUNT(*) as count FROM audit_data WHERE src_bytes = 0 AND dst_bytes = 0 GROUP BY src_ip, dst_ip, dst_port HAVING count > 5 ORDER BY count DESC",
                "category": "scanning_activity",
                "description": "Identify potential port scanning activities"
            },
            {
                "question": "Show rejected connections by destination port",
                "expected_sql": "SELECT dst_port, COUNT(*) as rejected_count FROM audit_data WHERE conn_state = 'REJ' GROUP BY dst_port ORDER BY rejected_count DESC",
                "category": "rejected_connections",
                "description": "Analyze which ports are being targeted but rejected"
            }
        ]
    
    def calculate_sql_similarity(self, generated_sql: str, expected_sql: str) -> float:
        """Calculate similarity between generated and expected SQL queries"""
        # Normalize SQL queries
        gen_normalized = self._normalize_sql(generated_sql)
        exp_normalized = self._normalize_sql(expected_sql)
        
        # Calculate similarity using difflib
        similarity = difflib.SequenceMatcher(None, gen_normalized, exp_normalized).ratio()
        return similarity
    
    def _normalize_sql(self, sql: str) -> str:
        """Normalize SQL query for comparison"""
        # Remove extra whitespace and convert to lowercase
        normalized = re.sub(r'\s+', ' ', sql.strip().lower())
        # Remove common variations
        normalized = normalized.replace('audit_data', 'TABLE')
        normalized = normalized.replace('data', 'TABLE')
        return normalized
    
    def evaluate_response(self, question: str, generated_sql: str, api_response: str) -> Dict:
        """Evaluate a single response against ground truth"""
        # Find matching ground truth
        matching_gt = None
        for gt in self.ground_truth_qa:
            if self._questions_similar(question, gt["question"]):
                matching_gt = gt
                break
        
        if not matching_gt:
            return {
                "question": question,
                "status": "no_ground_truth",
                "similarity_score": 0.0,
                "category": "unknown"
            }
        
        # Calculate SQL similarity
        sql_similarity = self.calculate_sql_similarity(generated_sql, matching_gt["expected_sql"])
        
        # Evaluate response quality
        response_quality = self._evaluate_response_quality(api_response)
        
        result = {
            "question": question,
            "generated_sql": generated_sql,
            "expected_sql": matching_gt["expected_sql"],
            "sql_similarity": sql_similarity,
            "response_quality": response_quality,
            "category": matching_gt["category"],
            "description": matching_gt["description"],
            "status": "evaluated"
        }
        
        self.evaluation_results.append(result)
        return result
    
    def _questions_similar(self, q1: str, q2: str) -> bool:
        """Check if two questions are similar enough to be considered the same"""
        q1_norm = q1.lower().strip()
        q2_norm = q2.lower().strip()
        
        # Extract key terms
        key_terms_q1 = set(re.findall(r'\b\w+\b', q1_norm))
        key_terms_q2 = set(re.findall(r'\b\w+\b', q2_norm))
        
        # Calculate Jaccard similarity
        intersection = key_terms_q1.intersection(key_terms_q2)
        union = key_terms_q1.union(key_terms_q2)
        
        if len(union) == 0:
            return False
        
        similarity = len(intersection) / len(union)
        return similarity > 0.6  # 60% similarity threshold
    
    def _evaluate_response_quality(self, response: str) -> float:
        """Evaluate the quality of the AI response"""
        quality_indicators = [
            "sql_query:" in response.lower(),
            "analysis:" in response.lower(),
            "risk" in response.lower(),
            len(response) > 50,  # Reasonable length
            "select" in response.lower(),  # Contains SQL
        ]
        
        return sum(quality_indicators) / len(quality_indicators)
    
    def get_accuracy_metrics(self) -> Dict:
        """Calculate overall accuracy metrics"""
        if not self.evaluation_results:
            return {"message": "No evaluations performed yet"}
        
        sql_similarities = [r["sql_similarity"] for r in self.evaluation_results if r["status"] == "evaluated"]
        response_qualities = [r["response_quality"] for r in self.evaluation_results if r["status"] == "evaluated"]
        
        metrics = {
            "total_evaluations": len(self.evaluation_results),
            "avg_sql_similarity": np.mean(sql_similarities) if sql_similarities else 0,
            "avg_response_quality": np.mean(response_qualities) if response_qualities else 0,
            "high_accuracy_queries": len([r for r in self.evaluation_results if r.get("sql_similarity", 0) > 0.8]),
            "category_breakdown": self._get_category_breakdown()
        }
        
        return metrics
    
    def _get_category_breakdown(self) -> Dict:
        """Get accuracy breakdown by category"""
        categories = {}
        for result in self.evaluation_results:
            if result["status"] == "evaluated":
                cat = result["category"]
                if cat not in categories:
                    categories[cat] = {"count": 0, "avg_similarity": 0, "similarities": []}
                
                categories[cat]["count"] += 1
                categories[cat]["similarities"].append(result["sql_similarity"])
        
        # Calculate averages
        for cat in categories:
            categories[cat]["avg_similarity"] = np.mean(categories[cat]["similarities"])
            del categories[cat]["similarities"]  # Remove raw data
        
        return categories

class SecurityAuditAssistant:
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.df = pd.read_csv(csv_path)
        self.table_name = "audit_data"
        self.policy_content = ""
        self.policy_rules = []
        self.policy_chunks = []
        self.conversation_history = []
        self.evaluator = AccuracyEvaluator()
        self.local_model = None
        self.local_tokenizer = None
        self.local_pipeline = None
        self._init_database()
        
    def _init_database(self):
        """Initialize database connection with thread-safe settings"""
        # Create a new connection each time to avoid threading issues
        self._create_connection()
        
    def _create_connection(self):
        """Create a new SQLite connection"""
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.df.to_sql(self.table_name, self.conn, if_exists='replace', index=False)
    
    def load_policy_document(self, file_path: str, file_type: str):
        """Load and parse security policy documents"""
        try:
            if file_type == "pdf":
                self.policy_content = self._extract_pdf_text(file_path)
            elif file_type == "docx":
                self.policy_content = self._extract_docx_text(file_path)
            elif file_type == "json":
                with open(file_path, 'r') as f:
                    policy_data = json.load(f)
                    self.policy_content = json.dumps(policy_data, indent=2)
            elif file_type == "txt":
                with open(file_path, 'r') as f:
                    self.policy_content = f.read()
            
            self._extract_policy_rules()
            self._create_document_chunks()  # Create chunks for enhanced RAG
            return True
        except Exception as e:
            st.error(f"Error loading policy document: {e}")
            return False
    
    def _extract_pdf_text(self, file_path: str) -> str:
        """Extract text from PDF file"""
        text = ""
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"
        except Exception as e:
            st.error(f"Error reading PDF: {e}")
        return text
    
    def _extract_docx_text(self, file_path: str) -> str:
        """Extract text from DOCX file"""
        text = ""
        try:
            doc = docx.Document(file_path)
            for paragraph in doc.paragraphs:
                text += paragraph.text + "\n"
        except Exception as e:
            st.error(f"Error reading DOCX: {e}")
        return text
    
    def _extract_policy_rules(self):
        """Extract key policy rules from the document"""
        rules = []
        lines = self.policy_content.split('\n')
        
        for line in lines:
            line = line.strip()
            if any(keyword in line.lower() for keyword in [
                'must not', 'shall not', 'prohibited', 'forbidden', 'blocked',
                'must', 'shall', 'required', 'mandatory', 'allowed ports',
                'unauthorized', 'violation', 'compliance', 'policy'
            ]):
                if len(line) > 20:
                    rules.append(line)
        
        self.policy_rules = rules[:20]
    
    def get_audit_schema_context(self) -> str:
        """Get schema information for audit data"""
        schema_info = f"Audit Data Table: {self.table_name}\n"
        schema_info += "Network/Log Columns:\n"
        
        for col in self.df.columns:
            dtype = str(self.df[col].dtype)
            sample_values = self.df[col].dropna().head(3).tolist()
            unique_count = self.df[col].nunique()
            
            schema_info += f"- {col} ({dtype}): {unique_count} unique values, examples: {sample_values}\n"
        
        return schema_info
    
    def execute_sql(self, query: str) -> str:
        """Execute SQL query and return formatted results"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
            columns = [description[0] for description in cursor.description]
            
            if not results:
                return "No results found."
            
            df_result = pd.DataFrame(results, columns=columns)
            
            if len(df_result) > 100:
                return f"**Audit Results (showing first 100 of {len(df_result)} rows):**\n\n{df_result.head(100).to_string(index=False)}"
            else:
                return f"**Audit Results ({len(df_result)} rows):**\n\n{df_result.to_string(index=False)}"
                
        except Exception as e:
            return f"❌ SQL Error: {str(e)}"
    
    def _determine_query_type(self, question: str) -> str:
        """Determine if question is about CSV data, policy, or both"""
        csv_keywords = ['data', 'records', 'connections', 'traffic', 'logs', 'packets', 'ip', 'port', 'bytes', 'count', 'show', 'find', 'list']
        policy_keywords = ['policy', 'rule', 'regulation', 'compliance', 'requirement', 'standard', 'guideline', 'procedure']
        
        question_lower = question.lower()
        csv_score = sum(1 for word in csv_keywords if word in question_lower)
        policy_score = sum(1 for word in policy_keywords if word in question_lower)
        
        if policy_score > csv_score:
            return "policy"
        elif csv_score > 0:
            return "csv"
        else:
            return "both"
    
    def _create_document_chunks(self):
        """Create semantic chunks from the policy document"""
        if not self.policy_content:
            return
        
        # Split into paragraphs and sections
        paragraphs = []
        current_paragraph = ""
        
        for line in self.policy_content.split('\n'):
            line = line.strip()
            if not line:
                if current_paragraph:
                    paragraphs.append(current_paragraph.strip())
                    current_paragraph = ""
            else:
                current_paragraph += " " + line
        
        if current_paragraph:
            paragraphs.append(current_paragraph.strip())
        
        # Create chunks with overlapping context
        chunks = []
        for i, paragraph in enumerate(paragraphs):
            if len(paragraph) > 50:  # Only include substantial paragraphs
                # Add context from previous and next paragraphs
                context_before = paragraphs[i-1] if i > 0 else ""
                context_after = paragraphs[i+1] if i < len(paragraphs)-1 else ""
                
                chunk = {
                    "content": paragraph,
                    "context_before": context_before,
                    "context_after": context_after,
                    "full_context": f"{context_before} {paragraph} {context_after}".strip(),
                    "keywords": self._extract_keywords(paragraph)
                }
                chunks.append(chunk)
        
        self.policy_chunks = chunks
    
    def _extract_keywords(self, text: str) -> set:
        """Extract important keywords from text"""
        # Common security and policy keywords
        important_words = {
            'password', 'access', 'authentication', 'authorization', 'security', 'policy',
            'compliance', 'violation', 'requirement', 'mandatory', 'prohibited', 'allowed',
            'encryption', 'firewall', 'network', 'data', 'confidential', 'audit', 'log',
            'user', 'admin', 'administrator', 'privilege', 'permission', 'role', 'group',
            'port', 'protocol', 'connection', 'remote', 'vpn', 'ssl', 'tls', 'certificate',
            'backup', 'recovery', 'incident', 'breach', 'vulnerability', 'risk', 'threat'
        }
        
        words = set(re.findall(r'\b\w+\b', text.lower()))
        keywords = words.intersection(important_words)
        
        # Add numbers (ports, versions, etc.)
        numbers = set(re.findall(r'\b\d+\b', text))
        keywords.update(numbers)
        
        return keywords
    
    def _calculate_chunk_relevance(self, chunk: dict, question: str) -> float:
        """Calculate relevance score for a chunk based on the question"""
        question_lower = question.lower()
        question_words = set(re.findall(r'\b\w+\b', question_lower))
        question_keywords = question_words.intersection(chunk['keywords'])
        
        # Scoring factors
        scores = []
        
        # 1. Keyword overlap score
        if chunk['keywords']:
            keyword_score = len(question_keywords) / len(chunk['keywords'])
            scores.append(keyword_score * 0.4)
        
        # 2. Direct text similarity
        chunk_text = chunk['content'].lower()
        text_score = 0
        for word in question_words:
            if word in chunk_text:
                text_score += 1
        if question_words:
            text_score = text_score / len(question_words)
            scores.append(text_score * 0.3)
        
        # 3. Phrase matching
        question_phrases = [question_lower[i:i+20] for i in range(0, len(question_lower)-19, 5)]
        phrase_score = 0
        for phrase in question_phrases:
            if phrase in chunk_text:
                phrase_score += 1
        if question_phrases:
            phrase_score = phrase_score / len(question_phrases)
            scores.append(phrase_score * 0.3)
        
        return sum(scores) if scores else 0
    
    def _search_policy_content(self, question: str) -> str:
        """Enhanced RAG search through policy content with semantic chunking"""
        if not self.policy_content:
            return "No policy document loaded."
        
        # Create chunks if not already done
        if not self.policy_chunks:
            self._create_document_chunks()
        
        if not self.policy_chunks:
            return "No meaningful content found in policy document."
        
        # Calculate relevance scores for all chunks
        chunk_scores = []
        for chunk in self.policy_chunks:
            score = self._calculate_chunk_relevance(chunk, question)
            if score > 0:
                chunk_scores.append((score, chunk))
        
        # Sort by relevance score
        chunk_scores.sort(key=lambda x: x[0], reverse=True)
        
        if not chunk_scores:
            # Fallback: simple keyword search
            question_words = set(question.lower().split())
            fallback_content = []
            for chunk in self.policy_chunks:
                chunk_words = set(chunk['content'].lower().split())
                if len(question_words.intersection(chunk_words)) > 0:
                    fallback_content.append(chunk['content'])
            
            if fallback_content:
                return "\n\n".join(fallback_content[:3])
            else:
                return "No relevant policy information found for this question."
        
        # Return top relevant chunks with context
        relevant_content = []
        for score, chunk in chunk_scores[:3]:  # Top 3 most relevant chunks
            content_with_context = f"**Relevance Score: {score:.2f}**\n{chunk['full_context']}"
            relevant_content.append(content_with_context)
        
        return "\n\n---\n\n".join(relevant_content)
    
    def load_local_model(self, model_name: str = "ZySec-AI/SecurityLLM") -> bool:
        """Load local Hugging Face model for inference"""
        try:
            st.info(f"🔄 Loading local model: {model_name}")
            
            # Check if CUDA is available
            device = "cuda" if torch.cuda.is_available() else "cpu"
            st.info(f"🖥️ Using device: {device}")
            
            # Load tokenizer and model
            with st.spinner("Loading tokenizer..."):
                self.local_tokenizer = AutoTokenizer.from_pretrained(model_name)
                
            with st.spinner("Loading model (this may take a few minutes)..."):
                self.local_model = AutoModelForCausalLM.from_pretrained(
                    model_name,
                    torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                    device_map="auto" if device == "cuda" else None,
                    trust_remote_code=True
                )
                
            # Create pipeline
            self.local_pipeline = pipeline(
                "text-generation",
                model=self.local_model,
                tokenizer=self.local_tokenizer,
                device=0 if device == "cuda" else -1,
                torch_dtype=torch.float16 if device == "cuda" else torch.float32
            )
            
            st.success(f"✅ Local model {model_name} loaded successfully!")
            return True
            
        except Exception as e:
            st.error(f"❌ Error loading local model: {e}")
            return False
    
    def analyze_with_local_llm(self, question: str, evaluate: bool = False, force_mode: str = None) -> Tuple[str, Optional[Dict]]:
        """Use local Hugging Face model for security analysis"""
        try:
            if self.local_pipeline is None:
                return "❌ Local model not loaded. Please load a model first.", None
            
            # Add conversation history for context
            conversation_context = ""
            if self.conversation_history:
                recent_history = self.conversation_history[-2:]  # Last 2 exchanges for local model
                conversation_context = "RECENT CONVERSATION:\n" + "\n".join([
                    f"Q: {item['question']}\nA: {item['response'][:150]}..." 
                    for item in recent_history
                ]) + "\n\n"
            
            schema_context = self.get_audit_schema_context()
            
            # Override query type based on force_mode if provided
            if force_mode == "policy":
                query_type = "policy"
            elif force_mode == "csv":
                query_type = "csv"
            else:
                query_type = self._determine_query_type(question)
            
            if query_type == "policy":
                # Policy-focused question
                relevant_policy = self._search_policy_content(question)
                prompt = f"""You are a security auditor assistant. Answer questions about security policies.

{conversation_context}SECURITY POLICY CONTENT:
{relevant_policy[:1000]}

QUESTION: "{question}"

Provide a comprehensive answer about the security policy.

Response:"""
            
            elif query_type == "csv":
                # Data-focused question
                prompt = f"""You are a security auditor assistant analyzing network traffic and log data.

{conversation_context}AUDIT DATA SCHEMA:
{schema_context[:800]}

QUESTION: "{question}"

Generate a SQL query to analyze the audit data and provide security analysis.

Response format:
SQL_QUERY: [your SQL query here]
ANALYSIS: [security analysis of what the query reveals]
RISK_LEVEL: [LOW/MEDIUM/HIGH]

Rules:
1. Use table name '{self.table_name}'
2. Use SQLite syntax
3. Limit results appropriately

Response:"""
            
            else:
                # Both policy and data question
                relevant_policy = self._search_policy_content(question)
                prompt = f"""You are a security auditor assistant with access to both security policies and network audit data.

{conversation_context}SECURITY POLICY CONTENT:
{relevant_policy[:600]}

AUDIT DATA SCHEMA:
{schema_context[:600]}

QUESTION: "{question}"

Provide a comprehensive response that:
1. References relevant policy requirements
2. Generates SQL query to check compliance in the data
3. Provides security analysis

Response format:
POLICY_REFERENCE: [relevant policy information]
SQL_QUERY: [SQL query to check compliance]
ANALYSIS: [security analysis combining policy and data insights]
RISK_LEVEL: [LOW/MEDIUM/HIGH]

Response:"""

            # Generate response using local model
            messages = [{"role": "user", "content": prompt}]
            
            # Use the pipeline for generation
            response = self.local_pipeline(
                messages,
                max_new_tokens=512,
                temperature=0.1,
                do_sample=True,
                pad_token_id=self.local_tokenizer.eos_token_id
            )
            
            # Extract the generated text
            if isinstance(response, list) and len(response) > 0:
                ai_response = response[0]['generated_text']
                # Remove the input prompt from the response
                if isinstance(ai_response, list) and len(ai_response) > 1:
                    ai_response = ai_response[-1]['content']
                elif isinstance(ai_response, str):
                    # Find where the actual response starts
                    if "Response:" in ai_response:
                        ai_response = ai_response.split("Response:")[-1].strip()
                    else:
                        # Fallback: take everything after the prompt
                        ai_response = ai_response[len(prompt):].strip()
            else:
                ai_response = "Error: No response generated"
            
            # Store in conversation history
            self.conversation_history.append({
                "question": question,
                "response": ai_response,
                "query_type": query_type
            })
            
            # Keep only last 10 conversations
            if len(self.conversation_history) > 10:
                self.conversation_history = self.conversation_history[-10:]
            
            evaluation_result = None
            if evaluate and query_type in ["csv", "both"]:
                # Extract SQL query for evaluation
                generated_sql = self._extract_sql_from_response(ai_response)
                evaluation_result = self.evaluator.evaluate_response(question, generated_sql, ai_response)
            
            return ai_response, evaluation_result
            
        except Exception as e:
            return f"❌ Error with local model inference: {e}", None
    
    def analyze_with_openrouter(self, question: str, api_key: str, model: str = "anthropic/claude-3.5-sonnet", evaluate: bool = False, force_mode: str = None) -> Tuple[str, Optional[Dict]]:
        """Use OpenRouter API for seamless security analysis - handles both CSV and policy questions"""
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            # Add conversation history for context
            conversation_context = ""
            if self.conversation_history:
                recent_history = self.conversation_history[-3:]  # Last 3 exchanges
                conversation_context = "RECENT CONVERSATION:\n" + "\n".join([
                    f"Q: {item['question']}\nA: {item['response'][:200]}..." 
                    for item in recent_history
                ]) + "\n\n"
            
            schema_context = self.get_audit_schema_context()
            policy_context = f"Security Policy Content:\n{self.policy_content[:2000]}..." if self.policy_content else "No policy loaded."
            
            # Override query type based on force_mode if provided
            if force_mode == "policy":
                query_type = "policy"
            elif force_mode == "csv":
                query_type = "csv"
            else:
                query_type = self._determine_query_type(question)
            
            if query_type == "policy":
                # Policy-focused question
                relevant_policy = self._search_policy_content(question)
                prompt = f"""
You are a security auditor assistant. The user is asking about security policies.

{conversation_context}SECURITY POLICY CONTENT:
{relevant_policy}

FULL POLICY RULES:
{chr(10).join(self.policy_rules[:5])}

QUESTION: "{question}"

Provide a comprehensive answer about the security policy. If the question relates to compliance checking against data, mention that data analysis would be needed.

Response:"""
            
            elif query_type == "csv":
                # Data-focused question
                prompt = f"""
You are a security auditor assistant analyzing network traffic and log data.

{conversation_context}AUDIT DATA SCHEMA:
{schema_context}

QUESTION: "{question}"

Generate a SQL query to analyze the audit data and provide security analysis.

Response format:
SQL_QUERY: [your SQL query here]
ANALYSIS: [security analysis of what the query reveals]
RISK_LEVEL: [LOW/MEDIUM/HIGH]

Rules:
1. Use table name '{self.table_name}'
2. Use SQLite syntax
3. Limit results appropriately
"""
            
            else:
                # Both policy and data question
                relevant_policy = self._search_policy_content(question)
                prompt = f"""
You are a security auditor assistant with access to both security policies and network audit data.

{conversation_context}SECURITY POLICY CONTENT:
{relevant_policy}

AUDIT DATA SCHEMA:
{schema_context}

QUESTION: "{question}"

Provide a comprehensive response that:
1. References relevant policy requirements
2. Generates SQL query to check compliance in the data
3. Provides security analysis

Response format:
POLICY_REFERENCE: [relevant policy information]
SQL_QUERY: [SQL query to check compliance]
ANALYSIS: [security analysis combining policy and data insights]
RISK_LEVEL: [LOW/MEDIUM/HIGH]
"""

            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 800,
                "temperature": 0.1
            }
            
            response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload)
            
            if response.status_code == 200:
                result = response.json()
                ai_response = result['choices'][0]['message']['content']
                
                # Store in conversation history
                self.conversation_history.append({
                    "question": question,
                    "response": ai_response,
                    "query_type": query_type
                })
                
                # Keep only last 10 conversations
                if len(self.conversation_history) > 10:
                    self.conversation_history = self.conversation_history[-10:]
                
                evaluation_result = None
                if evaluate and query_type in ["csv", "both"]:
                    # Extract SQL query for evaluation
                    generated_sql = self._extract_sql_from_response(ai_response)
                    evaluation_result = self.evaluator.evaluate_response(question, generated_sql, ai_response)
                
                return ai_response, evaluation_result
            else:
                return f"API Error: {response.status_code} - {response.text}", None
                
        except Exception as e:
            return f"Error calling OpenRouter API: {e}", None
    
    def _extract_sql_from_response(self, response: str) -> str:
        """Extract SQL query from AI response"""
        if "SQL_QUERY:" in response:
            sql_part = response.split("SQL_QUERY:")[1].split("ANALYSIS:")[0].strip()
            sql_query = sql_part.replace("```sql", "").replace("```", "").strip()
            return sql_query
        elif "SELECT" in response.upper():
            # Try to extract SELECT statement
            lines = response.split('\n')
            for line in lines:
                if line.strip().upper().startswith("SELECT"):
                    return line.strip()
        return ""
    
    def run_accuracy_test(self, api_key: str, model: str) -> Dict:
        """Run accuracy test on all ground truth questions"""
        results = []
        
        for gt in self.evaluator.ground_truth_qa:
            question = gt["question"]
            ai_response, eval_result = self.analyze_with_openrouter(question, api_key, model, evaluate=True)
            results.append({
                "question": question,
                "category": gt["category"],
                "evaluation": eval_result,
                "ai_response": ai_response
            })
        
        return {
            "test_results": results,
            "metrics": self.evaluator.get_accuracy_metrics()
        }

def main():
    st.set_page_config(page_title="SACA SQL RAG", layout="wide")
    st.title("🛡️ SACA - Security Audit Compliance Assistant with SQL Query and RAG")
    st.markdown("**Analyze network traffic and logs with security policies in mind**")
    
    # Get API key from environment variable
    api_key = os.getenv("OPENROUTER_API_KEY")
    
    # Sidebar configuration
    with st.sidebar:
        st.header("🔧 Configuration")
        
        # Model Type Selection
        model_type = st.radio(
            "🤖 Model Type",
            ["🌐 Online API Models", "💻 Local Hugging Face Models"],
            help="Choose between online API models or local models"
        )
        
        if model_type == "🌐 Online API Models":
            # API Key status (hidden input)
            if api_key:
                st.success("✅ AI Model Ready")
            else:
                st.error("❌ AI Model not configured")
                st.info("💡 Create a .env file with: OPENROUTER_API_KEY=your_key_here")
            
            # Model selection with free models highlighted
            model_choice = st.selectbox("🤖 AI Model", [
                # Free models (highlighted)
                "🆓 qwen/qwen-2.5-72b-instruct",
                "🆓 meta-llama/llama-3.1-8b-instruct:free", 
                "🆓 deepseek/deepseek-chat",
                "🆓 google/gemma-2-9b-it:free",
                "🆓 mistralai/mistral-7b-instruct:free",
                "🆓 microsoft/wizardlm-2-8x22b",
                # Premium models
                "💳 anthropic/claude-3.5-sonnet",
                "💳 openai/gpt-4o",
                "💳 openai/gpt-4",
                "💳 openai/gpt-3.5-turbo",
                "💳 google/gemini-pro"
            ])
            
            # Clean model name for API call
            clean_model = model_choice.split(" ", 1)[1] if " " in model_choice else model_choice
            
            # Show model info
            if model_choice.startswith("🆓"):
                st.info("💰 Free model selected - no cost!")
            else:
                st.warning("💳 Premium model - usage costs apply")
        
        else:
            # Local Model Configuration
            st.info("💻 Local Model Mode - No API key required!")
            
            # Local model selection
            local_model_name = st.selectbox("🤖 Local Model", [
                "ZySec-AI/SecurityLLM",
                "microsoft/DialoGPT-medium",
                "microsoft/DialoGPT-large",
                "facebook/blenderbot-400M-distill",
                "facebook/blenderbot-1B-distill",
                "Custom Model (enter below)"
            ])
            
            if local_model_name == "Custom Model (enter below)":
                local_model_name = st.text_input("Enter Hugging Face model name:", "ZySec-AI/SecurityLLM")
            
            # Model loading section
            if 'assistant' in st.session_state:
                assistant = st.session_state.assistant
                
                if assistant.local_pipeline is None:
                    st.warning("⚠️ Local model not loaded")
                    if st.button("🔄 Load Local Model"):
                        st.session_state.load_local_model = True
                else:
                    st.success("✅ Local model loaded and ready!")
                    if st.button("🗑️ Unload Model"):
                        assistant.local_model = None
                        assistant.local_tokenizer = None
                        assistant.local_pipeline = None
                        st.success("Model unloaded successfully!")
                        st.rerun()
            
            # Show system info
            if torch.cuda.is_available():
                st.info(f"🖥️ CUDA Available: {torch.cuda.get_device_name(0)}")
            else:
                st.info("🖥️ Using CPU (CUDA not available)")
        
        st.header("📁 Upload Files")
        audit_file = st.file_uploader("Upload CSV audit data", type=['csv'])
        policy_file = st.file_uploader("Upload security policy", type=['pdf', 'docx', 'txt', 'json'])
        
        # Accuracy Testing Section
        st.header("🎯 Accuracy Testing")
        if st.button("Run Accuracy Test") and api_key and audit_file:
            st.session_state.run_accuracy_test = True
        
        if st.button("Show Ground Truth"):
            st.session_state.show_ground_truth = True
        
        # Chat Control Section
        st.header("💬 Chat Controls")
        if st.button("🔄 Reset Chat Interface"):
            # Clear any problematic session state
            if hasattr(st.session_state, 'test_query'):
                delattr(st.session_state, 'test_query')
            st.rerun()
        
        if st.button("🗑️ Clear Chat History"):
            st.session_state.messages = []
            st.rerun()
    
    # Initialize assistant if files are uploaded
    if audit_file and policy_file:
        audit_path = f"./temp/{audit_file.name}"
        policy_path = f"./temp/{policy_file.name}"
        
        with open(audit_path, "wb") as f:
            f.write(audit_file.getvalue())
        with open(policy_path, "wb") as f:
            f.write(policy_file.getvalue())
        
        if 'assistant' not in st.session_state or st.session_state.get('current_audit_file') != audit_file.name:
            st.session_state.assistant = SecurityAuditAssistant(audit_path)
            st.session_state.current_audit_file = audit_file.name
            st.session_state.messages = []
            
            file_ext = policy_file.name.split('.')[-1].lower()
            policy_loaded = st.session_state.assistant.load_policy_document(policy_path, file_ext)
            
            if policy_loaded:
                st.success(f"✅ Policy loaded: {len(st.session_state.assistant.policy_rules)} rules extracted")
        
        assistant = st.session_state.assistant
        
        # Handle local model loading
        if hasattr(st.session_state, 'load_local_model') and st.session_state.load_local_model:
            success = assistant.load_local_model(local_model_name)
            if success:
                st.success("Local model loaded successfully!")
            del st.session_state.load_local_model
            st.rerun()
        
        # Show Ground Truth
        if hasattr(st.session_state, 'show_ground_truth') and st.session_state.show_ground_truth:
            st.subheader("📋 Ground Truth Question-Answer Pairs")
            for i, gt in enumerate(assistant.evaluator.ground_truth_qa, 1):
                with st.expander(f"{i}. {gt['category'].replace('_', ' ').title()}"):
                    st.write(f"**Question:** {gt['question']}")
                    st.write(f"**Expected SQL:**")
                    st.code(gt['expected_sql'], language='sql')
                    st.write(f"**Description:** {gt['description']}")
            del st.session_state.show_ground_truth
        
        # Run Accuracy Test
        if hasattr(st.session_state, 'run_accuracy_test') and st.session_state.run_accuracy_test:
            st.subheader("🧪 Accuracy Test Results")
            
            with st.spinner("Running accuracy test on all ground truth questions..."):
                test_results = assistant.run_accuracy_test(api_key, model_choice)
            
            # Display metrics
            metrics = test_results["metrics"]
            
            # Check if metrics has the expected structure
            if "message" in metrics:
                st.warning(f"⚠️ {metrics['message']}")
            else:
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Total Tests", metrics.get("total_evaluations", 0))
                with col2:
                    st.metric("Avg SQL Similarity", f"{metrics.get('avg_sql_similarity', 0):.2f}")
                with col3:
                    st.metric("Avg Response Quality", f"{metrics.get('avg_response_quality', 0):.2f}")
                with col4:
                    st.metric("High Accuracy (>80%)", metrics.get("high_accuracy_queries", 0))
            
            # Category breakdown
            st.subheader("📊 Accuracy by Category")
            category_data = []
            for cat, data in metrics["category_breakdown"].items():
                category_data.append({
                    "Category": cat.replace('_', ' ').title(),
                    "Count": data["count"],
                    "Avg Similarity": f"{data['avg_similarity']:.2f}"
                })
            
            if category_data:
                st.dataframe(pd.DataFrame(category_data))
            
            # Detailed results
            st.subheader("🔍 Detailed Test Results")
            for result in test_results["test_results"]:
                eval_data = result["evaluation"]
                if eval_data and eval_data["status"] == "evaluated":
                    with st.expander(f"{result['category'].replace('_', ' ').title()} - Similarity: {eval_data['sql_similarity']:.2f}"):
                        st.write(f"**Question:** {eval_data['question']}")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write("**Generated SQL:**")
                            st.code(eval_data['generated_sql'], language='sql')
                        with col2:
                            st.write("**Expected SQL:**")
                            st.code(eval_data['expected_sql'], language='sql')
                        
                        st.write(f"**SQL Similarity Score:** {eval_data['sql_similarity']:.2f}")
                        st.write(f"**Response Quality Score:** {eval_data['response_quality']:.2f}")
            
            del st.session_state.run_accuracy_test
        
        # Chat interface
        st.subheader("💬 Security Analysis Chat")
        
        # Chat mode selection
        st.markdown("**🎯 Choose Your Analysis Mode:**")
        chat_mode = st.radio(
            "Select what you want to analyze:",
            ["📊 Audit Data (SQL Queries)", "📋 Security Policy (Document Search)", "🔄 Auto-Detect"],
            horizontal=True,
            help="Choose whether to analyze audit data with SQL, search policy documents, or let the system auto-detect"
        )
        
        # Quick test buttons (only show for audit data mode)
        if chat_mode in ["📊 Audit Data (SQL Queries)", "🔄 Auto-Detect"]:
            st.markdown("**🚀 Quick Security Tests:**")
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("🔍 Unauthorized Ports", key="test_ports"):
                    st.session_state.test_query = "Find connections to unauthorized ports (not 80, 443, 22, 53)"
            with col2:
                if st.button("🚫 Failed Connections", key="test_failed"):
                    st.session_state.test_query = "Show sources with high failed connection attempts"
            with col3:
                if st.button("📈 High Volume Traffic", key="test_volume"):
                    st.session_state.test_query = "Identify sources generating high volume traffic"
        
        # Initialize chat history
        if "messages" not in st.session_state:
            st.session_state.messages = []
        
        # Display chat messages
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        
        # Handle test query if button was clicked
        if hasattr(st.session_state, 'test_query'):
            prompt = st.session_state.test_query
            delattr(st.session_state, 'test_query')
        else:
            prompt = st.chat_input("Chat with your documents: audit data or policy ...")
        
        # Check if we can process the prompt (either API key for online models or local model loaded)
        can_process = (model_type == "🌐 Online API Models" and api_key) or (model_type == "💻 Local Hugging Face Models" and assistant.local_pipeline is not None)
        
        if prompt:
            if not can_process:
                if model_type == "🌐 Online API Models":
                    st.error("❌ Please configure your OpenRouter API key in the .env file to use online models.")
                else:
                    st.error("❌ Please load a local model first before chatting.")
                return
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
            
            with st.chat_message("assistant"):
                with st.spinner("Analyzing..."):
                    # Determine force_mode based on user selection
                    force_mode = None
                    if chat_mode == "📊 Audit Data (SQL Queries)":
                        force_mode = "csv"
                    elif chat_mode == "📋 Security Policy (Document Search)":
                        force_mode = "policy"
                    # Auto-Detect mode uses force_mode = None
                    
                    # Use appropriate model based on selection
                    if model_type == "💻 Local Hugging Face Models":
                        ai_response, eval_result = assistant.analyze_with_local_llm(prompt, evaluate=True, force_mode=force_mode)
                    else:
                        ai_response, eval_result = assistant.analyze_with_openrouter(prompt, api_key, clean_model, evaluate=True, force_mode=force_mode)
                    
                    # Extract and execute SQL automatically
                    generated_sql = assistant._extract_sql_from_response(ai_response)
                    
                    if generated_sql and generated_sql.upper().startswith("SELECT"):
                        # Show the generated query
                        st.markdown(f"**🔍 Generated SQL Query:**\n```sql\n{generated_sql}\n```")
                        
                        # Execute the query automatically
                        with st.spinner("Executing query against audit data..."):
                            sql_result = assistant.execute_sql(generated_sql)
                        
                        # Display results in a more readable format
                        st.markdown("### 📊 Query Results")
                        if "No results found" not in sql_result:
                            # Try to parse and display as a proper table
                            try:
                                # Extract the dataframe part from the result
                                if "**Audit Results" in sql_result:
                                    table_part = sql_result.split("**Audit Results")[1].split(":**")[1].strip()
                                    # Convert string table back to dataframe for better display
                                    lines = table_part.split('\n')
                                    if len(lines) > 1:
                                        # Display as streamlit dataframe for better formatting
                                        st.text(sql_result)
                                        st.success(f"✅ Query executed successfully")
                                    else:
                                        st.markdown(sql_result)
                                else:
                                    st.markdown(sql_result)
                            except:
                                st.markdown(sql_result)
                        else:
                            st.warning("⚠️ No matching records found in the audit data")
                        
                        # Show evaluation if available
                        if eval_result and eval_result["status"] == "evaluated":
                            st.markdown("### 🎯 Accuracy Evaluation")
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("SQL Similarity", f"{eval_result['sql_similarity']:.2f}")
                            with col2:
                                st.metric("Response Quality", f"{eval_result['response_quality']:.2f}")
                        
                        # Show security analysis
                        if "ANALYSIS:" in ai_response:
                            analysis_part = ai_response.split("ANALYSIS:")[1].split("RISK_LEVEL:")[0].strip()
                            st.markdown("### 🔒 Security Analysis")
                            st.markdown(analysis_part)
                        
                        # Show risk assessment
                        if "RISK_LEVEL:" in ai_response:
                            risk_part = ai_response.split("RISK_LEVEL:")[1].strip()
                            risk_color = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk_part.upper(), "⚪")
                            st.markdown("### ⚠️ Risk Assessment")
                            st.markdown(f"**Risk Level:** {risk_color} **{risk_part}**")
                        
                        response = f"Query executed: {generated_sql}\nResults: {sql_result}"
                    
                    elif "SELECT" in ai_response.upper():
                        # Try to extract any SELECT statement from the response
                        lines = ai_response.split('\n')
                        for line in lines:
                            if line.strip().upper().startswith("SELECT"):
                                sql_query = line.strip()
                                st.markdown(f"**🔍 Detected SQL Query:**\n```sql\n{sql_query}\n```")
                                
                                with st.spinner("Executing query..."):
                                    sql_result = assistant.execute_sql(sql_query)
                                
                                st.markdown("### 📊 Query Results")
                                st.markdown(sql_result)
                                
                                response = f"Query executed: {sql_query}\nResults: {sql_result}"
                                break
                        else:
                            # No valid SQL found, show the AI response as is
                            st.markdown("### 🤖 AI Response")
                            st.markdown(ai_response)
                            response = ai_response
                    else:
                        # No SQL query detected, show the response
                        st.markdown("### 🤖 AI Response")
                        st.markdown(ai_response)
                        response = ai_response
            
            st.session_state.messages.append({"role": "assistant", "content": response})
    
    else:
        st.info("👆 Please upload both audit data (CSV) and security policy document to begin")
        
        st.markdown("""
     
        ### 📊 Evaluation Categories
        - Unauthorized Access Detection
        - Failed Connection Analysis  
        - High Volume Traffic Identification
        - Suspicious Protocol Detection
        - Backdoor Connection Discovery
        - Security Violation Summarization

        ### 🎯 New Features: Accuracy Testing
        """)

if __name__ == "__main__":
    main()
