# Chatbot Backend

This is a simple chatbot backend using FastAPI and OpenAI's GPT model. It allows you to send questions to the OpenAI model and receive answers.

## Requirements

- Python 3.8 or later

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/yourusername/chatbot_backend.git
   cd chatbot_backend

   # PrivAware: Multilayered Privacy-Enforcement LLM Framework

## What It Does
Controls what information a healthcare LLM can share based on who is asking. A doctor sees everything, a billing clerk sees only billing codes — enforced at the attention level, not just output filtering.

## Approach
- **Self-Attention Masking** on Flan-T5 — unauthorized tokens set to -infinity before softmax, making them invisible to the model's reasoning
- **RAG-based policy retrieval** — FAISS index stores role-specific access control rules
- **Reactive validation** — secondary LLM-based check on generated output
- **RLHF with PPO** — reward model scores both privacy compliance AND helpfulness jointly

## Key Results
- **3.91% privacy leakage** (down from 15% with output filtering)
- **90.13% role-compliant accuracy**

## Tech Stack
Python, PyTorch, HuggingFace Transformers, Flan-T5, FAISS, RLHF/PPO

## Repo Structure
- `core/` — Attention masking and model logic
- `api/` — API endpoints
- `services/` — RAG retrieval and validation services
- `models/` — Model configurations
- `db/` — Database and access control
- `results/` — Evaluation outputs
