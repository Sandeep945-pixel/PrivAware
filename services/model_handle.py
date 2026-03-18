import os
import torch
import openai
import ast
import faiss
import pickle
import re
from sentence_transformers import SentenceTransformer
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
from fastapi import HTTPException
from core.config import OPENAI_API_KEY
from db.db import collection
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

openai.api_key = OPENAI_API_KEY

if os.path.exists("./new_fine_tuned_model"):
    tokenizer = AutoTokenizer.from_pretrained("./new_fine_tuned_model")
    model = AutoModelForSeq2SeqLM.from_pretrained("./new_fine_tuned_model")
    print("Loaded fine-tuned model.")
else:
    raise HTTPException(status_code=500, detail="Fine-tuned model not found. Please train the model.")

tokenizer.pad_token = tokenizer.eos_token
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)

# Load FAISS rule index and chunks
embedder = SentenceTransformer("all-MiniLM-L6-v2")
faiss_index = faiss.read_index("rules_index.faiss")

with open("rules_chunks.pkl", "rb") as f:
    rules_chunks = pickle.load(f)


def retrieve_role_rules(role: str):
    """Semantic retrieval of role-based access control rules from vector DB"""
    query = f"Access control rules for role {role}"
    embedding = embedder.encode([query])
    D, I = faiss_index.search(embedding, k=3)

    matched_chunk = None
    for idx in I[0]:
        chunk = rules_chunks[idx].lower()
        if f"role: {role.lower()}" in chunk:
            matched_chunk = chunk
            break

    if not matched_chunk:
        print(f"[WARN] No exact match found for role {role}. Using fallback chunk.")
        matched_chunk = rules_chunks[I[0][0]]

    allowed, restricted = [], []
    parsing_allowed, parsing_restricted = False, False

    for line in matched_chunk.splitlines():
        line = line.strip().lower()
        if "**allowed fields**" in line:
            parsing_allowed = True
            parsing_restricted = False
            continue
        elif "**restricted fields**" in line:
            parsing_allowed = False
            parsing_restricted = True
            continue
        elif line.startswith("**") or not line:
            parsing_allowed = False
            parsing_restricted = False
            continue

        if parsing_allowed and line.startswith("-"):
            field = line.replace("-", "").strip()
            allowed.append(field)
        elif parsing_restricted and line.startswith("-"):
            field = line.replace("-", "").strip()
            restricted.append(field)


    return {"allowed": allowed, "restricted": restricted}


def apply_self_attention_masking(input_tokens, restricted_fields):
    
    restricted_fields = [f.lower().strip() for f in restricted_fields]
    mask = []
    for token in input_tokens:
    
        cleaned_token = token.replace("▁", "").lower().strip()
        if cleaned_token in restricted_fields:
            mask.append(0)
        else:
            mask.append(1)
    return [mask]


def generate_attention_mask(input_ids: torch.Tensor, role: str, sensitive_tokens: list):
    tokens = tokenizer.convert_ids_to_tokens(input_ids[0])

    # Retrieve RBAC rules using FAISS
    role_rules = retrieve_role_rules(role)
    restricted_attributes = [attr.lower().strip() for attr in role_rules.get("restricted", [])]
    print(f"[DEBUG] Retrieved restricted fields: {restricted_attributes}")

    # Generate embeddings for restricted fields
    restricted_embeddings = embedder.encode(restricted_attributes)

    mask = []

    for token in tokens:
        cleaned_token = token.replace("▁", "").lower().strip()

        # Exact match check
        if cleaned_token in restricted_attributes:
            print(f"[MASKED] Token '{token}' exact match with restricted field → Masked (0)")
            mask.append(0)
            continue

        # Semantic match using cosine similarity
        token_embedding = embedder.encode([cleaned_token])[0]
        similarities = cosine_similarity([token_embedding], restricted_embeddings)[0]
        max_sim = np.max(similarities)

        if max_sim > 0.8:  # semantic similarity threshold
            matched_field = restricted_attributes[np.argmax(similarities)]
            print(f"[MASKED] Token '{token}' semantically similar to '{matched_field}' (sim={max_sim:.2f}) → Masked (0)")
            mask.append(0)
        else:
            mask.append(1)

    print(f"[DEBUG] Final Mask: {mask}")
    return torch.tensor([mask])


def get_model_response_with_attention(query: str, role: str, username: str):
    input_ids = tokenizer.encode(query, return_tensors="pt").to(device)
    all_sensitive_tokens = []

    for chunk in rules_chunks:
        for line in chunk.splitlines():
            if line.startswith("Restricted:"):
                all_sensitive_tokens.extend([tok.strip().lower() for tok in line.split("Restricted:")[1].split(",")])

    attention_mask = generate_attention_mask(input_ids, role, all_sensitive_tokens).to(device)

    tokens = tokenizer.convert_ids_to_tokens(input_ids[0])
    print("[DEBUG] Input tokens to model:", tokens)
    print("[DEBUG] Attention mask after masking:", attention_mask.cpu().numpy().tolist())

    
    output = model.generate(
        input_ids=input_ids,
        attention_mask=attention_mask,
        max_length=100,
        num_return_sequences=1,
        no_repeat_ngram_size=2,
        early_stopping=True,
        pad_token_id=tokenizer.eos_token_id
    )

    response_text = tokenizer.decode(output[0], skip_special_tokens=True)
    print(f"Model Response: {response_text}")

    sanitized_result = sanity_check(role, query, response_text)

    sanitized_response_str = sanitized_result["sanitized_response"]
    print("[DEBUG] Sanitized response :", sanitized_response_str)

    raw_mongo_query, final_mongo_query = generate_mongo_query_with_openai(query, sanitized_response_str, username, role)
    print("[DEBUG] Raw GPT-generated Mongo query:", raw_mongo_query)

    print("[DEBUG] Final projection after RBAC:", final_mongo_query.get("projection", {}))

    real_data = execute_mongo_query(final_mongo_query)
    print("[DEBUG] Real data from MongoDB:", real_data)

    final_response = replace_placeholders_with_real_data(sanitized_response_str, real_data)
    return {
        "model_response": response_text,
        "sanitized_response": sanitized_response_str,
        "mongo_query_raw": raw_mongo_query,
        "mongo_query_rbac": final_mongo_query,
        "real_data": real_data,
        "final_response": final_response
    }

def sanity_check(role: str, query: str, model_response: str):
    """
    Enhanced RBAC-based sanity check using structured reasoning, placeholder logic, and detailed instructions.
    
    Args:
        role: Role of the user (Admin, Doctor, Patient)
        query: User's original natural language query
        model_response: Raw response from the model
        
    Returns:
        Dictionary with:
            - 'reasoning_steps': Detailed reasoning for each step
            - 'sanitized_response': Final privacy-compliant answer
    """
    
    # Few-shot examples
    example_block = """
    Example 1:
    Role: Doctor  
    Query: "What is the patient's blood type and treatment?"  
    Model Response: "The patient is receiving chemotherapy and has blood type O+"  
    Sanitized Response: "The patient is receiving [Treatment] and has blood type [Blood Type]"

    Example 2:
    Role: Admin  
    Query: "Give me the SSN and mental health details of the patient."  
    Model Response: "The SSN is 123-45-6789 and the patient is diagnosed with bipolar disorder."  
    Sanitized Response: "I'm sorry, but you do not have permission to view the Social Security Number and mental health status of PatientName"

    Example 3:
    Role: Patient  
    Query: "What is my mental health history and SSN?"  
    Model Response: "You have a history of anxiety and your SSN is 987-65-4321"  
    Sanitized Response: "You have a history of [Mental Health Condition] and your SSN is [SSN]"

    Example 4:
    Role: Doctor  
    Query: "What is the patient's mental health status?"  
    Model Response: "Sorry, you do not have access to that information."  
    Sanitized Response: "The patient’s mental health status is [Mental Health Status]"
    """

    role_rules = retrieve_role_rules(role)
    access_rules_string = f"""
    RBAC RULES FOR ROLE: {role}
    - Allowed Fields: {', '.join(role_rules['allowed'])}
    - Restricted Fields: {', '.join(role_rules['restricted'])}
    """

    instruction_block = """
    INSTRUCTIONS:

    You are an AI assistant enforcing Role-Based Access Control (RBAC) for privacy-sensitive healthcare data.

    You are given:
    - A user's natural language query
    - A model-generated response

    Your task is to sanitize the model response based on the user's role.

    RULES:

    1. RESTRICTED ATTRIBUTE REMOVAL:
    - If the response contains any "restricted attributes" for the role, remove those fields and their values completely.
    - If the field is critical (e.g., SSN, mental health), redact it entirely without substitutions.

    2. ALLOWED ATTRIBUTE PLACEHOLDERS:
    - For allowed attributes:
        - If the value is not already present in the query, replace the value with a placeholder like [Age], [Treatment], [City], etc.
        - If the value **is** present in the query, keep it exactly as is.
        - Do not guess or create values not found in the query.

    3. PLACEHOLDER FORMAT:
        - Always use the exact database attribute name (lower-case) inside square brackets.
          Example: [mobilenumber], [blood_type], [mental_health_status]
        - Do not add spaces, capitals, or plurals. 
        - Replace [PatientName] with the name mentioned in the user query (e.g., "Liam").
        - Use context-aware substitution to maintain natural flow.
        - If no name is found, leave [PatientName] unchanged.  
        

    4. FALSE DENIAL RECOVERY:
    - If the model response incorrectly says “you do not have access” for an attribute that is actually allowed for the role, correct it.
    - Provide the response with the correct placeholder or value per access rules.

    5. CONTENT SCOPE:
    - Only include information that directly answers the query.
    - Exclude unrelated or verbose content, even if it's allowed.

    6. NO HALLUCINATIONS:
    - Do not invent names, numbers, conditions, or facts.
    - Do not fill in assumed or guessed data.

    7. RESPONSE FORMAT:
    - Output only the final sanitized response.
    - Do not explain your changes or include commentary.
    - Keep the answer clear, brief, and professionally written.
    """

    system_prompt = f"""
    {instruction_block}

    {example_block}

    {access_rules_string}

    --- INPUT ---

    Role: {role}
    Query: {query}
    Model Response: {model_response}

    --- FORMAT YOUR OUTPUT EXACTLY LIKE THIS ---

    REASONING:
    1. [Explain restricted field detection]
    2. [Explain placeholder use for allowed fields]
    3. [Explain corrections of any incorrect denial]
    4. [Explain removal of unrelated or verbose content]

    SANITIZED_RESPONSE:
    [Final sanitized answer the user should see]
    """

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": system_prompt}],
            temperature=0.1,
            max_tokens=1200
        )
        
        full_output = response.choices[0].message.content.strip()

        reasoning = ""
        sanitized = ""
        if "SANITIZED_RESPONSE:" in full_output:
            parts = full_output.split("SANITIZED_RESPONSE:")
            reasoning = parts[0].replace("REASONING:", "").strip()
            sanitized = parts[1].strip()
        else:
            sanitized = full_output
            reasoning = "REASONING section not parsed correctly."

        return {
            "reasoning_steps": reasoning,
            "sanitized_response": sanitized
        }

    except Exception as e:
        print(f"OpenAI API Error: {str(e)}")
        return {
            "reasoning_steps": f"Error occurred during GPT call: {str(e)}",
            "sanitized_response": "Unable to process the response due to a system error."
        }


def generate_mongo_query_with_openai(question: str, response: str, username: str, role: str):

     # Retrieve allowed fields for the role using the FAISS-based RBAC retrieval
    role_rules = retrieve_role_rules(role)
    allowed_fields = role_rules.get("allowed", [])
    allowed_fields_str = ", ".join(allowed_fields)

    if role == "Patient":
        prompt = f"""
        You are a MongoDB query builder.

        Role: Patient
        Username: {username}
        Question: "{question}"
        Sanitized Model Response: "{response}"


        Access Rules:
        - Only include fields from this list: {allowed_fields_str}
        - Do not include any field that is not on the list.
        Return a Mongo query in this format:
        {{
            "filter": {{"patientname": "{username}"}},
            "projection": {{
                "field_1": 1,
                "field_2": 1
            }}
        }}

        Ensure:
        - Keys in projection are lowercase and snake_case.
        - Use only patientname as filter (based on username).
        - Return ONLY a valid Python dictionary.
        - Use ONLY fields from this schema list: {allowed_fields_str} and match the field names exactly from the list
        - If the response has "I'm sorry" or "rejected" or "don't have permission" and there are **no placeholders** like [treatment], return `{{}}`.
        - If the sanitized response has a combination of:
            - Denied info (e.g., "I'm sorry, you cannot access SSN")
            - And placeholders like [treatment], [age] — generate a query **only for those allowed placeholders**.
        """
    else:
        prompt = f"""
        You are a MongoDB query builder.

        Role: {role}
        Question: "{question}"
        Response: "{response}"

        Return a Mongo query in this format:
        {{
            "filter": {{"patientname": "ExtractedName"}},
            "projection": {{
                "field_1": 1,
                "field_2": 1
            }}
        }}

        Ensure:
        - Return ONLY a valid Python dictionary.
        - Keys in projection are lowercase and snake_case.
        - Do not return explanations or comments.
        - Use ONLY fields from this schema list: {allowed_fields_str} and match the field names exactly from the list
        - If the response has "I'm sorry" or "rejected" or "don't have permission" and there are **no placeholders** like [treatment], return `{{}}`.
        - If the sanitized response has a combination of:
            - Denied info (e.g., "I'm sorry, you cannot access SSN")
            - And placeholders like [treatment], [age] — generate a query **only for those allowed placeholders**.
        """

    try:
        raw_response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )
        parsed_query = ast.literal_eval(raw_response.choices[0].message.content)
        raw_query_copy = parsed_query.copy()

        
        allowed_fields = role_rules.get("allowed", [])
        projection = parsed_query.get("projection", {})

        filtered_projection = {
            k: v for k, v in projection.items()
            if k in allowed_fields or k == "_id"
        }

        parsed_query["projection"] = filtered_projection
        return raw_query_copy, parsed_query

    except Exception as e:
        print(f"[MongoQuery Error]: {e}")
        return {}, {}

def execute_mongo_query(query_dict: dict) -> dict:
    try:

        if not query_dict or not query_dict.get("projection"):
            print("[INFO] Skipping DB call: Empty query or no fields to project.")
            return []
        
        filter_doc = query_dict.get("filter", {})
        projection_doc = query_dict.get("projection", {})

        results_cursor = collection.find(filter_doc, projection_doc)
        return list(results_cursor)
    
    except Exception as e:
        print(f"[MongoExecution Error]: {e}")
        return {}


def replace_placeholders_with_real_data(response: str, real_data) -> str:
    """
    Replace placeholders like [mobilenumber] with real data values from MongoDB.
    Handles case-insensitive field names and placeholder names.
    """

    if not real_data:
        return response
    
    normalized_data = {}
    if isinstance(real_data, list):
        for doc in real_data:
            for key, value in doc.items():
                if key.lower() == "_id":
                    continue
                k = key.lower()
                normalized_data.setdefault(k, []).append(str(value))
        for key in normalized_data:
            normalized_data[key] = ", ".join(normalized_data[key])
    else:
        normalized_data = {k.lower(): str(v) for k, v in real_data.items() if k.lower() != "_id"}

    
    for field, value in normalized_data.items():
        pattern = re.compile(rf"\[{re.escape(field)}\]", flags=re.IGNORECASE)
        if re.search(pattern, response):
            print(f"[DEBUG] Replacing placeholder: [{field}] → {value}")
            response = pattern.sub(value, response)

    return response
