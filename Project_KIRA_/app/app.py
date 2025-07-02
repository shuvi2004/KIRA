from flask import Flask, request, jsonify
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
import requests
# Gemini 1.5 Flash API endpoint and API key
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"
API_KEY = "AIzaSyAYo5kaKGNQ2jL_dPbOBYFM9zbX6c3zpzo"  # Add your Gemini API key to .env

app = Flask(__name__)
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

def initialize_vector_store():
    file_path = "data.txt"
    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()
    splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=100)
    chunks = splitter.split_text(text)
    return FAISS.from_texts(chunks, embedding_model)

vector_db = initialize_vector_store()

@app.route("/reload", methods=["POST"])
def reload_data():
    global vector_db
    try:
        vector_db = initialize_vector_store()
        return jsonify({"message": "Vector store reloaded successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/ask", methods=["POST"])
def ask():
    data = request.get_json()
    flag = data.get("ask")
    query = data.get("query")
    
    if flag:
        return jsonify({"error": "No Access"}), 400

    if not query:
        return jsonify({"error": "No query provided"}), 400

    try:
        # Get similar documents from vector store
        scores = vector_db.similarity_search_with_score(query, k=5)
        filtered_texts = [doc.page_content for doc, score in scores if score < 0.8]

        if not filtered_texts:
            # If no relevant context found, ask Gemini directly
            prompt = f"Question: {query}\nAnswer:"
        else:
            # Use the context from similar documents
            context = "\n".join(filtered_texts)
            prompt = f"""
            Context:
            {context}

            IF THIS CONTEXT DOES'NT MAKE SENSE, PLEASE SAY "I DON'T KNOW". 
            Question:
            {query}

            Answer:
            """
        
        print("Final Prompt:", prompt)  

        headers = {
            "Content-Type": "application/json"
        }
        params = {
            "key": API_KEY
        }
        payload = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }]
        }

        # Make request to Gemini API
        response = requests.post(
            GEMINI_API_URL,
            headers=headers,
            params=params,
            json=payload,
            timeout=30
        )
        response.raise_for_status()  # Will raise an error for 4XX/5XX responses
        
        # Parse the response
        response_data = response.json()
        print("Gemini Response:", response_data)  # Debug print
        
        # Extract the generated text
        if "candidates" in response_data and len(response_data["candidates"]) > 0:
            generated_text = response_data["candidates"][0]["content"]["parts"][0]["text"]
            formatted_text = generated_text.replace("*", "").replace("\n", " ").strip()
            return jsonify({"text": formatted_text})
        else:
            return jsonify({"error": "No valid response from Gemini API"}), 500

    except requests.exceptions.RequestException as e:
        print(f"Request to Gemini API failed: {str(e)}")
        return jsonify({"error": f"Failed to communicate with Gemini API: {str(e)}"}), 500
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080, debug=True)  

