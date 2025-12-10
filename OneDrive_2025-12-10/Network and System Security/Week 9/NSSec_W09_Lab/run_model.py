from ollama import chat
from ollama import ChatResponse

# CHANGE THIS to the model you pulled, e.g. "smollm2:1.7b"
MODEL_NAME = "smollm2:1.7b"

response: ChatResponse = chat(
    model=MODEL_NAME,
    messages=[
        {
            'role': 'user',
            'content': 'Why is the sky blue?',
        },
    ],
)

print("=== Model Response ===")
print(response['message']['content'])
