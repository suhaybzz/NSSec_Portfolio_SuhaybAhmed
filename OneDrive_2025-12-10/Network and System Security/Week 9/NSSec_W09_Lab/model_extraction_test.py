import subprocess

MODEL_NAME = "smollm2:1.7b"

def ask(prompt: str) -> str:
    result = subprocess.run(
        ["ollama", "run", MODEL_NAME],
        input=prompt.encode(),
        stdout=subprocess.PIPE,
    )
    return result.stdout.decode()

if __name__ == "__main__":
    inputs = [
        "Summarise the concept of Gen AI security in one sentence.",
        "Summarise the concept of Gen AI security in one sentence.",
    ]

    print("=== Model Extraction Pattern Test ===")
    for i, prompt in enumerate(inputs, start=1):
        print(f"\nAttempt {i}")
        print(ask(prompt))
