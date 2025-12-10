import random
from datetime import datetime

THRESHOLD = 100          # suspicious if more than this
ITERATIONS = 20          # pretend these are 20 time-slots

def main():
    print("=== Simple outbound-connection monitor ===")
    for i in range(ITERATIONS):
        connections = random.randint(0, 150)
        timestamp = datetime.now().isoformat(timespec="seconds")
        line = f"{timestamp} - outbound connections: {connections}"
        if connections > THRESHOLD:
            print(line + "  --> ALERT: possible worm / scan behaviour")
        else:
            print(line)

if __name__ == "__main__":
    main()
