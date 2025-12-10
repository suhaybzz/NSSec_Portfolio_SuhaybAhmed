import random

NUM_HOSTS = 50
ATTEMPTS_PER_INFECTED = 3
STEPS = 10

def simulate():
    infected = {0}  # start with host 0 infected
    history = []

    for step in range(1, STEPS + 1):
        newly_infected = set(infected)
        for host in infected:
            for _ in range(ATTEMPTS_PER_INFECTED):
                target = random.randrange(NUM_HOSTS)
                newly_infected.add(target)
        infected = newly_infected
        history.append(len(infected))
        print(f"Step {step}: {len(infected)} / {NUM_HOSTS} hosts infected")

    return history

if __name__ == "__main__":
    simulate()
