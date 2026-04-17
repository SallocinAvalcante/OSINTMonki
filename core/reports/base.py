import os
from datetime import datetime


def create_report_file(prefix: str, target: str) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    os.makedirs("reports", exist_ok=True)

    filename = f"{prefix}_{target}_{timestamp}.txt"
    return os.path.join("reports", filename)