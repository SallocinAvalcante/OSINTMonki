from models.findings import Finding
import sys
import time


SEPARATOR = "-" * 60

def typewriter(text: str, delay: float = 0.005, skip=False):
    if skip:
        print(text)
        return

    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

    

def print_section(title: str, results: list[Finding]) -> None:
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)

    if not results:
        print("  Nenhum resultado encontrado.")
        return

    for i, item in enumerate(results, start=1):
        print(f"  [{i}] {item}")


def print_summary(findings: list[Finding]) -> None:
    print(f"\n{SEPARATOR}")
    print(f"  Total de resultados encontrados: {len(findings)}")
    print(f"{SEPARATOR}\n")

    severity_count = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for f in findings:
        if f.severity in severity_count:
            severity_count[f.severity] += 1

    print("Resumo por severidade:")
    for sev, count in severity_count.items():
        print(f"  {sev}: {count}")

    print(SEPARATOR)


def print_error(source: str, message: str) -> None:
    print(f"[ERRO] ({source}) {message}")


def print_info(source: str, message: str) -> None:
    print(f"[INFO] ({source}) {message}")