import re

def interpret_cvss_v3(cvss_string):
    metrics = {
        "AV": {"N": "Network", "A": "Adjacent Network", "L": "Local", "P": "Physical"},
        "AC": {"L": "Low", "H": "High"},
        "PR": {"N": "None", "L": "Low", "H": "High"},
        "UI": {"N": "None", "R": "Required"},
        "S": {"U": "Unchanged", "C": "Changed"},
        "C": {"N": "None", "L": "Low", "H": "High"},
        "I": {"N": "None", "L": "Low", "H": "High"},
        "A": {"N": "None", "L": "Low", "H": "High"},
    }

    parts = cvss_string.split('/')
    results = {}
    for part in parts:
        key, value = part.split(':')
        if key in metrics:
            results[key] = metrics[key].get(value, "Unknown")

    return results

def interpret_cvss_v2(cvss_string):
    metrics = {
        "AV": {"N": "Network", "A": "Adjacent Network", "L": "Local"},
        "AC": {"L": "Low", "M": "Medium", "H": "High"},
        "Au": {"N": "None", "S": "Single", "M": "Multiple"},
        "C": {"N": "None", "P": "Partial", "C": "Complete"},
        "I": {"N": "None", "P": "Partial", "C": "Complete"},
        "A": {"N": "None", "P": "Partial", "C": "Complete"},
    }

    parts = cvss_string.split('/')
    results = {}
    for part in parts:
        key, value = part.split(':')
        if key in metrics:
            results[key] = metrics[key].get(value, "Unknown")

    return results

def interpret_cvss(cvss_string):
    if cvss_string.startswith("CVSS:3."):
        return interpret_cvss_v3(cvss_string)
    else:
        return interpret_cvss_v2(cvss_string)

def main():
    cvss_string = input("Enter the CVSS string: ")
    result = interpret_cvss(cvss_string)
    print("\nInterpreted CVSS Metrics:")
    for key, value in result.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    main()