
"""
Intentionally poor-quality Python for static-analysis testing.
Do not use in production.
"""

import os
import re
import json
import time
import hashlib


# 1. Unused variable and dead code
def calculate_total(prices):
    debug_message = "calculating total"
    unused_multiplier = 100

    if False:
        print("This code can never run")

    return sum(prices)


# 2. Inefficient algorithm: O(n^2) membership checks
def find_duplicates(items):
    duplicates = []

    for item in items:
        if items.count(item) > 1 and item not in duplicates:
            duplicates.append(item)

    return duplicates


# 3. Mutable default argument
def append_record(record, records=[]):
    records.append(record)
    return records


# 4. Broad exception handling hides defects
def parse_config(raw):
    try:
        return json.loads(raw)
    except Exception:
        return {}


# 5. Duplicate logic and magic numbers
def calculate_discount_a(price):
    if price > 1000:
        return price * 0.15
    return price * 0.05


def calculate_discount_b(price):
    if price > 1000:
        return price * 0.15
    return price * 0.05


# 6. Misleading name and implicit type assumptions
def is_valid_email(value):
    return "@" in value and "." in value


# 7. Unnecessary work inside a loop
def normalize_names(names):
    result = []

    for name in names:
        pattern = re.compile(r"\s+")
        result.append(pattern.sub(" ", name).strip().lower())

    return result


# 8. Fragile filesystem handling
def read_user_file(filename):
    path = os.path.join("/tmp/app-data", filename)

    with open(path, "r") as file:
        return file.read()


# 9. Poor resource and performance choices
def repeated_hash(data, rounds=100000):
    result = data.encode()

    for _ in range(rounds):
        result = hashlib.sha256(result).hexdigest().encode()

    return result.decode()


# 10. Silent failure and misleading return value
def save_records(records, destination):
    try:
        with open(destination, "w") as file:
            json.dump(records, file)
    except OSError:
        pass

    return True


if __name__ == "__main__":
    print(calculate_total([10, 20, 30]))
    print(find_duplicates([1, 2, 2, 3, 3, 3]))
    print(append_record("first"))
    print(append_record("second"))
