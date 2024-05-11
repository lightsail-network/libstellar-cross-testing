import base64
import difflib
import subprocess
import json
import csv
import argparse

from stellar_sdk import *
from tx_formatter import Formatter


def print_diff(text1: str, text2: str):
    differ = difflib.Differ()
    diff = list(differ.compare(text1.splitlines(), text2.splitlines()))
    for line in diff:
        if line.startswith("- "):
            print("\033[91m" + line + "\033[0m")
        elif line.startswith("+ "):
            print("\033[92m" + line + "\033[0m")
        else:
            print(line)


def execute_command(command):
    try:
        output = subprocess.check_output(command, shell=True, universal_newlines=True)
        return output.strip()
    except subprocess.CalledProcessError as e:
        # print(f"Error executing command: {e}")
        return ""


def format_with_c(te):
    data = base64.b64encode(te.signature_base()).decode()
    command = f"./build/test_tx_formatter {data}"
    output = execute_command(command)
    return output


def compare_output(te):
    resp_c = format_with_c(te)
    formatter = Formatter(te)
    resp_py = formatter.get_formatted()
    return resp_c == resp_py, resp_c, resp_py


def process_json_file(file_path):
    with open(file_path, "r") as f:
        records = json.load(f)
        for idx, item in enumerate(records):
            tx_envelope = item["tx_envelope"]
            process_transaction_envelope(tx_envelope, idx)


def process_csv_file(file_path):
    with open(file_path, "r") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            tx_envelope = row["tx_envelope"]
            try:
                process_transaction_envelope(tx_envelope, idx)
            except Exception as e:
                # Dirty hack to ignore the utc year out of range error
                if " is out of range" in str(e):
                    pass
                else:
                    raise e


def process_transaction_envelope(tx_envelope, idx):
    te = parse_transaction_envelope_from_xdr(
        tx_envelope, Network.PUBLIC_NETWORK_PASSPHRASE
    )
    print("Processing tx:", idx + 1)
    eq, resp_c, resp_py = compare_output(te)
    if not eq:
        print(te.to_xdr())
        print("-" * 24)
        print_diff(resp_c, resp_py)
        raise ValueError("Output mismatch")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process transaction envelope files.")
    parser.add_argument("file_path", help="Path to the JSON or CSV file.")
    args = parser.parse_args()

    file_path = args.file_path
    if file_path.endswith(".json"):
        process_json_file(file_path)
    elif file_path.endswith(".csv"):
        process_csv_file(file_path)
    else:
        print("Unsupported file format. Please provide a JSON or CSV file.")
