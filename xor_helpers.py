from utils import is_printable_ascii, is_wrapped
import json
import subprocess

process = subprocess.Popen(
    "WordTrie/WordTrie.exe",
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Read and discard the startup message
startup_message = process.stdout.readline().strip()
print(f"Startup Message: {startup_message}")


def send_command(command, type_, string):
    """
    Send a command to the C++ process and return the parsed JSON response.

    Args:
        command (str): "search" or "count"
        type_ (str): "prefix" or "suffix"
        string (str): the input string to search/count

    Returns:
        dict or list: JSON-decoded result from the C++ program
    """
    input_data = json.dumps({
        "command": command,
        "type": type_,
        "string": string
    })
    process.stdin.write(input_data + "\n")
    process.stdin.flush()

    response = process.stdout.readline()
    if command == "count":
        return json.loads(response)["count"]
    return json.loads(response)


def xor(bytes_seq1, bytes_seq2):
    """
    XOR two byte sequences of equal length.

    Args:
        bytes_seq1 (bytes): First byte sequence.
        bytes_seq2 (bytes): Second byte sequence.

    Returns:
        bytes: The XOR result as a bytes object.
    """
    if len(bytes_seq1) != len(bytes_seq2):
        raise ValueError("Both byte sequences must be of equal length.")
    return bytes(b1 ^ b2 for b1, b2 in zip(bytes_seq1, bytes_seq2))


def generate_xor_labels(xor_data):
    """
    Generate a comma-separated string of XOR pair labels from nested xor_data.

    This function expects a nested dictionary where:
      - The first-level keys (e.g., "p1") represent the first plaintext label.
      - The second-level keys (e.g., "p2") represent the second plaintext label.
      - The innermost dictionaries contain:
          - "name" (str): A label for the XOR operation (e.g., "x12").
          - "result": The XOR result (ignored in this function).

    It returns a single string that describes each XOR pair in the form:
      {name} = {p1} ^ {p2},
    with the last pair omitting the trailing comma.

    Example:
        xor_data = { 
            "p1": {
                "p2": {"name": "x12", "result": "..."},
                "p3": {"name": "x13", "result": "..."}
            }, 
            "p2": {
                "p3": {"name": "x23", "result": "..."}
            }
        }
        labels_str = generate_xor_labels(xor_data)
        # labels_str -> "x12 = p1 ^ p2, x13 = p1 ^ p3, x23 = p2 ^ p3"
    """
    xor_labels = []
    for p1, inner_dict in xor_data.items():
        for p2, details in inner_dict.items():
            label = f"{details['name']} = {p1} ^ {p2}"
            xor_labels.append(label)
    return ", ".join(xor_labels)


def generate_xor_data(ciphertexts):
    xor_data = {}
    for idx, ct in enumerate(ciphertexts):
        if idx + 1 == len(ciphertexts):
            break
        xor_data.setdefault(f"p{idx+1}", {})
        for jdx in range(idx + 1, len(ciphertexts)):
            xor_data.setdefault(f"p{jdx+1}", {})
            xor_data[f"p{idx+1}"][f"p{jdx+1}"] = {"name": f"x{idx+1}{jdx+1}",
                                                  "result": xor(ct, ciphertexts[jdx])}
            xor_data[f"p{jdx+1}"][f"p{idx+1}"] = {"name": f"x{idx+1}{jdx+1}",
                                                  "result": xor(ct, ciphertexts[jdx])}
    return xor_data


def generate_xor_slices(xor_data, offset, crib_len):
    """
    Generate an array of slices from XOR'd ciphertexts in a nested xor_data structure.

    This function takes a nested dictionary of XOR'd ciphertext data, where the structure is:
      {
          "p1": {
              "p2": {"name": "x12", "slice": "xor_slice"},
              "p3": {"name": "x13", "slice": "xor_slice"}
          },
          "p2": {
              "p1": {"name": "x12", "slice": "xor_slice"},
              "p3": {"name": "x23", "slice": "xor_slice"}
          },
          "p3": {
              "p1": {"name": "x13", "slice": "xor_slice"},
              "p2": {"name": "x23", "slice": "xor_slice"}
          }
      }

    The function extracts slices from the XOR'd ciphertexts (`result`), sliced from `offset`
    to `offset + crib_len`.

    Args:
        xor_data (dict): A nested dictionary of XOR'd data.
        offset (int): The starting index for the slice.
        crib_len (int): The length of the slice.

    Returns:
        list: A list of dictionaries, each containing the name and the sliced result.
              Example: [{"name": "x12", "slice": "slice_data"}, ...]
    """
    xor_slices = {}
    for outer_key in xor_data:
        xor_slices.setdefault(outer_key, {})
        for inner_key, details in xor_data[outer_key].items():
            slice_result = details["result"][offset:offset + crib_len]
            xor_slices[outer_key][inner_key] = {
                "name": details["name"], "slice": slice_result}
    # print(xor_slices)
    return xor_slices


def check_suffix(decrypted_slice, idx, string):
    string = string.decode("utf-8")
    return not idx and decrypted_slice[0] != " "\
        and not send_command("count", "suffix", string)


def check_word(decrypted_slice, idx, string, dict):
    return idx and is_wrapped(decrypted_slice, string)\
        and not string in dict


def check_prefix(string):
    string = string.decode("utf-8")
    return not send_command("count", "prefix", string)


def valid_decryption(decrypted_slice, dict):
    substrings = decrypted_slice.split()
    for idx, substring in enumerate(substrings):
        if not is_printable_ascii(substring):
            return False
        if check_suffix(decrypted_slice, idx, substring):
            return False
        elif check_word(decrypted_slice, idx, substring, dict):
            return False
        elif check_prefix(substring):
            return False
    return True


def potential_match(xor_slices, crib, offset, dict):
    """Check if a crib decrypts to potential matches in XOR slices.

    Args:
        xor_slices: Dictionary of XOR slices to check against
        crib: Known plaintext string to search for
        offset: Starting position to consider in the slices
        dictionary: Dictionary for validation

    Returns:
        List of dictionaries containing potential matches with their details
    """
    results = []

    for outer_key, slices in xor_slices.items():
        is_valid = True
        decryptions = []
        for inner_key, details in slices.items():
            decrypted_slice = xor(details["slice"], crib)
            if valid_decryption(decrypted_slice, dict):
                decryptions.append(decrypted_slice)
                continue
            is_valid = False
            break
        if not is_valid:
            continue
        results.append({
            "crib": crib,
            "plaintext": outer_key,
            "start": offset,
            "end": offset+len(crib)
        })
        print(
            f"{crib} is potentially a string in {outer_key} at index [{offset}:{offset+len(crib)}]!")
        print(decryptions)

    return results
