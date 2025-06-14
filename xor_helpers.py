from utils import is_printable_ascii, boundary_adj
import json
import subprocess
from pprint import pprint
import string

process = subprocess.Popen(
    "WordTrie/WordTrie.exe",
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Read and discard the startup message
process.stdout.readline()


BOUNDARY = bytes(string.whitespace + string.punctuation, "utf-8")


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
    return xor_slices


def check_invalid_suffix(string, porf, log):
    # If a whitespace preceeds or follows the string, this is not a suffix
    if porf:
        if log:
            print(f"{string} is not a suffix")
        return False
    # If suffix is invalid, return True
    string = string.decode("utf-8").lower()
    if log:
        print(f"Checking if {string} is a valid suffix")
    return not send_command("count", "suffix", string)


def check_invalid_word(string, dict, pandf, log):
    # If not wrapped, string is not a word
    if not pandf:
        if log:
            print(f"{string} is not a word")
        return False

    if log:
        print(f"Checking if {string} is a valid word")
    # If word is not present, return True
    return not string.decode("utf-8").lower() in dict


def check_invalid_prefix(string, pnotf, log):
    # If string is preceeded by whitespace(and not followed), it is a prefix
    if not pnotf:
        if log:
            print(f"{string} is not a prefix")
        return False

    string = string.decode("utf-8").lower()
    if log:
        print(f"Checking if {string} is a valid prefix")
    return not send_command("count", "prefix", string)


def check_invalid_reverse(string, fnotp, log):
    # If string is followed by whitespace(and not preceeded),
    # it is a reverse prefix
    if not fnotp:
        if log:
            print(f"{string} is not a reverse prefix")
        return False

    string = string.decode("utf-8").lower()
    if log:
        print(f"Checking if {string} is a valid reverse prefix")
    return not send_command("count", "reverse", string)


def valid_decryption(decrypted_slice, dict, log=False):
    substrings = decrypted_slice.split()
    # if is_printable_ascii(decrypted_slice) and decrypted_slice.decode("utf-8") == "efore we st":
    for substring in substrings:

        # CASE 1: If string is not printable, decryption is invalid
        if not is_printable_ascii(substring):
            return False

        substring = substring.rstrip(BOUNDARY)
        preceeds, follows = boundary_adj(decrypted_slice, substring)
        if log:
            print(
                f"preceeds, follows = {preceeds}, {follows} for {substring} in {decrypted_slice}")

        # CASE 2: If not preceeded or followed by whitespace, check if valid suffix
        if check_invalid_suffix(substring, preceeds or follows, log):
            if log:
                print(f"{substring} failed this check")
            return False

        # CASE 3: If only followed by whitespace, check if valid reverse prefix
        elif check_invalid_reverse(substring, follows and not preceeds, log):
            if log:
                print(f"{substring} failed this check")
            return False

        # CASE 4: If wrapped by whitespace, check if word
        elif check_invalid_word(substring, dict, preceeds and follows, log):
            if log:
                print(f"{substring} failed this check")
            return False

        # CASE 5: If only preceeded by whitespace, check if valid prefix
        elif check_invalid_prefix(substring, preceeds and not follows, log):
            if log:
                print(f"{substring} failed this check")
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
        substrings = []
        for ct, details in slices.items():
            decrypted_slice = xor(details["slice"], crib)
            log = False
            if crib.decode("utf-8") == "shouldn't" and is_printable_ascii(decrypted_slice):
                log = True
            if valid_decryption(decrypted_slice, dict, log):
                if crib.decode("utf-8") == "shouldn't" and is_printable_ascii(decrypted_slice):
                    print(
                        f"{crib} has a valid decryption for {decrypted_slice} at offset: {offset}")
                decryptions.append(decrypted_slice)
                substrings.append(decrypted_slice.split())
                continue
            if log:
                print(
                    f"{crib} did not have a valid decryption for {decrypted_slice} at offset: {offset}")
            is_valid = False
            break
        if not is_valid:
            continue
        if log:
            print(
                f"{crib} is being appended!")
        results.append({
            "crib": crib,
            "plaintext": outer_key,
            "start": offset,
            "end": offset+len(crib),
            "substrings": substrings,
            "length": len(crib),
            "decryptions": decryptions
        })
        if crib.decode("utf-8") == "guidelines":
            print("guidelines is being appended")
            print(results)
        # print(
        #     f"{crib} is potentially a string in {outer_key} at index [{offset}:{offset+len(crib)}]!")
        # print(decryptions)

    return results
