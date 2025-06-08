import string


def split_set(s, n):
    """ Splits a set into `n` roughly equal subsets. """
    s = list(s)
    chunk_size = len(s) // n
    remainder = len(s) % n

    chunks = []
    start = 0
    for i in range(n):
        end = start + chunk_size + (1 if i < remainder else 0)
        chunks.append(set(s[start:end]))
        start = end

    return chunks


def load_words(file_path, previous_words=[]):
    """
    Reads a SCOWL word list from a text file and returns a set of words.
    Skips words that cannot be decoded in UTF-8.

    :param file_path: Path to the SCOWL word list file.
    :param previous_words: List of previously loaded word sets to avoid duplicates.
    :return: A set containing all words from the file.
    """
    words = set()
    with open(file_path, 'rb') as infile:
        for line in infile:
            try:
                decoded_line = line.decode('utf-8').strip().lower()
                seen = any(
                    decoded_line in words_set for words_set in previous_words)
                if decoded_line and len(decoded_line) > 0 and not seen:
                    words.add(decoded_line)
            except UnicodeDecodeError:
                continue
    return words


def read_ciphertexts(filename):
    """
    Reads lines from 'filename', each line is assumed to be hex-encoded or binary-encoded ciphertext.
    Returns a list of bytes objects, one per line.
    """
    ciphertexts = []

    with open(filename, 'r') as infile:
        for line in infile:
            line = line.strip()

            if not line:
                continue

            if is_hex_string(line):
                ciphertexts.append(bytes.fromhex(line))

            elif len(line) % 8 == 0 and all(c in '01' for c in line):
                byte_array = [int(line[i:i+8], 2)
                              for i in range(0, len(line), 8)]
                ciphertexts.append(bytes(byte_array))
            else:
                raise ValueError(f"Invalid line in file: {line}")

    return ciphertexts


def is_hex_string(s):
    """
    Checks if the given string represents a valid hexadecimal number.
    It allows an optional '0x' prefix, but this is not required.

    :param s: The string to check (e.g. "1A3F", "0x1A3F", or "FF").
    :return: True if s is a valid hex string, False otherwise.
    """
    if s.lower().startswith("0x"):
        s = s[2:]

    hex_digits = string.hexdigits
    return all(ch in hex_digits for ch in s)


def is_binary_string(s):
    """
    Checks if the given string represents a valid binary number.
    It allows an optional '0b' prefix, but this is not required.

    :param s: The string to check (e.g. "1010" or "0b110").
    :return: True if s is a valid binary string, False otherwise.
    """
    if s.lower().startswith("0b"):
        s = s[2:]

    return all(ch in '01' for ch in s)


def is_printable_ascii(s):
    """
    Returns True if all characters in the input are printable ASCII
    and ensures that guessed substrings:
    - Do not have unsupported symbols or numbers at the start or end (except for ', . ').
    - Do not have random numbers or unsupported symbols between letters.
    """
    try:
        text = s.decode('utf-8')
    except:
        return False
    punc = r'[!,.:;\'"?]'
    allowed_characters = string.ascii_letters + punc + " "

    if not all(c in allowed_characters for c in text):
        return False

    return True


def is_wrapped(decrypted_slice, string):
    start = decrypted_slice.find(string)
    end = start + len(string)
    # If the start of the string is the first character or the end
    # of the string is the end of the slice, it is not wrapped
    if start == 0 or end == len(decrypted_slice):
        return False
    return True


def whitespace_adj(decrypted_slice, string):
    start = decrypted_slice.find(string)
    end = start + len(string)
    # If start<0 and end is the end of the decrypted_slice, then the
    # string is not whitespace adjacent
    if start-1 < 0 and end == len(decrypted_slice):
        return False, False
    # If only start<0, check if the end is whitespace or not
    if start-1 < 0:
        return False, decrypted_slice[end] == 32
    # If only end is the end of the decrypted_slice, check if start is
    # whitespace or not
    if end == len(decrypted_slice):
        return decrypted_slice[start-1] == 32, False
    # If one of decrypted_slice[start-1] or decrypted_slice[end]
    # equal whitespace, the string is whitespace adjacent
    return decrypted_slice[start-1] == 32, decrypted_slice[end] == 32


def is_word(string, dict):
    return string in dict
