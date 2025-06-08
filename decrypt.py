from xor_helpers import generate_xor_slices, potential_match


def auto_crib_drag(words, xor_data, len_ct, num_ct, dict):
    """
    Automatically crib drags words over the XOR'd ciphertexts.
    There are three scenarios we could come across during this,
    either the program.
        a. deciphers entire words in the plaintexts.
        b. deciphers portions of words in the plaintexts.
        c. yields complete gibberish.
    """

    matches = []
    cribs = set()

    for word in sorted(words):
        crib = word.encode("utf-8")
        crib_len = len(crib)

        if crib_len < 3:
            continue

        max_offset = len_ct - crib_len + 1  # +1 since range is exclusive

        # # Debugging purposes
        # print(f"Crib dragging '{crib}' across {labels}")

        for offset in range(max_offset):
            xor_slices = generate_xor_slices(xor_data, offset, crib_len)
            matches_found = potential_match(
                xor_slices, crib, offset, dict)
            for match in matches_found:
                matches.append(match)
                cribs.add(match["crib"])
    # print("Finished looking for potential matches!")
    # print(f"Found {len(matches)} potential matches!")
    return matches, cribs
