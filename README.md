# One-Time-Pad-Decryption
Python program that programmatically decrypts messages encrypted with a "One-Time Pad"

# Algorithm
- The program begins by reading the ciphertexts as bytes, storing each string of bytes into an array `ciphertexts`.
- We then obtain an array of sets `words`, where each set contains english words with similar levels of usage.
- Now, we obtain a dictionary of the ciphertexts XOR'd together `xor_data`, of the form:
    ```
    {
        "p1": {
            "p2": {"name": "x12", "result": "xor_result_string"},
            "p3": {"name": "x13", "result": "xor_result_string"}
        },
        "p2": {
            "p1": {"name": "x12", "result": "xor_result_string"},
            "p3": {"name": "x23", "result": "xor_result_string"}
        },
        "p3": {
            "p1": {"name": "x13", "result": "xor_result_string"},
            "p2": {"name": "x23", "result": "xor_result_string"}
        }
    }
    ```
- Following the above, we loop through `words` and split each set into equal subsets `split_sets`
  - Then for each subset, we run the function `auto_crib_drag(words, xor_data, len_ct, num_ct, dict)`

## auto_crib_drag
- We initialize an empty set `matches` and loop through `words`(in this case, `split_sets[i]` is passed as `words`)
- We loop through the sorted set of `words`
  - Define `crib` as the utf-8 encoded word, with `crib_len` being the length of `crib` and `max_offset` being the exclusive range that our           crib can be shifted over(Ie. If the crib is "hello" and the ciphertext is 10 characters, then the max_offset would be 6 since we can only         shift 'hello' to start at the 5th index of the ciphertext before XOR'ing)
  - We then iterate through all `offset` values from 0 to `max_offset` - 1
    - We call `generate_xor_slices` with `xor_data`, `offset`, and `crib_len`
    - If `potential_match(xor_slices, crib, offset, dict)` yields `True` for any slice, we add `crib` to `matches`
- The function returns the number of matches

## generate_xor_slices
- We initialize the empty dictionary `xor_slices`
- We iterate through each `outer_key` in `xor_data`, in which `outer_key` is of the form p1, p2, ..., pn where `n` is the number of ciphertexts
  - We add each `outer_key` as a key in `xor_slices` with an empty dictionary as its value
  - Then, we iterate through each `inner_key` and `details` from `xor_data[outer_key].items()`
    - We define `slice_result` as the offset of XORing `outer_key` and `inner_key` at indices `offset` to `offset + crib_len`
    - We then store `{ "name": details["name"], "slice": slice_result }` into `xor_slices[outer_key][inner_key]`

## potential_match
- Initialize an empty array `results`
- Iterate through each `outer_key` in `xor_slices`
  - Initialize `plaintexts` as an empty array and set `p_match` to `True`
  - For each `inner_key` and `details` in `xor_slices[outer_key].items()`
    - Let `pt_slice` be the slice of the plaintext when XORing the crib with the XOR'd slice, where `pt_words` is the `split()` of `pt_slice`
    - Iterate through the potential words in `pt_words`
      - If the word returns `True` on `valid_string()` for all elements of `pt_words`, then append `True` to `results`. Otherwise append `False`
- Return the results array
