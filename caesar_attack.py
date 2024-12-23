# # Educational purposes only - demonstrates common cryptographic vulnerabilities
# import string
# from collections import Counter

# def brute_force_caesar(encrypted_text):
#     results = []
#     # Try all possible shifts (0-25)
#     for shift in range(26):
#         decrypted = ''
#         for char in encrypted_text:
#             if char.isalpha():
#                 # Determine case and base
#                 base = ord('A') if char.isupper() else ord('a')
#                 # Shift back and wrap around
#                 decrypted += chr((ord(char) - base - shift) % 26 + base)
#             else:
#                 decrypted += char
#         results.append(f"Shift {shift}: {decrypted}")
#     return results

# def frequency_analysis_attack(encrypted_text):
#     # English letter frequency order (most to least common)
#     eng_freq = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'.lower()
    
#     # Count frequencies in encrypted text
#     freq = Counter(c.lower() for c in encrypted_text if c.isalpha())
#     sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    
#     # Try to match with English frequency
#     possible_shift = (ord(sorted_freq[0][0]) - ord(eng_freq[0])) % 26
#     return possible_shift

# # Example usage:
# encrypted_email = "1pddqleudu86@jpdlo.frp"
# encrypted_password = "password"  # Example encrypted email

# print("Brute Force Results:")
# results = brute_force_caesar(encrypted_email)
# for result in results:
#     print(result)
# print("Brute Force Results:")
# results = brute_force_caesar(encrypted_password)
# for result in results:
#     print(result)

# print("\nFrequency Analysis Result:")
# shift = frequency_analysis_attack(encrypted_email)
# print(f"Most likely shift: {shift}")
def brute_force_caesar(ciphertext):
  """
  Attempts to decrypt a Caesar cipher by brute-forcing all possible shifts.

  Args:
    ciphertext: The encrypted text.

  Returns:
    A dictionary of possible plaintexts, where the keys are the shift values.
  """

  possible_plaintexts = {}

  for shift in range(26):
    plaintext = caesar_decrypt(ciphertext, shift)
    possible_plaintexts[shift] = plaintext

  return possible_plaintexts

def caesar_decrypt(ciphertext, shift):
  """
  Decrypts a Caesar cipher with a given shift value.

  Args:
    ciphertext: The encrypted text.
    shift: The number of positions to shift the letters back.

  Returns:
    The decrypted plaintext.
  """

  plaintext = ""
  for char in ciphertext:
    if char.isalpha():
      if char.isupper():
        start = ord('A')
      else:
        start = ord('a')
      shifted_char = chr((ord(char) - start - shift) % 26 + start)
      plaintext += shifted_char
    else:
      plaintext += char
  return plaintext

# Example usage
encrypted_email = "1pddqleudu86@jpdlo.frp"
encrypted_password = "sdvvzrug"  

possible_plaintexts = brute_force_caesar(encrypted_email)

# Print all possible plaintexts
for shift, plaintext in possible_plaintexts.items():
  print(f"Shift {shift}: {plaintext}")


possible_plaintexts = brute_force_caesar(encrypted_password)

# Print all possible plaintexts
for shift, plaintext in possible_plaintexts.items():
  print(f"Shift {shift}: {plaintext}")