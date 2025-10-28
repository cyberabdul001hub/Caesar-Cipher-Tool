import string

def encrypt_decrypt(text, shift, mode):
    """
    Implements the Caesar Cipher for encryption or decryption.
    Mode 'e' is for encrypt, 'd' is for decrypt.
    """
    result = ""
    
    # Decrypting is just shifting in the opposite direction
    if mode == 'd':
        shift = -shift
        
    # Go through every character in the message
    for char in text:
        if char.isalpha(): 
            
            # Determine the base (ASCII value of 'a' or 'A')
            if char.islower():
                base = ord('a')
            else:
                base = ord('A')
            
            # 1. Convert the character to a 0-25 index (0 for 'A', 25 for 'Z')
            char_index = ord(char) - base
            
            # 2. Apply the shift and use the Modulus (%) for wrap-around
            new_index = (char_index + shift) % 26
            
            # 3. Convert the new index back to a character
            new_char = chr(new_index + base)
            
            result += new_char
        else:
            # Keep non-alphabetical characters (spaces, punctuation, numbers) unchanged
            result += char
            
    return result

# --- Main Program: Test and Demonstration ---

print("\n*** Caesar Cipher Encryption Tool ***")

# Get user input for the message and shift
message_to_send = input("Enter your secret message: ")
try:
    # Use 13 as a common default shift (ROT13) if the user doesn't enter a number
    key_input = input("Enter the shift number (1-25, or leave blank for 13): ")
    shift_key = int(key_input) if key_input.strip().isdigit() else 13
except ValueError:
    shift_key = 13
    print("Invalid shift. Using default key of 13.")


# 1. ENCRYPT the message
encrypted_text = encrypt_decrypt(message_to_send, shift_key, 'e')

print("\n--- Encryption Complete ---")
print(f"Original Message: {message_to_send}")
print(f"Shift Key Used:   {shift_key}")
print(f"Encrypted Code:   {encrypted_text}")

# 2. DECRYPT the message for proof
decrypted_text = encrypt_decrypt(encrypted_text, shift_key, 'd')

print("\n--- Decryption Proof ---")
print(f"Decrypted Back:   {decrypted_text}")
print("---------------------------------\n")