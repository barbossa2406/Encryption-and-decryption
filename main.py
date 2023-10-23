def encrypt_vigenere(plaintext, keyword):
    encrypted_text = ""
    keyword = keyword.upper()  # Convert the keyword to uppercase for consistency

    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.isalpha():
            shift = ord(keyword[i % len(keyword)]) - ord('A')
            if char.islower():
                encrypted_char = chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
            else:
                encrypted_char = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
            encrypted_text += encrypted_char
        else:
            encrypted_text += char

    return encrypted_text


def decrypt_vigenere(ciphertext, keyword):
    decrypted_text = ""
    keyword = keyword.upper()

    for i in range(len(ciphertext)):
        char = ciphertext[i]
        if char.isalpha():
            shift = ord(keyword[i % len(keyword)]) - ord('A')
            if char.islower():
                decrypted_char = chr(((ord(char) - ord('a') - shift + 26) % 26) + ord('a'))
            else:
                decrypted_char = chr(((ord(char) - ord('A') - shift + 26) % 26) + ord('A'))
            decrypted_text += decrypted_char
        else:
            decrypted_text += char

    return decrypted_text


if __name__ == "__main__":
    try:
        keyword = input("Enter the keyword for encryption and decryption: ")
        plaintext = input("Enter the text you want to encrypt: ")

        encrypted_text = encrypt_vigenere(plaintext, keyword)
        print(f"Encrypted text: {encrypted_text}")

        decrypted_text = decrypt_vigenere(encrypted_text, keyword)
        print(f"Decrypted text: {decrypted_text}")
    except Exception as e:
        print(f"An error occurred: {e}")
