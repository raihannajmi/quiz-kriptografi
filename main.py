import tkinter as tk
from tkinter import ttk, messagebox
import string


def vigenere_encrypt(plaintext, key):
    key = key.upper()
    ciphertext = []
    for i, letter in enumerate(plaintext.upper()):
        shift = (ord(key[i % len(key)]) - ord('A'))
        cipher_char = chr(((ord(letter) - ord('A') + shift) % 26) + ord('A'))
        ciphertext.append(cipher_char)
    return ''.join(ciphertext)


def generate_playfair_square(key):

    key = ''.join(sorted(set(key), key=key.index)).replace("J", "I").upper()
    alphabet = string.ascii_uppercase.replace("J", "")

    key_square = []
    used_letters = set(key)
    key_square.extend(key)

    for letter in alphabet:
        if letter not in used_letters:
            key_square.append(letter)
            used_letters.add(letter)

    return [key_square[i:i + 5] for i in range(0, 25, 5)]


def format_plaintext(plaintext):
    plaintext = plaintext.replace("J", "I").upper()
    formatted_text = []

    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        b = plaintext[i + 1] if i + 1 < len(plaintext) else 'X'

        if a == b:
            formatted_text.append(a)
            formatted_text.append('X')
            i += 1
        else:
            formatted_text.append(a)
            formatted_text.append(b)
            i += 2

    if len(formatted_text) % 2 != 0:
        formatted_text.append('X')

    return ''.join(formatted_text)


def find_position(letter, key_square):
    for row in range(5):
        for col in range(5):
            if key_square[row][col] == letter:
                return row, col
    return None


def playfair_encrypt(plaintext, key):

    key_square = generate_playfair_square(key)
    formatted_text = format_plaintext(plaintext)

    ciphertext = []

    for i in range(0, len(formatted_text), 2):
        a, b = formatted_text[i], formatted_text[i + 1]
        row_a, col_a = find_position(a, key_square)
        row_b, col_b = find_position(b, key_square)

        if row_a == row_b:
            ciphertext.append(key_square[row_a][(col_a + 1) % 5])
            ciphertext.append(key_square[row_b][(col_b + 1) % 5])

        elif col_a == col_b:
            ciphertext.append(key_square[(row_a + 1) % 5][col_a])
            ciphertext.append(key_square[(row_b + 1) % 5][col_b])

        else:
            ciphertext.append(key_square[row_a][col_b])
            ciphertext.append(key_square[row_b][col_a])

    return ''.join(ciphertext)


def hill_encrypt(plaintext, key):
    plaintext = plaintext.lower().replace(' ', '')
    if len(plaintext) % 3 != 0:
        plaintext += 'x' * (3 - len(plaintext) % 3)

    encrypted = ""
    for i in range(0, len(plaintext), 3):
        block = [ord(char) - ord('a') for char in plaintext[i:i + 3]]
        encrypted_block = [
            (key[0][0] * block[0] + key[0][1] * block[1] +
             key[0][2] * block[2]) % 26,
            (key[1][0] * block[0] + key[1][1] * block[1] +
             key[1][2] * block[2]) % 26,
            (key[2][0] * block[0] + key[2][1] * block[1] +
             key[2][2] * block[2]) % 26,
        ]
        encrypted += ''.join(
            [chr(char + ord('a')) for char in encrypted_block])
    return encrypted


def encrypt():
    selected_cipher = cipher_choice.get()
    plaintext = entry_plaintext.get()
    keytext = entry_key.get()

    if len(keytext) < 12:
        messagebox.showwarning(
            "Error", "Plaintext must be at least 12 characters long.")
        return

    key = entry_key.get() if selected_cipher == 'Vigenère' else ""

    if selected_cipher == 'Vigenère':
        ciphertext = vigenere_encrypt(plaintext, key)
    elif selected_cipher == 'Playfair':
        ciphertext = playfair_encrypt(plaintext, key)
    elif selected_cipher == 'Hill':
        key = [[1, 2, 3], [10, 11, 12], [100, 200, 300]]
        ciphertext = hill_encrypt(plaintext, key)
    else:
        ciphertext = ""

    entry_ciphertext.delete(0, tk.END)
    entry_ciphertext.insert(0, ciphertext)


root = tk.Tk()
root.title("Main Rahasiaan Yuk")
root.geometry("400x250")

style = ttk.Style()
style.theme_use('clam')

label_cipher = ttk.Label(root, text="Mau Pakai Rahasia Apa ?")
label_cipher.grid(row=0, column=0, padx=10, pady=10)
cipher_choice = ttk.Combobox(root, values=["Vigenère", "Playfair", "Hill"])
cipher_choice.grid(row=0, column=1, padx=10, pady=10)
cipher_choice.current(0)

label_plaintext = ttk.Label(root, text="Apa Yang Mau Di Rahasiakan ?")
label_plaintext.grid(row=1, column=0, padx=10, pady=10)
entry_plaintext = ttk.Entry(root, width=40)
entry_plaintext.grid(row=1, column=1, padx=10, pady=10)

label_key = ttk.Label(root, text="Kuncinya Apa ? ( minamal 12 kata ya)")
label_key.grid(row=2, column=0, padx=10, pady=10)
entry_key = ttk.Entry(root, width=40)
entry_key.grid(row=2, column=1, padx=10, pady=10)

label_ciphertext = ttk.Label(root, text="Ini Hasilnya")
label_ciphertext.grid(row=3, column=0, padx=10, pady=10)
entry_ciphertext = ttk.Entry(root, width=40)
entry_ciphertext.grid(row=3, column=1, padx=10, pady=10)

btn_encrypt = ttk.Button(root, text="Rahasiakan", command=encrypt)
btn_encrypt.grid(row=4, column=1, padx=10, pady=20)

root.mainloop()
