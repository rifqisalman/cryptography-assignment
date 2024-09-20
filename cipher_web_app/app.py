from flask import Flask, render_template, request, jsonify
import numpy as np

app = Flask(__name__)

# Fungsi Vigenere Cipher
def vigenere_encrypt(plaintext, key):
    key = key.lower()
    key_len = len(key)
    plaintext = plaintext.lower()
    encrypted = ''
    for i, char in enumerate(plaintext):
        if char.isalpha():
            offset = ord('a')
            encrypted += chr((ord(char) - offset + ord(key[i % key_len]) - offset) % 26 + offset)
        else:
            encrypted += char
    return encrypted

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    key_len = len(key)
    ciphertext = ciphertext.lower()
    decrypted = ''
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            offset = ord('a')
            decrypted += chr((ord(char) - offset - (ord(key[i % key_len]) - offset)) % 26 + offset)
        else:
            decrypted += char
    return decrypted

# Fungsi Playfair Cipher
def generate_playfair_matrix(key):
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    key = ''.join(sorted(set(key.lower()), key=key.index)).replace('j', 'i')
    matrix = []
    used_letters = set()
    
    for char in key:
        if char not in used_letters:
            matrix.append(char)
            used_letters.add(char)
    
    for char in alphabet:
        if char not in used_letters:
            matrix.append(char)
            used_letters.add(char)
    
    return [matrix[i:i + 5] for i in range(0, len(matrix), 5)]

def playfair_encrypt(plaintext, key):
    plaintext = plaintext.lower().replace('j', 'i')
    encrypted = ''
    i = 0

    matrix = generate_playfair_matrix(key)

    while i < len(plaintext):
        a = plaintext[i]

        if not a.isalpha():
            encrypted += a
            i += 1
            continue

        if i + 1 < len(plaintext) and plaintext[i + 1].isalpha():
            b = plaintext[i + 1]
            i += 2
        else:
            b = 'x' 
            i += 1

        row_a, col_a, row_b, col_b = 0, 0, 0, 0

        for r in range(5):
            if a in matrix[r]:
                row_a, col_a = r, matrix[r].index(a)
            if b in matrix[r]:
                row_b, col_b = r, matrix[r].index(b)

        if row_a == row_b:
            encrypted += matrix[row_a][(col_a + 1) % 5] + matrix[row_b][(col_b + 1) % 5]
        
        elif col_a == col_b:
            encrypted += matrix[(row_a + 1) % 5][col_a] + matrix[(row_b + 1) % 5][col_b]
        
        else:
            encrypted += matrix[row_a][col_b] + matrix[row_b][col_a]

    return encrypted

def playfair_decrypt(ciphertext, key):
    decrypted = ''
    i = 0
    matrix = generate_playfair_matrix(key)

    while i < len(ciphertext):
        a = ciphertext[i]

        if not a.isalpha():
            decrypted += a
            i += 1
            continue

        if i + 1 < len(ciphertext) and ciphertext[i + 1].isalpha():
            b = ciphertext[i + 1]
            i += 2
        else:
            b = 'x' 
            i += 1

        row_a, col_a, row_b, col_b = 0, 0, 0, 0

        for r in range(5):
            if a in matrix[r]:
                row_a, col_a = r, matrix[r].index(a)
            if b in matrix[r]:
                row_b, col_b = r, matrix[r].index(b)

        if row_a == row_b:
            decrypted += matrix[row_a][(col_a - 1) % 5] + matrix[row_b][(col_b - 1) % 5]
        
        elif col_a == col_b:
            decrypted += matrix[(row_a - 1) % 5][col_a] + matrix[(row_b - 1) % 5][col_b]
        
        else:
            decrypted += matrix[row_a][col_b] + matrix[row_b][col_a]

    return decrypted

# Fungsi Hill Cipher
def hill_encrypt(plaintext, key):
    n = int(len(key)**0.5)
    if n * n != len(key):
        raise ValueError("Panjang kunci harus merupakan kuadrat sempurna (misalnya 4, 9, 16, dll.)")
    
    key_matrix = np.array([ord(c) - ord('a') for c in key]).reshape(n, n)
    
    plaintext = plaintext.lower().replace(' ', '')
    while len(plaintext) % n != 0:
        plaintext += 'x'
    
    plaintext_matrix = np.array([ord(c) - ord('a') for c in plaintext]).reshape(-1, n)
    
    encrypted_matrix = np.dot(plaintext_matrix, key_matrix) % 26
    encrypted_text = ''.join(chr(num + ord('a')) for num in encrypted_matrix.flatten())
    
    return encrypted_text

def hill_decrypt(ciphertext, key):
    n = int(len(key)**0.5)
    if n * n != len(key):
        raise ValueError("Panjang kunci harus merupakan kuadrat sempurna (misalnya 4, 9, 16, dll.)")
    
    key_matrix = np.array([ord(c) - ord('a') for c in key]).reshape(n, n)
    
    try:
        key_matrix_inv = np.linalg.inv(key_matrix) * np.linalg.det(key_matrix)
        key_matrix_inv = np.round(np.linalg.inv(key_matrix) * np.linalg.det(key_matrix)).astype(int) % 26
        key_matrix_inv = (key_matrix_inv * pow(int(np.round(np.linalg.det(key_matrix))), -1, 26)) % 26
    except np.linalg.LinAlgError:
        raise ValueError("Matriks kunci tidak dapat diinvers di modulo 26.")
    
    ciphertext_matrix = np.array([ord(c) - ord('a') for c in ciphertext]).reshape(-1, n)
    
    decrypted_matrix = np.dot(ciphertext_matrix, key_matrix_inv) % 26
    decrypted_text = ''.join(chr(num + ord('a')) for num in decrypted_matrix.flatten())
    
    return decrypted_text

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    method = request.form['method']
    text = request.form['text']
    key = request.form['key']
    action = request.form['action']
    
    if len(key) < 12:
        return jsonify({'error': 'Kunci harus memiliki panjang minimal 12 karakter!'})
    
    result = ""
    try:
        if action == 'encrypt':
            if method == 'Vigenere':
                result = vigenere_encrypt(text, key)
            elif method == 'Playfair':
                result = playfair_encrypt(text, key)
            elif method == 'Hill':
                result = hill_encrypt(text, key)
        elif action == 'decrypt':
            if method == 'Vigenere':
                result = vigenere_decrypt(text, key)
            elif method == 'Playfair':
                result = playfair_decrypt(text, key)
            elif method == 'Hill':
                result = hill_decrypt(text, key)
    except ValueError as e:
        return jsonify({'error': str(e)})
    
    return jsonify({'result': result})

if __name__ == '__main__':
    app.run(debug=True)
