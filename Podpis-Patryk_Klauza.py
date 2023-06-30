import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
import os

def generate_keys():
    private_key = generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=os.urandom
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)
    messagebox.showinfo('Generacja kluczy RSA', 'Klucz prywatny został wygenerowany i zapisany jako private_key.pem\nKlucz publiczny został wygenerowany i zapisany jako public_key.pem')

def sign_file():
    filepath = filedialog.askopenfilename(filetypes=[('Text files', '*.txt')])
    if filepath:
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
            with open('private_key.pem', 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            signature = private_key.sign(
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signature_file = filepath + '.sig'
            with open(signature_file, 'wb') as f:
                f.write(signature)
            messagebox.showinfo('Podpisywanie pliku', 'Podpisywanie pliku zakończone sukcesem')
        except Exception as e:
            messagebox.showerror('Błąd', 'Błąd podczas podpisywania pliku')

def verify_signature():
    filepath = filedialog.askopenfilename(filetypes=[('Text files', '*.txt')])
    if filepath:
        signature_file = filepath + '.sig'
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
            with open(signature_file, 'rb') as f:
                signature = f.read()
            with open('public_key.pem', 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            public_key.verify(
                signature,
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            messagebox.showinfo('Weryfikacja podpisu', 'Podpis jest prawidłowy')
        except Exception as e:
            messagebox.showerror('Weryfikacja podpisu', 'Podpis jest nieprawidłowy')

# Tworzenie głównego okna programu
window = tk.Tk()
window.title('Podpisywanie plików RSA')
window.geometry("350x125")

# Przycisk do generowania kluczy
generate_keys_button = tk.Button(window, text='Generuj klucze', command=generate_keys)
generate_keys_button.pack(pady=5)

# Przycisk do podpisywania pliku
sign_file_button = tk.Button(window, text='Podpisz plik', command=sign_file)
sign_file_button.pack(pady=5)

# Przycisk do weryfikowania podpisu
verify_signature_button = tk.Button(window, text='Zweryfikuj podpis', command=verify_signature)
verify_signature_button.pack(pady=5)

window.mainloop()
