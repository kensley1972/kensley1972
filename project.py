'''
This program implements double encryption using the AES-256 algorithm and a rotor-like
substitution technique inspired by the Turing machine. The system has a graphical interface
in Tkinter that allows the user to provide encryption keys, encrypt and decrypt binary files.
'''

#Libraries
import logging
import string
import random
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import secrets

# Função principal
def main():
    global criptografia
    criptografia = None
    root = tk.Tk()
    root.title("TURING CRYPTOGRAPHY WITH AES-256")
    frame = tk.Frame(root)
    frame.pack(pady=20, padx=20)
    tk.Label(frame, text="ENTER KEYS (7 SETS OF UP TO 10 NUMBERS):").grid(row=0, column=0, columnspan=3, padx=5, pady=5)
    entradas_chaves = []
    for i in range(7):
        tk.Label(frame, text=f"SET {i + 1}:").grid(row=i + 1, column=0, padx=5, pady=5, sticky="e")
        entrada = tk.Entry(frame, width=50)
        entrada.grid(row=i + 1, column=1, padx=5, pady=5)
        entradas_chaves.append(entrada)
    tk.Button(frame, text="SET KEYS", command=lambda: definir_chaves(entradas_chaves)).grid(row=8, column=0, columnspan=2, pady=10)
    tk.Button(frame, text="ENCRYPTION MESSAGE", command=criptografar_mensagem).grid(row=9, column=0, columnspan=3, pady=10)
    tk.Button(frame, text="DECRYPTION MESSAGE", command=descriptografar_mensagem).grid(row=10, column=0, columnspan=3, pady=10)
    root.mainloop()


# Configuração do logger
logging.basicConfig(
    filename="operacoes_criptografia.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# Funções de leitura e escrita de arquivo
def ler_arquivo(caminho):
    try:
        with open(caminho, 'rb') as arquivo:  # Abre o arquivo em modo binário
            conteudo = arquivo.read()
        logging.info(f"FILE '{caminho}' READ.")
        return conteudo
    except FileNotFoundError:
        logging.error(f"FILE NOT FOUND!: {caminho}")
        return b""  # Retorna bytes vazios
    except Exception as e:
        logging.error(f"READING ERROR '{caminho}': {e}")
        return b""  # Retorna bytes vazios

def salvar_arquivo(caminho, conteudo):
    """
    Salva um conteúdo binário em um arquivo.
    :param caminho: Caminho do arquivo.
    :param conteudo: Conteúdo binário a ser salvo.
    """
    try:
        with open(caminho, 'wb') as arquivo:  # Alterado para 'wb' para arquivos binários
            arquivo.write(conteudo)
        logging.info(f"FILE SAVED IN '{caminho}'.")
    except Exception as e:
        logging.error(f"ERROR SAVING FILE '{caminho}': {e}")

# Função AES (Usando AES-256)
def criptografar_aes(mensagem, chave):
    cipher = AES.new(chave, AES.MODE_CBC)
    mensagem_criptografada = cipher.encrypt(pad(mensagem, AES.block_size))
    return cipher.iv + mensagem_criptografada

def descriptografar_aes(mensagem_criptografada, chave):
    iv = mensagem_criptografada[:AES.block_size]
    cipher = AES.new(chave, AES.MODE_CBC, iv)
    mensagem_original = unpad(cipher.decrypt(mensagem_criptografada[AES.block_size:]), AES.block_size)
    return mensagem_original  # Retorna diretamente como bytes

# Função para criptografar com os rotores
class Rotor:
    def __init__(self, chave):
        self.chave = chave

    def criptografar(self, byte):
        return (byte + self.chave) % 256  # Manipular como byte, não caractere

    def descriptografar(self, byte):
        return (byte - self.chave) % 256  # Manipular como byte, não caractere

# Função para Criptografar a Mensagem
class CriptografiaTuring:
    def __init__(self, chaves):
        self.rotores = [Rotor(chave) for chave in chaves]
        self.chave_aes = secrets.token_bytes(32)  # Gerar uma chave AES-256
        logging.info(f"CRYPTOGRAPHY SYSTEM STARTED WITH {len(chaves)} ROTORS AND KEYS AES-256.")
    
    def criptografar(self, mensagem):
        # Garantir que a mensagem seja tratada como bytes
        if isinstance(mensagem, str):
            mensagem = mensagem.encode('latin1')  # Codificar string para bytes usando 'latin1'

        # Diagnóstico para verificar a mensagem após a codificação
        logging.info(f"CODED MESSAGE: {mensagem[:100]}...")  # Exibe os primeiros 100 bytes

        # Criptografar com os rotores
        for rotor in self.rotores:
            mensagem = bytearray(rotor.criptografar(b) for b in mensagem)

        # Diagnóstico após o processo de rotor
        logging.info(f"MESSAGE AFTER ROTORS: {mensagem[:100]}...")  # Exibe os primeiros 100 bytes

        # Criptografar a mensagem com AES
        mensagem_criptografada = criptografar_aes(mensagem, self.chave_aes)
        logging.info("ENCRYPTED MESSAGE! (AES-256 + ROTORS).")

        # Diagnóstico final
        logging.info(f"ENCRYPTED MESSAGE!(WITH AES): {mensagem_criptografada[:100]}...")  # Exibe os primeiros 100 bytes

        return mensagem_criptografada


    def descriptografar(self, mensagem_criptografada):
        # Descriptografar com AES
        mensagem_descriptografada = descriptografar_aes(mensagem_criptografada, self.chave_aes)

        # Verificar se a descriptografia AES está funcionando corretamente (exibir os primeiros 100 bytes)
        logging.info(f" AES MESSAGE(IN bytes): {mensagem_descriptografada[:100]}...")

        # Descriptografar com os rotores
        for rotor in reversed(self.rotores):
            # Aplicando descriptografia para cada caractere
            mensagem_descriptografada = bytearray(rotor.descriptografar(b) for b in mensagem_descriptografada)

        # Log para verificar o estado após os rotores
        logging.info(f"ROTORS MESSAGE(IN bytes): {mensagem_descriptografada[:100]}...")

        # Retorna a mensagem final como bytes (não convertida para string)
        return bytes(mensagem_descriptografada)

# Funções principais
def definir_chaves(entradas_chaves):
    global criptografia
    try:
        chaves = []
        for i, entrada in enumerate(entradas_chaves):
            valor = entrada.get().strip()
            if not valor:
                raise ValueError(f"SET {i + 1} IS EMPTY.")
            conjunto = valor.split()
            if not all(c.isdigit() for c in conjunto):
                raise ValueError(f"INVALID VALUES IN SET {i + 1}.")
            conjunto = list(map(int, conjunto))
            while len(conjunto) < 10:
                conjunto.append(secrets.randbelow(100))  # Gerar aleatoriamente com secrets
            chaves.extend(conjunto)
        criptografia = CriptografiaTuring(chaves)
        logging.info("CONFIGURED KEYS.")
        messagebox.showinfo("READ", "CONFIGURED KEYS.")
    except ValueError as e:
        logging.error(f"KEY CONFIGURATION ERROR: {e}")
        messagebox.showerror("ERROR", f"INVALID INPUT: {e}")
    except Exception as e:
        logging.error(f"UNEXPECTED ERROR: {e}")
        messagebox.showerror("ERROR", f"UNEXPECTED ERROR: {e}")

def criptografar_mensagem():
    caminho_entrada = filedialog.askopenfilename(title="SELECT THE FILE TO BE ENCRYPTED")
    if not caminho_entrada:
        return
    mensagem_original = ler_arquivo(caminho_entrada)
    if not mensagem_original:
        messagebox.showerror("ERROR!!", "EMPTY OR NOT FOUND FILE.")
        return
    mensagem_criptografada = criptografia.criptografar(mensagem_original)
    diretorio, nome_arquivo = os.path.split(caminho_entrada)
    nome_saida = f"{os.path.splitext(nome_arquivo)[0]}_criptografado.bin"
    caminho_saida = os.path.join(diretorio, nome_saida)
    salvar_arquivo(caminho_saida, mensagem_criptografada)
    messagebox.showinfo("READ", f"ENCRYPTED MESSAGE IN {caminho_saida}.")
    os.system(f"START {caminho_saida}")

def descriptografar_mensagem():
    caminho_entrada = filedialog.askopenfilename(title="SELECT THE FILE TO BE DECRYPTED")
    if not caminho_entrada:
        return
    mensagem_criptografada = ler_arquivo(caminho_entrada)
    if not mensagem_criptografada:
        messagebox.showerror("ERROR!!", "EMPTY OR NOT FOUND FILE.")
        return
    mensagem_descriptografada = criptografia.descriptografar(mensagem_criptografada)
    if mensagem_descriptografada is None:
        messagebox.showerror("ERROR!!", "DECRYPTION FAILURE.")
        return
    
    # Salvar como arquivo binário
    diretorio, nome_arquivo = os.path.split(caminho_entrada)
    nome_saida = f"{os.path.splitext(nome_arquivo)[0]}_descriptografado.bin"
    caminho_saida = os.path.join(diretorio, nome_saida)
    salvar_arquivo(caminho_saida, mensagem_descriptografada)
    messagebox.showinfo("READ", f"DECRYPTED MESSAGE IN {caminho_saida}.")
    os.system(f"START {caminho_saida}")


if __name__ == "__main__":
    main()
