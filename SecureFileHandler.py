import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
from tqdm import tqdm


class SecureFileHandler:
    CHUNK_SIZE = 64 * 1024 * 1024  # 64MB chunks

    def __init__(self, reuse_credentials=False, password=None, salt=None):
        """
        Inicializa o handler com opção de reutilizar credenciais

        Args:
            reuse_credentials (bool): Se True, usa as credenciais fornecidas
            password (bytes/str): Senha para reutilizar (opcional)
            salt (bytes/str): Salt para reutilizar (opcional)
        """
        if reuse_credentials and password and salt:
            if isinstance(password, str):
                self.password = base64.urlsafe_b64decode(password.encode())
            else:
                self.password = password

            if isinstance(salt, str):
                self.salt = base64.urlsafe_b64decode(salt.encode())
            else:
                self.salt = salt
        else:
            self.salt = os.urandom(16)
            self.password = os.urandom(32)

        self.password_str = base64.urlsafe_b64encode(self.password).decode('utf-8')
        self.salt_str = base64.urlsafe_b64encode(self.salt).decode('utf-8')
        self.destruction_key = os.urandom(32)

    def get_credentials(self):
        """Retorna as credenciais em formato amigável"""
        return {
            'password': self.password_str,
            'salt': self.salt_str
        }

    def get_key(self, password=None, salt=None):
        """Deriva a chave de criptografia usando PBKDF2"""
        if password is None:
            password = self.password
            salt = self.salt
        elif isinstance(password, str):
            try:
                password = base64.urlsafe_b64decode(password)
                salt = base64.urlsafe_b64decode(salt)
            except:
                raise Exception("Invalid password or salt format")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=500000,
        )
        return kdf.derive(password)

    def secure_encrypt(self, file_path):
        """
        Encripta um arquivo usando AES-GCM
        """
        try:
            key = self.get_key()
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            encrypted_path = f"{file_path}.encrypted"

            with open(file_path, 'rb') as src, open(encrypted_path, 'wb') as dst:
                dst.write(nonce)
                while True:
                    chunk = src.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    dst.write(encrypted_chunk)

            return encrypted_path

        except Exception as e:
            if os.path.exists(encrypted_path):
                os.remove(encrypted_path)
            raise Exception(f"Encryption error: {str(e)}")

    def secure_decrypt(self, encrypted_file, password, salt):
        """
        Decripta um arquivo previamente encriptado
        """
        try:
            if (password == self.password_str and salt == self.salt_str):
                key = self.get_key()  # Usa as credenciais do handler
            else:
                key = self.get_key(password, salt)  # Usa as credenciais fornecidas

            aesgcm = AESGCM(key)
            original_path = encrypted_file.replace('.encrypted', '')

            with open(encrypted_file, 'rb') as src, open(original_path, 'wb') as dst:
                nonce = src.read(12)  # Lê o nonce do início do arquivo

                while True:
                    chunk = src.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    try:
                        decrypted_chunk = aesgcm.decrypt(nonce, chunk, None)
                        dst.write(decrypted_chunk)
                    except Exception as e:
                        dst.close()
                        os.remove(original_path)
                        raise Exception("Invalid password or salt")

            return original_path

        except Exception as e:
            raise Exception(f"Decryption error: {str(e)}")

    def secure_delete(self, file_path):
        """
        Implementação otimizada da deleção segura
        """
        try:
            if not os.path.exists(file_path):
                return

            file_size = os.path.getsize(file_path)
            temp_path = f"{file_path}.tmp"

            # Uma única passada de zeros
            with open(file_path, 'wb') as f:
                remaining = file_size
                while remaining > 0:
                    write_size = min(remaining, self.CHUNK_SIZE)
                    f.write(b'\x00' * write_size)
                    remaining -= write_size
                f.flush()
                os.fsync(f.fileno())

            # Criptografa o arquivo antes da deleção final
            nonce = os.urandom(12)
            aesgcm = AESGCM(self.destruction_key)

            with open(file_path, 'rb') as src, open(temp_path, 'wb') as dst:
                dst.write(nonce)
                while True:
                    chunk = src.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    dst.write(encrypted_chunk)
                dst.flush()
                os.fsync(dst.fileno())

            # Remove os arquivos do sistema de arquivos
            os.remove(file_path)
            os.rename(temp_path, file_path)
            os.remove(file_path)

            return True

        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise Exception(f"Secure deletion error: {str(e)}")

    def process_secure(self, path):
        """
        Processo otimizado de criptografia e deleção que garante
        deleção segura dos arquivos originais
        """
        try:
            if os.path.isfile(path):
                # Para arquivos individuais
                encrypted_path = self.secure_encrypt(path)
                self.secure_delete(path)
                return encrypted_path
            elif os.path.isdir(path):
                # Para diretórios
                encrypted_paths = []
                for root, _, files in os.walk(path, topdown=False):
                    for file in files:
                        file_path = os.path.join(root, file)
                        encrypted_path = self.secure_encrypt(file_path)
                        encrypted_paths.append(encrypted_path)
                        self.secure_delete(file_path)
                    try:
                        os.rmdir(root)
                    except:
                        pass
                return encrypted_paths
            return True
        except Exception as e:
            raise Exception(f"Secure process error: {str(e)}")

    def get_total_size(self, path):
        """Calcula o tamanho total dos arquivos em um caminho"""
        total = 0
        if os.path.isfile(path):
            return os.path.getsize(path)
        for root, _, files in os.walk(path):
            total += sum(os.path.getsize(os.path.join(root, name)) for name in files)
        return total

    def destroy_large_file(self, file_path):
        """Destruição segura de um arquivo grande"""
        try:
            if not os.path.exists(file_path):
                return

            file_size = os.path.getsize(file_path)
            temp_path = f"{file_path}.tmp"

            # Sobrescreve com zeros
            with open(file_path, 'wb') as f:
                remaining = file_size
                while remaining > 0:
                    write_size = min(remaining, self.CHUNK_SIZE)
                    f.write(b'\x00' * write_size)
                    remaining -= write_size
                f.flush()
                os.fsync(f.fileno())

            # Criptografa antes da deleção final
            nonce = os.urandom(12)
            aesgcm = AESGCM(self.destruction_key)

            with open(file_path, 'rb') as src, open(temp_path, 'wb') as dst:
                dst.write(nonce)
                while True:
                    chunk = src.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    dst.write(encrypted_chunk)
                dst.flush()
                os.fsync(dst.fileno())

            os.remove(file_path)
            os.rename(temp_path, file_path)
            os.remove(file_path)

        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise e

    def destroy_large_path(self, path):
        """Destruição segura de um caminho (arquivo ou diretório)"""
        try:
            if os.path.isfile(path):
                self.destroy_large_file(path)
            else:
                for root, _, files in os.walk(path, topdown=False):
                    for file in files:
                        file_path = os.path.join(root, file)
                        self.destroy_large_file(file_path)
                    try:
                        os.rmdir(root)
                    except:
                        pass
            return True

        except Exception as e:
            raise Exception(f"Destruction error: {str(e)}")

    def secure_delete(self, file_path):
        """
        Implementação otimizada da deleção segura
        """
        try:
            if not os.path.exists(file_path):
                return

            file_size = os.path.getsize(file_path)
            temp_path = f"{file_path}.tmp"

            # Uma única passada de zeros
            with open(file_path, 'wb') as f:
                remaining = file_size
                while remaining > 0:
                    write_size = min(remaining, self.CHUNK_SIZE)
                    f.write(b'\x00' * write_size)
                    remaining -= write_size
                f.flush()
                os.fsync(f.fileno())

            # Criptografa o arquivo antes da deleção final
            nonce = os.urandom(12)
            aesgcm = AESGCM(self.destruction_key)

            with open(file_path, 'rb') as src, open(temp_path, 'wb') as dst:
                dst.write(nonce)
                while True:
                    chunk = src.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    dst.write(encrypted_chunk)
                dst.flush()
                os.fsync(dst.fileno())

            # Remove os arquivos do sistema de arquivos
            os.remove(file_path)
            os.rename(temp_path, file_path)
            os.remove(file_path)

            return True

        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise Exception(f"Secure deletion error: {str(e)}")

    def process_secure(self, path):
        """
        Processo otimizado de criptografia e deleção que garante
        deleção segura dos arquivos originais
        """
        try:
            if os.path.isfile(path):
                # Para arquivos individuais
                encrypted_path = self.secure_encrypt(path)
                self.secure_delete(path)  # Usando o método otimizado
                return True
            elif os.path.isdir(path):
                # Para diretórios
                for root, _, files in os.walk(path, topdown=False):
                    for file in files:
                        file_path = os.path.join(root, file)
                        encrypted_path = self.secure_encrypt(file_path)
                        self.secure_delete(file_path)  # Usando o método otimizado
                    try:
                        # Tenta remover o diretório vazio
                        os.rmdir(root)
                    except:
                        pass
                return True
        except Exception as e:
            raise Exception(f"Secure process error: {str(e)}")

    def secure_decrypt(self, encrypted_file, password, salt):
        """
        Decripta um arquivo previamente encriptado, criando diretórios necessários
        """
        try:
            if (password == self.password_str and salt == self.salt_str):
                key = self.get_key()  # Usa as credenciais do handler
            else:
                key = self.get_key(password, salt)  # Usa as credenciais fornecidas

            aesgcm = AESGCM(key)
            original_path = encrypted_file.replace('.encrypted', '')

            # Cria o diretório pai se não existir
            os.makedirs(os.path.dirname(original_path), exist_ok=True)

            with open(encrypted_file, 'rb') as src, open(original_path, 'wb') as dst:
                nonce = src.read(12)  # Lê o nonce do início do arquivo

                while True:
                    chunk = src.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    try:
                        decrypted_chunk = aesgcm.decrypt(nonce, chunk, None)
                        dst.write(decrypted_chunk)
                    except Exception as e:
                        dst.close()
                        if os.path.exists(original_path):
                            os.remove(original_path)
                        raise Exception("Invalid password or salt")

            return original_path

        except Exception as e:
            raise Exception(f"Decryption error: {str(e)}")

    def process_secure(self, path):
        """
        Processo otimizado de criptografia e deleção que garante
        deleção segura dos arquivos originais
        """
        try:
            if os.path.isfile(path):
                # Para arquivos individuais
                encrypted_path = self.secure_encrypt(path)
                self.secure_delete(path)  # Usando o método otimizado
                return True
            elif os.path.isdir(path):
                # Para diretórios
                for root, _, files in os.walk(path, topdown=False):
                    for file in files:
                        file_path = os.path.join(root, file)
                        encrypted_path = self.secure_encrypt(file_path)
                        self.secure_delete(file_path)  # Usando o método otimizado
                    try:
                        # Tenta remover o diretório vazio
                        os.rmdir(root)
                    except:
                        pass
                return True
        except Exception as e:
            raise Exception(f"Secure process error: {str(e)}")

    def secure_decrypt(self, encrypted_file, password, salt):

        try:

            key = self.get_key(password, salt)

            aesgcm = AESGCM(key)



            original_path = encrypted_file.replace('.encrypted', '')



            with open(encrypted_file, 'rb') as src, open(original_path, 'wb') as dst:

                nonce = src.read(12)  # Lê o nonce do início do arquivo



                while True:

                    chunk = src.read(self.CHUNK_SIZE)

                    if not chunk:

                        break

                    decrypted_chunk = aesgcm.decrypt(nonce, chunk, None)

                    dst.write(decrypted_chunk)



            return original_path



        except Exception as e:

            raise Exception(f"Erro na decriptação: {str(e)}")



    def secure_delete(self, file_path):

        try:

            if os.path.exists(file_path):

                file_size = os.path.getsize(file_path)

                with open(file_path, 'wb') as f:

                    remaining = file_size

                    while remaining > 0:

                        write_size = min(remaining, self.CHUNK_SIZE)

                        f.write(b'\x00' * write_size)

                        remaining -= write_size

                    f.flush()

                    os.fsync(f.fileno())

                os.remove(file_path)

                return True

        except Exception as e:

            raise Exception(f"Erro na deleção: {str(e)}")



    def process_secure(self, path):

        try:

            if os.path.isfile(path):

                encrypted_path = self.secure_encrypt(path)

                self.secure_delete(path)

                return True

            elif os.path.isdir(path):

                for root, _, files in os.walk(path):

                    for file in files:

                        file_path = os.path.join(root, file)

                        encrypted_path = self.secure_encrypt(file_path)

                        self.secure_delete(file_path)

                return True

        except Exception as e:

            raise Exception(f"Erro no processo: {str(e)}")



    def get_total_size(self, path):

        total = 0

        if os.path.isfile(path):

            return os.path.getsize(path)

        for root, _, files in os.walk(path):

            total += sum(os.path.getsize(os.path.join(root, name)) for name in files)

        return total



    def destroy_large_file(self, file_path, total_size, pbar):

        try:

            if not os.path.exists(file_path):

                return



            nonce = os.urandom(12)

            aesgcm = AESGCM(self.destruction_key)

            file_size = os.path.getsize(file_path)

            temp_path = str(file_path) + '.tmp'



            with open(file_path, 'rb') as src, open(temp_path, 'wb') as dst:

                dst.write(nonce)

                while True:

                    chunk = src.read(self.CHUNK_SIZE)

                    if not chunk:

                        break

                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)

                    dst.write(encrypted_chunk)

                    pbar.update(len(chunk))



            self.secure_delete(file_path)

            os.rename(temp_path, file_path)

            self.secure_delete(file_path)



        except Exception as e:

            if os.path.exists(temp_path):

                os.remove(temp_path)

            raise e



    def destroy_large_path(self, path):

        try:

            total_size = self.get_total_size(path)



            with tqdm(total=total_size, unit='B', unit_scale=True, desc="Progresso") as pbar:

                if os.path.isfile(path):

                    self.destroy_large_file(path, total_size, pbar)

                else:

                    for root, _, files in os.walk(path, topdown=False):

                        for file in files:

                            file_path = os.path.join(root, file)

                            self.destroy_large_file(file_path, total_size, pbar)

                        try:

                            os.rmdir(root)

                        except:

                            pass

            return True



        except Exception as e:

            raise Exception(f"Erro: {str(e)}")





def main():

    handler = SecureFileHandler()



    while True:

        print("\n=== Sistema de Criptografia e Segurança ===")

        print("1. Encriptar arquivo (AES-256)")

        print("2. Encriptar pasta (AES-256)")

        print("3. Encriptar e deletar arquivo")

        print("4. Encriptar e deletar pasta")

        print("5. Decriptografar arquivo")

        print("6. Decriptografar pasta")

        print("7. Destruir grandes volumes permanentemente")

        print("8. Sair")



        choice = input("\nEscolha uma opção (1-8): ")



        if choice == "1":

            file_path = input("Arquivo para encriptar: ")

            if os.path.exists(file_path):

                encrypted_path = handler.secure_encrypt(file_path)

                print(f"Arquivo encriptado: {encrypted_path}")

                print(f"\nGUARDE ESTAS INFORMAÇÕES EM LOCAL SEGURO:")

                print(f"Senha: {handler.password}")

                print(f"Salt: {base64.b64encode(handler.salt).decode()}")



        elif choice == "2":

            folder_path = input("Pasta para encriptar: ")

            if os.path.exists(folder_path):

                for root, _, files in os.walk(folder_path):

                    for file in files:

                        file_path = os.path.join(root, file)

                        encrypted_path = handler.secure_encrypt(file_path)

                        print(f"Encriptado: {encrypted_path}")

                print(f"\nGUARDE ESTAS INFORMAÇÕES EM LOCAL SEGURO:")

                print(f"Senha: {handler.password}")

                print(f"Salt: {base64.b64encode(handler.salt).decode()}")



        elif choice == "3":

            path = input("Arquivo para encriptar e deletar: ")

            if os.path.exists(path):

                handler.process_secure(path)

                print(f"\nGUARDE ESTAS INFORMAÇÕES EM LOCAL SEGURO:")

                print(f"Senha: {handler.password}")

                print(f"Salt: {base64.b64encode(handler.salt).decode()}")

                print("Processo completado")



        elif choice == "4":

            path = input("Pasta para encriptar e deletar: ")

            if os.path.exists(path):

                handler.process_secure(path)

                print(f"\nGUARDE ESTAS INFORMAÇÕES EM LOCAL SEGURO:")

                print(f"Senha: {handler.password}")

                print(f"Salt: {base64.b64encode(handler.salt).decode()}")

                print("Processo completado")



        elif choice == "5":

            file_path = input("Arquivo .encrypted para decriptografar: ")

            if os.path.exists(file_path):

                password = input("Digite a senha: ")

                salt = input("Digite o salt: ")

                try:

                    decrypted_path = handler.secure_decrypt(file_path, password, salt)

                    print(f"Arquivo decriptografado restaurado: {decrypted_path}")

                except Exception as e:

                    print(f"Erro: senha ou salt incorretos")



        elif choice == "6":

            folder_path = input("Pasta com arquivos .encrypted: ")

            if os.path.exists(folder_path):

                password = input("Digite a senha: ")

                salt = input("Digite o salt: ")

                try:

                    for root, _, files in os.walk(folder_path):

                        for file in files:

                            if file.endswith('.encrypted'):

                                file_path = os.path.join(root, file)

                                decrypted_path = handler.secure_decrypt(file_path, password, salt)

                                print(f"Restaurado: {decrypted_path}")

                except Exception as e:

                    print(f"Erro: senha ou salt incorretos")



        elif choice == "7":

            path = input("\nCaminho do arquivo/pasta para destruir permanentemente: ")

            if os.path.exists(path):

                size_gb = handler.get_total_size(path) / (1024 ** 3)

                print(f"\nTamanho total: {size_gb:.2f}GB")

                confirm = input("\nATENÇÃO! Arquivos serão destruídos permanentemente!\nDigite 'SIM' para confirmar: ")

                if confirm == "SIM":

                    handler.destroy_large_path(path)

                    print("\nDestruição completa - arquivos foram criptografados e deletados")

                else:

                    print("Operação cancelada")

            else:

                print("Caminho não encontrado!")



        elif choice == "8":

            print("\nPrograma encerrado!")

            break



        else:

            print("Opção inválida!")





if __name__ == "__main__":

    main()