import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from tkinter import filedialog
import os
from typing import List
import base64
import threading
import json
from datetime import datetime
from SecureFileHandler import SecureFileHandler


class SecureFileGUI:
    def __init__(self):
        self.handler = None  # Inicialmente None, será criado quando necessário

        # Setup main window
        self.root = ctk.CTk()
        self.root.title("Secure File Handler")
        self.root.geometry("800x600")

        # Configure grid
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        # Create main frame
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

        # Create buttons frame
        self.button_frame = ctk.CTkFrame(self.main_frame)
        self.button_frame.pack(fill="x", padx=10, pady=10)

        # Action buttons
        self.encrypt_btn = ctk.CTkButton(
            self.button_frame,
            text="Encrypt Files",
            command=self.encrypt_selected
        )
        self.encrypt_btn.pack(side="left", padx=5)

        self.encrypt_delete_btn = ctk.CTkButton(
            self.button_frame,
            text="Encrypt & Delete",
            command=self.encrypt_and_delete_selected
        )
        self.encrypt_delete_btn.pack(side="left", padx=5)

        self.decrypt_btn = ctk.CTkButton(
            self.button_frame,
            text="Decrypt Files",
            command=self.decrypt_selected
        )
        self.decrypt_btn.pack(side="left", padx=5)

        self.destroy_btn = ctk.CTkButton(
            self.button_frame,
            text="Destroy Files",
            command=self.destroy_selected,
            fg_color="red",
            hover_color="darkred"
        )
        self.destroy_btn.pack(side="left", padx=5)

        # Create drop zone
        self.drop_frame = ctk.CTkFrame(self.main_frame)
        self.drop_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.drop_label = ctk.CTkLabel(
            self.drop_frame,
            text="Click here to select files",
            font=("Arial", 14)
        )
        self.drop_label.pack(expand=True)

        # Create file list
        self.file_list = tk.Listbox(
            self.main_frame,
            selectmode=tk.MULTIPLE,
            background="#2b2b2b",
            foreground="white",
            selectbackground="#1f538d"
        )
        self.file_list.pack(fill="both", expand=True, padx=10, pady=10)

        # Progress bar
        self.progress = ttk.Progressbar(
            self.main_frame,
            mode='determinate',
            orient="horizontal"
        )
        self.progress.pack(fill="x", padx=10, pady=10)

        # Status label
        self.status_label = ctk.CTkLabel(
            self.main_frame,
            text="Ready",
            font=("Arial", 12)
        )
        self.status_label.pack(pady=5)

        # Bind click event for manual file selection
        self.drop_frame.bind("<Button-1>", self.select_files)
        self.drop_label.bind("<Button-1>", self.select_files)

        self.files: List[str] = []

    def save_credentials_to_file(self, password, salt):
        """Salva as credenciais em um arquivo"""
        try:
            credentials = {
                'password': password,
                'salt': salt,
                'timestamp': datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            }

            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")],
                initialfile=f"credentials_{credentials['timestamp']}.json"
            )

            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(credentials, f, indent=4)
                messagebox.showinfo("Success", "Credentials saved successfully!")
                return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save credentials: {str(e)}")
            return False

    def show_credentials_dialog(self, password, salt):
        """Mostra um diálogo com as credenciais que permite copiar"""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Encryption Credentials")
        dialog.geometry("600x400")

        # Fazer o diálogo modal
        dialog.transient(self.root)
        dialog.grab_set()

        # Frame para o conteúdo
        frame = ctk.CTkFrame(dialog)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Título
        ctk.CTkLabel(frame, text="SAVE THESE CREDENTIALS SECURELY!",
                     font=("Arial", 16, "bold")).pack(pady=10)

        # Password
        pw_frame = ctk.CTkFrame(frame)
        pw_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(pw_frame, text="Password:",
                     font=("Arial", 12, "bold")).pack(side="left", padx=5)
        pw_entry = ctk.CTkEntry(pw_frame, width=400)
        pw_entry.pack(side="left", padx=5)
        pw_entry.insert(0, password)
        pw_entry.configure(state="readonly")

        # Salt
        salt_frame = ctk.CTkFrame(frame)
        salt_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(salt_frame, text="Salt:",
                     font=("Arial", 12, "bold")).pack(side="left", padx=5)
        salt_entry = ctk.CTkEntry(salt_frame, width=400)
        salt_entry.pack(side="left", padx=5)
        salt_entry.insert(0, salt)
        salt_entry.configure(state="readonly")

        # Botões
        btn_frame = ctk.CTkFrame(frame)
        btn_frame.pack(fill="x", pady=20)

        ctk.CTkButton(
            btn_frame,
            text="Save to File",
            command=lambda: self.save_credentials_to_file(password, salt)
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="Close",
            command=dialog.destroy
        ).pack(side="right", padx=5)

        # Warning
        warning_text = (
            "WARNING: Store these credentials safely!\n"
            "You will need them to decrypt your files.\n"
            "Lost credentials cannot be recovered!"
        )
        ctk.CTkLabel(frame, text=warning_text,
                     text_color="red").pack(pady=20)

    def select_files(self, event=None):
        """Permite selecionar arquivos para processar"""
        files = filedialog.askopenfilenames()
        self.add_files(files)

    def add_files(self, new_files):
        """Adiciona novos arquivos à lista"""
        for file in new_files:
            if file not in self.files:
                self.files.append(file)
                self.file_list.insert(tk.END, os.path.basename(file))

    def get_selected_files(self) -> List[str]:
        """Retorna a lista de arquivos selecionados"""
        selections = self.file_list.curselection()
        return [self.files[i] for i in selections]

    def update_progress(self, value):
        """Atualiza a barra de progresso"""
        self.progress['value'] = value
        self.root.update_idletasks()

    def encrypt_selected(self):
        """Encripta os arquivos selecionados usando as mesmas credenciais"""
        files = self.get_selected_files()
        if not files:
            messagebox.showwarning("Warning", "Please select files to encrypt")
            return

        def encrypt_task():
            try:
                # Cria um novo handler para esta operação
                self.handler = SecureFileHandler()
                total_files = len(files)
                self.status_label.configure(text="Encrypting files...")

                for i, file in enumerate(files):
                    # Usa o mesmo handler para todos os arquivos
                    encrypted_path = self.handler.secure_encrypt(file)
                    progress = ((i + 1) / total_files) * 100
                    self.root.after(0, self.update_progress, progress)

                credentials = self.handler.get_credentials()
                self.root.after(0, self.show_credentials_dialog,
                                credentials['password'],
                                credentials['salt'])
                self.root.after(0, self.status_label.configure, {"text": "Ready"})
                self.root.after(0, self.update_progress, 0)

            except Exception as e:
                self.root.after(0, messagebox.showerror, "Error", str(e))

        threading.Thread(target=encrypt_task, daemon=True).start()

    def encrypt_and_delete_selected(self):
        """Encripta e deleta os arquivos selecionados usando as mesmas credenciais"""
        files = self.get_selected_files()
        if not files:
            messagebox.showwarning("Warning", "Please select files to encrypt and delete")
            return

        if not messagebox.askyesno("Confirm", "Selected files will be encrypted and then deleted. Continue?"):
            return

        def encrypt_delete_task():
            try:
                # Cria um novo handler para esta operação
                self.handler = SecureFileHandler()
                total_files = len(files)
                self.status_label.configure(text="Encrypting and deleting files...")

                for i, file in enumerate(files):
                    # Usa o mesmo handler para todos os arquivos
                    self.handler.process_secure(file)
                    progress = ((i + 1) / total_files) * 100
                    self.root.after(0, self.update_progress, progress)

                credentials = self.handler.get_credentials()
                self.root.after(0, self.show_credentials_dialog,
                                credentials['password'],
                                credentials['salt'])
                self.root.after(0, self.status_label.configure, {"text": "Ready"})
                self.root.after(0, self.update_progress, 0)

            except Exception as e:
                self.root.after(0, messagebox.showerror, "Error", str(e))

        threading.Thread(target=encrypt_delete_task, daemon=True).start()

    def decrypt_selected(self):
        """Decripta os arquivos selecionados"""
        files = self.get_selected_files()
        if not files:
            messagebox.showwarning("Warning", "Please select encrypted files to decrypt")
            return

        password = ctk.CTkInputDialog(
            text="Enter decryption password:",
            title="Password Required"
        ).get_input()
        if not password:
            return

        salt = ctk.CTkInputDialog(
            text="Enter salt value:",
            title="Salt Required"
        ).get_input()
        if not salt:
            return

        def decrypt_task():
            try:
                # Não criamos um novo handler aqui, apenas passamos as credenciais
                total_files = len(files)
                self.status_label.configure(text="Decrypting files...")

                for i, file in enumerate(files):
                    # Chama diretamente secure_decrypt do handler existente
                    decrypted_path = self.handler.secure_decrypt(file, password, salt)
                    progress = ((i + 1) / total_files) * 100
                    self.root.after(0, self.update_progress, progress)

                self.root.after(0, messagebox.showinfo, "Success", "Decryption Complete!")
                self.root.after(0, self.status_label.configure, {"text": "Ready"})
                self.root.after(0, self.update_progress, 0)

            except Exception as e:
                self.root.after(0, messagebox.showerror, "Error", f"Decryption error: {str(e)}")

        threading.Thread(target=decrypt_task, daemon=True).start()

    def destroy_selected(self):
        """Destroi permanentemente os arquivos selecionados"""
        files = self.get_selected_files()
        if not files:
            messagebox.showwarning("Warning", "Please select files to destroy")
            return

        total_size = sum(os.path.getsize(f) for f in files)
        size_gb = total_size / (1024 ** 3)

        if not messagebox.askyesno(
                "Confirm Destruction",
                f"WARNING: {len(files)} files ({size_gb:.2f}GB) will be permanently destroyed!\n\nContinue?"
        ):
            return

        def destroy_task():
            try:
                # Cria um novo handler para esta operação
                if self.handler is None:
                    self.handler = SecureFileHandler()

                self.status_label.configure(text="Destroying files...")

                total_files = len(files)
                for i, file in enumerate(files):
                    self.handler.destroy_large_path(file)
                    progress = ((i + 1) / total_files) * 100
                    self.root.after(0, self.update_progress, progress)

                self.root.after(0, messagebox.showinfo, "Success", "Files Destroyed Successfully")
                self.root.after(0, self.status_label.configure, {"text": "Ready"})
                self.root.after(0, self.update_progress, 0)

            except Exception as e:
                self.root.after(0, messagebox.showerror, "Error", str(e))

        threading.Thread(target=destroy_task, daemon=True).start()

    def run(self):
        """Inicia a aplicação"""
        self.root.mainloop()


if __name__ == "__main__":
    app = SecureFileGUI()
    app.run()