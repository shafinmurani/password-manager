import tkinter as tk
from tkinter import messagebox
import sqlite3
from cryptography.fernet import Fernet
from tkinter import font as tkfont


class PasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")

        # Use Roboto font and increase font size by 2
        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(family="Roboto", size=default_font.cget("size") + 2)

        # Set the window size
        window_width = 380
        window_height = 300
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()

        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 2

        self.master.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

        # Create a frame to contain all widgets
        content_frame = tk.Frame(master)
        content_frame.grid(row=0, column=0, padx=20, pady=20)

        # GUI elements
        self.label_website = tk.Label(content_frame, text="Website:")
        self.label_username = tk.Label(content_frame, text="Username:")
        self.label_password = tk.Label(content_frame, text="Password:")

        self.entry_website = tk.Entry(content_frame)
        self.entry_username = tk.Entry(content_frame)
        self.entry_password = tk.Entry(content_frame, show="*")

        self.label_search = tk.Label(content_frame, text="Search:")
        self.entry_search = tk.Entry(content_frame, textvariable=tk.StringVar())
        self.button_search = tk.Button(content_frame, text="Search", command=self.search_passwords)

        self.button_save = tk.Button(content_frame, text="Save", command=self.save_password)
        self.button_show_passwords = tk.Button(content_frame, text="Show Passwords", command=self.show_passwords)

        # Grid layout for content
        self.label_website.grid(row=0,
                                column=0,
                                sticky=tk.E,
                                pady=5)

        self.label_username.grid(row=1,
                                 column=0,
                                 sticky=tk.E,
                                 pady=5)

        self.label_password.grid(row=2,
                                 column=0,
                                 sticky=tk.E,
                                 pady=5)

        self.entry_website.grid(row=0,
                                column=1,
                                padx=10,
                                pady=5)

        self.entry_username.grid(row=1,
                                 column=1,
                                 padx=10,
                                 pady=5)

        self.entry_password.grid(row=2,
                                 column=1,
                                 padx=10,
                                 pady=5)

        self.label_search.grid(row=3,
                               column=0,
                               sticky=tk.E,
                               pady=5)

        self.entry_search.grid(row=3,
                               column=1,
                               padx=10,
                               pady=5)

        self.button_search.grid(row=3,
                                column=2,
                                padx=10,
                                pady=5)

        self.button_save.grid(row=4, column=1, pady=10)
        self.button_show_passwords.grid(row=5, column=1)

        # Initialize the database connection and encryption key
        self.conn = sqlite3.connect("passwords.db")
        self.c = self.conn.cursor()
        self.key = self.load_or_generate_key()

        # Create the 'passwords' table if not exists
        self.c.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT,
                username TEXT,
                password TEXT
            )
        ''')
        self.conn.commit()

    @staticmethod
    def load_or_generate_key():
        try:
            with open('key.key', 'rb') as key_file:
                key = key_file.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open('key.key', 'wb') as key_file:
                key_file.write(key)
        return key

    def encrypt_password(self, password):
        cipher_suite = Fernet(self.key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        return encrypted_password

    def decrypt_password(self, encrypted_password):
        try:
            cipher_suite = Fernet(self.key)
            decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
            return decrypted_password
        except Exception as e:
            print(f"Error decrypting password: {str(e)}")
            return "Decryption Error"

    def save_password(self):
        website = self.entry_website.get()
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not website or not username or not password:
            messagebox.showwarning("Incomplete Information", "Please enter website, username, and password.")
            return

        # Encrypt the password before storing
        encrypted_password = self.encrypt_password(password)

        # Insert data into the 'passwords' table
        self.c.execute('INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)',
                       (website, username, encrypted_password))
        self.conn.commit()

        messagebox.showinfo("Success", "Password saved successfully!")

        # Clear the entry fields
        self.entry_website.delete(0, tk.END)
        self.entry_username.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)

    def show_passwords(self):
        # Fetch all passwords from the 'passwords' table
        self.c.execute('SELECT website, username, password FROM passwords')
        passwords = self.c.fetchall()

        # Display passwords in a new window
        if passwords:
            new_window = tk.Toplevel(self.master)
            new_window.title("Stored Passwords")

            text_widget = tk.Text(new_window)
            text_widget.pack()

            for entry in passwords:
                # Decrypt the password before displaying
                decrypted_password = self.decrypt_password(entry[2])
                text_widget.insert(tk.END,
                                   f"Website: {entry[0]}\n")
                text_widget.insert(tk.END, f"Username: {entry[1]}\n")
                text_widget.insert(tk.END, f"Password: {decrypted_password}\n\n")
        else:
            messagebox.showinfo("No Passwords", "No passwords stored yet.")

    def search_passwords(self):
        # Get the search query from the entry
        search_query = self.entry_search.get().strip()

        if not search_query:
            messagebox.showinfo("Empty Search", "Please enter a search query.")
            return

        # Fetch matching passwords from the 'passwords' table
        self.c.execute('''
            SELECT website, username, password
            FROM passwords
            WHERE website LIKE ? OR username LIKE ?
        ''', (f'%{search_query}%', f'%{search_query}%'))

        matching_passwords = self.c.fetchall()

        # Display matching passwords in a new window
        if matching_passwords:
            new_window = tk.Toplevel(self.master)
            new_window.title("Matching Passwords")

            text_widget = tk.Text(new_window)
            text_widget.pack()

            for entry in matching_passwords:
                # Decrypt the password before displaying
                decrypted_password = self.decrypt_password(entry[2])
                text_widget.insert(tk.END,
                                   f"Website: {entry[0]}\n")
                text_widget.insert(tk.END, f"Username: {entry[1]}\n")
                text_widget.insert(tk.END, f"Password: {decrypted_password}\n\n")
        else:
            messagebox.showinfo("No Matches", f"No passwords match the search query: {search_query}.")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
