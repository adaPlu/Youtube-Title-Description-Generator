import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from tkinter import filedialog
from tkinter import ttk
import os
import requests
import time
import logging
import threading
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from cryptography.fernet import Fernet
import json
import base64
import uuid
import hashlib
import sys
import re

# Web server url change as needed prior to web hosting
SERVER_URL = "http://localhost:5000"  # Adjust as necessary


# Configure logging
logging.basicConfig(filename='Errors.log', filemode='a', format='%(name)s - %(levelname)s - %(message)s', level=logging.INFO)

# Function to check and manage log file size
def manage_log_file(file_path='Errors.log', max_size=5*1024*1024):  # 5 MB as max size
    """
    Check the log file size and delete it if it's too large, then recreate it.

    :param file_path: Path to the log file
    :param max_size: Maximum allowed file size in bytes
    """
    # Check if the file exists and its size
    if os.path.exists(file_path) and os.path.getsize(file_path) > max_size:
        # Delete the file if it's too large
        os.remove(file_path)
        # Recreate the log file by opening it in append mode and then closing it immediately
        with open(file_path, 'a') as file:
            pass  # The log file is recreated
# 
manage_log_file()

# Storage simulation
key_database = {}



def save_key(key):
    with open('encryption_key.key', 'wb') as file_key:
        file_key.write(key)

def load_key():
    key_path = 'encryption_key.key'
    if not os.path.exists(key_path):
        # If the key file doesn't exist, generate a new key and save it
        key = Fernet.generate_key()
        save_key(key)
    else:
        # Load the existing key
        with open(key_path, 'rb') as file_key:
            key = file_key.read()
    return key
    

# Generate a key for encryption and decryption
# For real use, save this key securely; if you lose it, you cannot decrypt your data
# Load or generate a key
key = load_key()
cipher_suite = Fernet(key)

def is_password_valid(password):
    """
    Checks if the password meets the requirements:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one symbol
    """
    if len(password) < 8:
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def hash_password(password, salt=None):
    """
    Hashes a password using SHA-256, with an optional salt.
    If no salt is provided, generates a new one.
    Returns the hash and the salt used.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a new 16-byte salt
    assert isinstance(salt, bytes), "Salt must be bytes"
    
    # Prepend the salt to the password before hashing
    hash_digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    # Return the hash digest and the salt used
    return hash_digest, salt

def register_or_verify_user(is_new_user):
    if is_new_user:
        username = simpledialog.askstring("New User Setup", "Enter a username:")
        password = simpledialog.askstring("New User Setup", "Create a password:", show="*")
        
        if not is_password_valid(password):
            messagebox.showerror("Invalid Password", "Password must be at least 8 characters long, contain at least one uppercase letter, and at least one symbol.")
            return  # Stop the registration process and let the user adjust the password
        
        # Secure handling before sending to the server
        hashed_password, salt = hash_password(password)
        registration_key = simpledialog.askstring("New User Setup", "Enter your registration key:")
        
        # Send hashed password and salt to the server
        response = requests.post(f"{SERVER_URL}/register", json={"username": username, "password": hashed_password.hex(), "salt": salt.hex(), "registration_key": registration_key})
        if response.status_code == 201:
            messagebox.showinfo("Registration", "Registration successful. Please login to continue.")
        else:
            messagebox.showerror("Registration Error", response.json().get('message', 'Unknown error during registration.'))
            sys.exit(1)
    else:
        username = simpledialog.askstring("Login", "Enter your username:")
        password = simpledialog.askstring("Login", "Enter your password:", show="*")
        
        # For the login process, we only send the username and password.
        # The server will retrieve the salt for this user, recompute the hash, and compare it.
        response = requests.post(f"{SERVER_URL}/verify", json={"username": username, "password": password})
        if response.status_code == 200:
            messagebox.showinfo("Login", "Login successful.")
            return True
        else:
            messagebox.showerror("Login Error", response.json().get('message', 'Verification failed. Please check your credentials.'))
            return False            
    
def encrypt_and_save_data(api_key, client_secrets_path):
    # Encrypt and encode the data
    encrypted_api_key = base64.urlsafe_b64encode(cipher_suite.encrypt(api_key.encode()))
    encrypted_client_secrets_path = base64.urlsafe_b64encode(cipher_suite.encrypt(client_secrets_path.encode()))
    
    # Save data
    with open("config.json", "w") as file:
        json.dump({
            "api_key": encrypted_api_key.decode(),
            "client_secrets_path": encrypted_client_secrets_path.decode()
        }, file)

def load_and_decrypt_data():
    # Load data
    if os.path.exists("config.json"):
        with open("config.json", "r") as file:
            data = json.load(file)
            decrypted_api_key = cipher_suite.decrypt(base64.urlsafe_b64decode(data["api_key"].encode())).decode()
            decrypted_client_secrets_path = cipher_suite.decrypt(base64.urlsafe_b64decode(data["client_secrets_path"].encode())).decode()
            return decrypted_api_key, decrypted_client_secrets_path
    return None, None
    

def get_credentials():
    api_key, client_secrets_path = load_and_decrypt_data()
    if api_key and client_secrets_path:
        return api_key, client_secrets_path
    else:
        # Prompt user for the details, then encrypt and save
        api_key = simpledialog.askstring("API Key", "Enter your OpenAI API Key:")
        client_secrets_path = filedialog.askopenfilename(title="Select your client secrets file", filetypes=[("JSON files", "*.json")])
        
        if api_key and client_secrets_path:
            encrypt_and_save_data(api_key, client_secrets_path)
        else:
            messagebox.showwarning("Warning", "API Key or Client Secrets File was not provided. The application will exit.")
            sys.exit(1)
    return api_key, client_secrets_path


def get_authenticated_service(client_secrets_file):
    scopes = ["https://www.googleapis.com/auth/youtube.force-ssl"]
    flow = InstalledAppFlow.from_client_secrets_file(client_secrets_file, scopes)
    credentials = flow.run_local_server(port=0)
    return build("youtube", "v3", credentials=credentials)

def fetch_upload_playlist_id(youtube):
    channels_response = youtube.channels().list(part="contentDetails", mine=True).execute()
    return channels_response['items'][0]['contentDetails']['relatedPlaylists']['uploads']


def generate_youtube_content(video_title, video_description, api_key):
    service_url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}"}
    prompt = f"Generate a search optimized YouTube video title, a brief description, and suggest some appropriate tags based on the following title and description:\n\nTitle: {video_title}\nDescription: {video_description}"
    data = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant designed to generate or optimize creative YouTube content, titles, descriptions, and tags."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7
    }
    for attempt in range(5):
        response = requests.post(service_url, headers=headers, json=data)
        if response.status_code == 200:
            content = response.json()
            choices = content.get("choices", [])
            if choices:
                generated_text = choices[0]['message']['content'].strip()
                return parse_generated_content(generated_text)
            else:
                logging.info(f"No generated content available for video title: {video_title}")
                messagebox.showinfo("Information", "No generated content available for the provided video title.")
            break
        elif response.status_code == 429:
            logging.warning(f"Rate limit exceeded on attempt {attempt + 1} for video title: {video_title}. Retrying...")
            messagebox.showwarning("Warning", f"Rate limit exceeded on attempt {attempt + 1}. Retrying...")
            time.sleep(1 * (2 ** attempt))
        else:
            logging.error(f"Failed to generate content due to an API error. Status Code: {response.status_code}, Response: {response.text}")
            messagebox.showerror("Error", f"Failed to generate content due to an API error. Status Code: {response.status_code}, Response: {response.text}")
            break
    return video_title, video_description, []

def parse_generated_content(generated_text):
    new_title, new_description, new_tags = None, None, []
    if "Title:" in generated_text and "Description:" in generated_text:
        title_part = generated_text.split("Description:")[0].strip()
        new_title = title_part.replace("Title:", "").strip()
        desc_and_tags_part = generated_text.split("Description:")[1].strip()
        if "Tags:" in desc_and_tags_part:
            new_description, tags_part = desc_and_tags_part.split("Tags:")
            new_tags = [tag.strip() for tag in tags_part.split(",") if tag.strip()]
        else:
            new_description = desc_and_tags_part
        new_description = new_description.strip()
    if not new_title or not new_description:
        logging.error("Failed to parse the title or description from the generated content.")
    return new_title, new_description, new_tags

def update_videos(youtube, uploads_playlist_id, api_key):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "0"
    video_counter, next_page_token = 0, None
    while next_page_token is not None or video_counter == 0:
        playlist_items_response = youtube.playlistItems().list(
            part="snippet",
            playlistId=uploads_playlist_id,
            maxResults=50,
            pageToken=next_page_token
        ).execute()
        for item in playlist_items_response.get('items', []):
            video_id = item['snippet']['resourceId']['videoId']
            video_title = item['snippet']['title']
            video_description = item['snippet']['description']
            
            # Check for blank or default titles/descriptions
            if not video_title or video_title.lower() in ["default title", ""] or not video_description or video_description.lower() in ["default description", ""]:
                logging.info(f"Skipping video ID {video_id} due to blank or default title/description.")
                continue
            
            new_title, new_description, new_tags = generate_youtube_content(video_title, video_description, api_key)
            if new_title and new_description:  # Ensure we have new content before updating
                update_video(youtube, video_id, new_title, new_description, new_tags)

            
        next_page_token = playlist_items_response.get('nextPageToken', None)
        
        
def get_total_video_count(youtube):
    """
    Retrieves the total number of videos uploaded to the authenticated user's YouTube channel.

    Parameters:
    - youtube: The authenticated YouTube API client object.

    Returns:
    - An integer representing the total number of videos, or None if the information cannot be retrieved.
    """
    try:
        # Make an API call to fetch channel details
        response = youtube.channels().list(
            part='statistics',
            mine=True  # Fetches the authenticated user's channel
        ).execute()

        # Extract the total video count from the response
        total_videos = int(response['items'][0]['statistics']['videoCount'])
        return total_videos
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def update_video(youtube, video_id, new_title, new_description, new_tags):
    update_request_body = {
        "id": video_id,
        "snippet": {
            "title": new_title,
            "description": new_description,
            "tags": new_tags,
            "categoryId": "22"
        }
    }
    try:
        update_request = youtube.videos().update(part="snippet", body=update_request_body)
        update_request.execute()
        logging.info(f"Video {video_id} updated successfully.")
    except Exception as error:
        logging.error(f"An error occurred: {error}")
        
#Updates one video
def update_one_video(youtube, video_id, new_title, new_description, new_tags):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "0"
    update_request_body = {
        "id": video_id,
        "snippet": {
            "title": new_title,
            "description": new_description,
            "tags": new_tags,
            "categoryId": "22"
        }
    }
    try:
        update_request = youtube.videos().update(part="snippet", body=update_request_body)
        update_request.execute()
        logging.info(f"Video {video_id} updated successfully.")
    except Exception as error:
        logging.error(f"An error occurred: {error}")
        
class YoutubeContentGeneratorGUI:
    def __init__(self, master):
        self.master = master
        master.title("YouTube Content Generator")
        
        # Start by verifying the user
        self.user_verification()
        
        self.api_key, self.client_secrets_file = get_credentials()
        
        if not self.api_key or not self.client_secrets_file:
            messagebox.showwarning("Warning", "OpenAI API Key or Client Secrets File was not provided. The application will exit.")
            master.destroy()
            return
        
        self.youtube = get_authenticated_service(self.client_secrets_file)
        self.total_videos = get_total_video_count(self.youtube)

        # Adjust layout for dynamic resizing
        master.grid_columnconfigure(1, weight=1)
        master.grid_rowconfigure([4, 5], weight=1)
        
        # Input fields
        tk.Label(master, text="Input Video Title:").grid(row=0, column=0, sticky="w")
        self.video_title_entry = tk.Entry(master)
        self.video_title_entry.grid(row=0, column=1, sticky="ew")

        tk.Label(master, text="Input Video Description:").grid(row=1, column=0, sticky="nw")
        self.video_description_entry = scrolledtext.ScrolledText(master, height=4)
        self.video_description_entry.grid(row=1, column=1, sticky="nsew", pady=5)

        # Output fields
        tk.Label(master, text="Generated Video Title:").grid(row=3, column=0, sticky="w")
        self.generated_title_output = scrolledtext.ScrolledText(master, height=2)
        self.generated_title_output.grid(row=3, column=1, sticky="ew")

        tk.Label(master, text="Generated Video Description:").grid(row=4, column=0, sticky="nw")
        self.generated_description_output = scrolledtext.ScrolledText(master, height=4)
        self.generated_description_output.grid(row=4, column=1, sticky="nsew")

        tk.Label(master, text="Generated Tags:").grid(row=5, column=0, sticky="nw")
        self.generated_tags_output = scrolledtext.ScrolledText(master, height=2)
        self.generated_tags_output.grid(row=5, column=1, sticky="nsew")

        # Buttons
        self.clear_button = tk.Button(master, text="Clear", command=self.clear_generated_content)
        self.clear_button.grid(row=2, column=2, sticky="ew")

        self.generate_button = tk.Button(master, text="Generate", command=self.generate_content)
        self.generate_button.grid(row=2, column=1, sticky="ew")
        
        # Button to update one video
        self.update_button = tk.Button(master, text="Update Video", command=self.update_one_video)
        self.update_button.grid(row=5, column=2, sticky="ew")

        # Button for auto-generating content. Increase the row number to position it below the "Update Video" button.
        # Note: Adjust the row number as needed based on your actual GUI layout.
        self.auto_generate_button = tk.Button(master, text="Auto Generate All", command=self.auto_generate_content)
        self.auto_generate_button.grid(row=6, column=1, sticky="ew")

        # Button to change the API key
        self.change_api_key_button = tk.Button(master, text="Change API Key", command=self.change_api_key)
        self.change_api_key_button.grid(row=7, column=1, sticky="ew", pady=(10,0))
        
        # Button to update the client secrets file
        self.update_client_secrets_button = tk.Button(master, text="Update Client Secrets File", command=self.update_client_secrets)
        self.update_client_secrets_button.grid(row=8, column=1, sticky="ew")

        # Adjust layout for dynamic resizing
        master.grid_columnconfigure(1, weight=1)
        master.grid_rowconfigure([4, 5, 6, 7, 8], weight=1)  # Adjust row configurations as needed

    def change_api_key(self):
        # Prompt the user for the new API key
        new_api_key = simpledialog.askstring("New API Key", "Enter your new OpenAI API Key:")
        if new_api_key:
            # Encrypt and save the new API key along with the existing client secrets path
            encrypt_and_save_data(new_api_key, self.client_secrets_file)
            messagebox.showinfo("Success", "API Key updated successfully.")
            self.api_key = new_api_key

    def update_client_secrets(self):
        # Prompt the user for the new client secrets file
        new_client_secrets_path = filedialog.askopenfilename(title="Select your new client secrets file", filetypes=[("JSON files", "*.json")])
        if new_client_secrets_path:
            # Encrypt and save the new client secrets path along with the existing API key
            encrypt_and_save_data(self.api_key, new_client_secrets_path)
            messagebox.showinfo("Success", "Client Secrets File updated successfully.")
            self.client_secrets_file = new_client_secrets_path


    def generate_content(self):
        video_title = self.video_title_entry.get()  # This is correct for Entry widgets
        video_description = self.video_description_entry.get("1.0", tk.END+"-1c")  # Correct for ScrolledText or Text widgets
        try:
            new_title, new_description, new_tags = generate_youtube_content(video_title, video_description, self.api_key)
            self.generated_title_output.delete('1.0', tk.END)
            self.generated_title_output.insert(tk.INSERT, new_title)
            self.generated_description_output.delete('1.0', tk.END)
            self.generated_description_output.insert(tk.INSERT, new_description)
            self.generated_tags_output.delete('1.0', tk.END)
            self.generated_tags_output.insert(tk.INSERT, ", ".join(new_tags))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate content: {str(e)}")

    def update_one_video(self):
        video_id = simpledialog.askstring("Update Video", "Enter Video ID:")
        if video_id:
            try:
                new_title = self.generated_title_output.get('1.0', tk.END).strip()
                new_description = self.generated_description_output.get('1.0', tk.END).strip()
                # Assuming tags are comma-separated in the tags ScrolledText widget
                new_tags = self.generated_tags_output.get('1.0', tk.END).strip().split(", ")
                # Filtering out empty strings in case of trailing commas
                new_tags = [tag for tag in new_tags if tag]
                try:
                    update_video(self.youtube, video_id, new_title, new_description, new_tags)
                    messagebox.showinfo("Success", "Video updated successfully.")
                except Exception as error:
                    logging.error(f"An error occurred: {error}")
                    messagebox.showerror("Error", f"Failed to update video: {str(error)}")
            except Exception as error:
                logging.error(f"An error occurred: {error}")
                messagebox.showerror("Error", f"Failed to update video: {str(error)}")
        else:
            messagebox.showinfo("Cancelled", "Operation cancelled.")
            
    def auto_generate_content(self):
        self.auto_generate_button.config(state='disabled')
        threading.Thread(target=self._auto_generate_task).start()
        

    def _auto_generate_task(self):
        # Set the maximum value of the progress bar to the total number of videos
        self.master.after(0, lambda: self.progress.configure(maximum=self.total_videos, value=0))
        try:
            uploads_playlist_id = fetch_upload_playlist_id(self.youtube)
            update_videos(self.youtube, uploads_playlist_id, self.api_key)
            # Inform the user that auto-generation is complete
            # Note: Since this runs in a thread, use `master.after` to safely interact with the GUI
            self.master.after(0, lambda: messagebox.showinfo("Auto Generate", "Auto-generation of titles, descriptions, and tags is complete."))
        except Exception as e:
            # Display any errors that occur during the auto-generation process
            self.master.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            # Reset the progress bar and re-enable the button once done
            self.master.after(0, self.progress.stop)
            self.master.after(0, lambda: self.auto_generate_button.config(state='normal'))
        
            # Inform the user that the process is complete
            self.master.after(0, lambda: messagebox.showinfo("Completion", "Auto-generation completed."))
            
    def clear_generated_content(self):
         # Clear input fields
        self.video_title_entry.delete(0, tk.END)
        #self.video_description_entry.delete(0, tk.END)
        self.video_description_entry.delete("1.0", tk.END)

    
        # Clear output fields
        self.generated_title_output.delete('1.0', tk.END)
        self.generated_description_output.delete('1.0', tk.END)
        self.generated_tags_output.delete('1.0', tk.END)

    def user_verification(self):
        while True:
            is_new_user = messagebox.askyesno("New User", "Are you a new user?")
            success, message = register_or_verify_user(is_new_user)
            if success:
                break  # Exit the loop if registration or login is successful
            else:
                messagebox.showerror("Error", message)
                # If user chooses to cancel, break the loop to prevent being stuck in it
                if not messagebox.askretrycancel("Retry", "Would you like to try again?"):
                    sys.exit(1)  # Exit the application if the user chooses not to retry


    def user_verification2(self):
        is_new_user = messagebox.askyesno("New User", "Are you a new user?")
        register_or_verify_user(is_new_user)
        if not is_new_user:
            # For returning users, ensure the credentials are correct before proceeding
            loggedIn = False
            while not loggedIn:
                loggedIn = register_or_verify_user(is_new_user)
   
def main():
    root = tk.Tk()
    gui = YoutubeContentGeneratorGUI(root)
    root.geometry("800x600")  # Initial size of the window
    root.mainloop()

if __name__ == "__main__":
    main()
