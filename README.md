# YouTube Title & Description Generator (ChatGPT-Powered)

This repository contains multiple Python scripts and examples for generating SEO-friendly YouTube video titles, descriptions, and tags using OpenAI’s ChatGPT (GPT-3.5/GPT-4). It supports:

1. A **Command-Line Interface (CLI)** application  
2. A **GUI** application in Python (Tkinter)  
3. An **unfinished Client–Server** example using Flask (server) and Tkinter (client)

The goal is to demonstrate various ways of integrating AI-based text generation into a workflow that optimizes YouTube content.

---

## Table of Contents

1. [Overview of Files](#overview-of-files)  
2. [Key Features](#key-features)  
3. [Prerequisites & Installation](#prerequisites--installation)  
4. [Usage](#usage)  
   - [Command-Line Version](#command-line-version)  
   - [GUI Version](#gui-version)  
   - [Client–Server Version](#clientserver-version)  
5. [Configuration & Credentials](#configuration--credentials)  
6. [Logging & Troubleshooting](#logging--troubleshooting)  
7. [Notes on Security](#notes-on-security)  
8. [License](#license)

---

## 1. Overview of Files

| **File**                  | **Purpose**                                                     |
|---------------------------|-----------------------------------------------------------------|
| **YoutubeTitler.py**      | Primary Python Tkinter GUI application (YouTube generation).    |
| **YoutubeTitler.spec**    | PyInstaller spec file (for packaging the Tkinter GUI).          |
| **YoutubeTitlerCLI.py**   | Command-line interface (CLI) application.                       |
| **YoutubeTitlerClient.py**      | Unfinished client script (Tkinter-based) for a Client–Server setup. |
| **YoutubeTitlerClientTest.py**  | Additional/in-progress client script and user-management code.       |
| **YoutubeTitlerServer** (binary / not fully visible) | Possibly an older or partially compiled server artifact.          |
| **YoutubeTitlerServer.py**     | Flask-based server application for user registration, login, etc.    |
| **YoutubeTitlerServer2.py**    | An alternate/experimental version of the Flask server code.          |
| **YoutubeTitlerTest.py**       | Testing utilities for the GUI/Client or demonstration code.          |
| **Errors.log** (created at runtime) | Log file used to store application logs and API errors.           |
| **config.json** (created at runtime) | Stores encrypted credentials (OpenAI key, Google client secret). |

> **Note**: Some files are truncated in the provided view, but the core functionality is captured here.  

---

## 2. Key Features

- **Generate Optimized YouTube Titles & Descriptions**  
  Leverages OpenAI’s ChatGPT to produce compelling, SEO-friendly titles, descriptions, and tag suggestions.

- **Multiple Interfaces**  
  - **CLI** version for quick, no-frills usage.  
  - **GUI** version (Tkinter) for a more user-friendly approach (field inputs, buttons, progress).  
  - **Client–Server** prototype for registering users, logging in, and processing AI requests on the server side.

- **Google YouTube API Integration**  
  Scripts can authenticate with YouTube via **OAuth** to update video metadata (title/description/tags) directly on your channel.

- **Encryption & Basic Security**  
  - Local encryption (via **Fernet**) to store your OpenAI API key and Google OAuth client secrets in `config.json`.  
  - Basic user registration & login (unfinished) in the client–server version, including hashed passwords and registration keys.

---

## 3. Prerequisites & Installation

1. **Python 3.7+** recommended.

2. **Install Dependencies**  
   - Many scripts reference the following libraries (not exhaustive):  
     - `requests` (for OpenAI requests)  
     - `google-auth-oauthlib`, `google-api-python-client` (for YouTube API)  
     - `cryptography` (for key-based encryption)  
     - `flask` & `flask_sqlalchemy` (for the server scripts)  
     - `tkinter` (built into most Python installations for the GUI)  

   If you have a `requirements.txt`, run:
   ```bash
   pip install -r requirements.txt
   ```
   Otherwise, install manually:
   ```bash
   pip install requests google-api-python-client google-auth-oauthlib cryptography flask flask_sqlalchemy
   ```

3. **(Optional) Create & Activate a Virtual Environment**  
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   ```

4. **OpenAI API Key**  
   - Sign up at [OpenAI’s Platform](https://platform.openai.com/) to get an API key.

5. **Google OAuth Client Secrets**  
   - Create OAuth credentials in your [Google Cloud Console](https://console.cloud.google.com/)  
   - Download the `client_secrets.json` file.

6. **(Optional) Database Setup** (for the server code)  
   - `YoutubeTitlerServer.py` and `YoutubeTitlerServer2.py` expect a database, such as PostgreSQL.  
   - Update environment variables (`DATABASE_URL`, etc.) if you plan to run the server for user management.

---

## 4. Usage

### Command-Line Version

1. **Set Environment Variables**  
   - `OPENAI_API_KEY` for your OpenAI key.  
   - `CLIENT_SECRETS_FILE` for your `client_secrets.json` path.

2. **Run the CLI**  
   ```bash
   python YoutubeTitlerCLI.py
   ```
3. **Follow Prompts**  
   - The script authenticates with YouTube, retrieves your videos, and attempts to update them with optimized titles/descriptions.

**Note**: Depending on the code, the CLI may only process a certain range of videos (e.g., 911–999). Adjust as needed.

---

### GUI Version

1. **Run `YoutubeTitler.py`**  
   ```bash
   python YoutubeTitler.py
   ```
2. **Enter API & OAuth Details** (if asked)  
   - On first run, a dialog will appear prompting for your OpenAI API key and Google client secrets file.  
   - These credentials are encrypted and stored locally in `config.json`.

3. **Interact with the GUI**  
   - A Tkinter window allows you to input or refine your video titles and descriptions.  
   - You can then update your YouTube channel metadata directly if the code is configured to do so.

---

### Client–Server Version

> **Status**: **Unfinished** proof-of-concept. Shows how you could create a multi-user system that logs in/out and calls OpenAI from a server.

1. **Server**  
   - Check either `YoutubeTitlerServer.py` or `YoutubeTitlerServer2.py`.  
   - Update your environment variables for `DATABASE_URL`, `MAIL_USERNAME`, `MAIL_PASSWORD`, etc. (if using email).  
   - Launch the server:
     ```bash
     python YoutubeTitlerServer.py
     ```
   - The server starts on `localhost:5000` by default, offering endpoints for registration, login, key generation, etc.

2. **Client**  
   - Run `YoutubeTitlerClient.py` or `YoutubeTitlerClientTest.py`.  
   - On startup, you may be prompted to register or log in (username/password).  
   - Once authenticated, the client is intended to send requests to the server for generating titles/descriptions.  

> Since this portion is incomplete, certain flows (e.g., advanced user management or direct integration with YouTube) may not be fully operational. Use the code as a reference for building a robust system.

---

## 5. Configuration & Credentials

- **OpenAI API Key**:  
  - Stored in `config.json` after encryption by the scripts (GUI or client).  
  - Alternatively, load from an environment variable like `OPENAI_API_KEY`.

- **Google OAuth**:  
  - The scripts rely on a `client_secrets.json` file for OAuth 2.0 authentication with YouTube.  
  - The location is prompted on first run, then encrypted into `config.json`.

- **Database URL** (Server scripts):  
  - `YoutubeTitlerServer.py` / `YoutubeTitlerServer2.py` default to PostgreSQL via `DATABASE_URL` environment variable.  
  - Adjust or switch to SQLite if desired.

---

## 6. Logging & Troubleshooting

- **Logs**:  
  - The code writes logs to `Errors.log`.  
  - Each script checks file size and rotates/deletes the log if it exceeds ~5MB.  

- **Common Issues**:  
  - **Rate Limiting** (OpenAI): The code retries up to 5 times if you exceed your API rate.  
  - **HTTP 429**: Wait for rate-limits to reset or reduce the request volume.  
  - **Credential Prompts**: If you see repeated prompts for API keys/client secrets, ensure `config.json` is writable.  
  - **Flask or Database**: If the server fails to start, confirm your DB connection string is correct.

---

## 7. Notes on Security

- **Encryption**:  
  - A local `encryption_key.key` is generated (if none exists) and stored in your folder.  
  - This key is used with `cryptography.Fernet` to encrypt credentials in `config.json`.  
  - Do not commit `config.json` or `encryption_key.key` to public repositories.

- **User Registration Keys** (Server side):  
  - The server can generate or store unique registration keys in a `RegistrationKey` table.  
  - These are used for controlling who can register for the system.  
  - Passwords are hashed with a salt (`pbkdf2_hmac`) before being stored in the DB.

---

## 8. License

Choose or add a license that fits your needs (e.g., [MIT License](https://opensource.org/licenses/MIT)), and include it here.  

---

**Thank you for using the YouTube Title & Description Generator!**  
For any questions, feel free to open issues or contribute new features. Enjoy optimizing your channel’s metadata with AI!
