# Secure-Chat-Application-using-End-to-End-Encryption

Secure Browser-Based Chat App: A zero‑trust messaging platform using Flask + Socket.IO as a stateless relay. Client‑side ephemeral ECDH for forward secrecy, AES‑GCM per‑message encryption, JWT auth, and IndexedDB for key storage. All crypto runs in‑browser; server never sees plaintext or private keys.

## Key Features & Benefits

*   **End-to-End Encryption:**  Messages are encrypted on the sender's device and decrypted only on the recipient's device, ensuring privacy.
*   **Zero-Trust Architecture:** The server acts as a relay and never has access to plaintext messages or private keys.
*   **Ephemeral ECDH:**  Uses ephemeral ECDH for forward secrecy, meaning past communications remain secure even if private keys are compromised in the future.
*   **AES-GCM Encryption:**  Employs AES-GCM for robust per-message encryption.
*   **JWT Authentication:**  Uses JSON Web Tokens (JWT) for secure user authentication.
*   **Client-Side Key Storage:** Private keys are stored securely in the browser using IndexedDB.
*   **Browser-Based:**  All cryptographic operations are performed within the browser, minimizing server-side dependencies.
*   **Flask + Socket.IO:**  Utilizes Flask and Socket.IO for real-time communication.

## Prerequisites & Dependencies

Before you begin, ensure you have the following installed:

*   **Python 3.6+:**  The server-side logic is built with Python.
*   **pip:**  Python package installer.
*   **Node.js and npm (Optional):** Required if you wish to modify the frontend JavaScript code and build/bundle it.
*   **MongoDB:** Used for storing user data, login attempts, reset tokens, etc.
*   **Flask Mail:** Flask extension for sending emails (e.g., for password reset, OTP).

Python packages required:

*   Flask
*   Flask-CORS
*   Flask-SocketIO
*   PyMongo
*   Flask-Mail
*   PyJWT
*   Werkzeug
*   Eventlet

## Installation & Setup Instructions

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/AdvikNarendran/Secure-Chat-Application-using-End-to-End-Encryption.git
    cd Secure-Chat-Application-using-End-to-End-Encryption
    ```

2.  **Create a virtual environment (recommended):**

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Linux/macOS
    venv\Scripts\activate  # On Windows
    ```

3.  **Install Python dependencies:**

    ```bash
    pip install -r requirements.txt
    ```
    *(Note: You might need to create this file manually by listing all the dependencies, as it's not present in the given information)*

4.  **Configure environment variables:**

    *   Set `JWT_SECRET` environment variable to a strong, randomly generated secret.
    *   Configure MongoDB connection details.  (e.g., `MONGO_URI`)
    *   Configure Flask-Mail settings for sending emails (e.g., `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`).

    ```bash
    export JWT_SECRET="your_strong_jwt_secret"
    export MONGO_URI="mongodb://localhost:27017/your_database_name"
    # Example Flask-Mail configurations
    export MAIL_SERVER="smtp.example.com"
    export MAIL_PORT=587
    export MAIL_USERNAME="your_email@example.com"
    export MAIL_PASSWORD="your_email_password"
    ```

5.  **Set up MongoDB:**

    *   Ensure MongoDB is running.
    *   Create a database for the application.
    *   The application uses MongoDB collections for users, messages, login attempts, reset tokens, etc.  The code contains indexing logic (see `auth_otp.py`, `auth_security.py`) to ensure proper TTL expiry for OTPs and reset tokens.  Make sure the proper indexes exist in your MongoDB.

6. **Run the Flask application:**

   ```bash
   python app.py
   ```

   (The application will typically run on `http://127.0.0.1:5000/`)

7.  **Access the application in your browser:**

    Open your web browser and navigate to the address where the Flask application is running (e.g., `http://127.0.0.1:5000/`).

## Usage Examples & API Documentation

The application provides a browser-based chat interface. The client-side JavaScript code handles user authentication, key generation/management, encryption, and decryption.

*   **Registration:** Users can register a new account using the registration form.
*   **Login:**  Existing users can log in with their credentials. 2FA may be required if enabled.
*   **Chat:** Users can initiate private chats with other registered users.
*   **Key Exchange:**  The application implements an ephemeral ECDH key exchange to establish a shared secret for encryption.
*   **Message Encryption/Decryption:**  Messages are encrypted using AES-GCM before being sent and decrypted upon receipt.

**API Endpoints:**

*   `/auth/register` (POST): Registers a new user.
*   `/auth/login` (POST): Logs in an existing user.
*   `/auth/logout` (POST): Logs out the current user.
*   Other internal API calls are present within the files. Look into the source for more information.

## Configuration Options

*   **JWT Secret:**  The `JWT_SECRET` environment variable controls the secret key used to sign JWTs.  **This should be a strong, randomly generated string and kept confidential.**
*   **MongoDB URI:**  The `MONGO_URI` environment variable specifies the connection string for your MongoDB database.
*   **Flask-Mail settings:** `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD` are used to configure email sending functionality.
*   **OTP TTL:** The validity duration for OTP (One-Time Password) can be configured in `auth_otp.py` through the `OTP_TTL_SECONDS` variable or the TTL index in MongoDB.
*   **Redis:** The in-memory token blacklist in `auth.py` can be replaced with a Redis-backed blacklist for production deployments.

## Contributing Guidelines

We welcome contributions to the project! To contribute:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Make your changes and commit them with clear, descriptive commit messages.
4.  Submit a pull request.

Please follow these guidelines:

*   Adhere to the existing code style.
*   Write clear and concise code.
*   Include relevant tests for your changes.
*   Update the documentation as needed.

## License Information

License not specified.

## Acknowledgments

*   Flask:  A micro web framework for Python.
*   Socket.IO:  Enables real-time, bidirectional communication between web clients and servers.
*   PyMongo:  The official MongoDB driver for Python.
*   Forge.js: Javascript tool set used for cryptography. (Not listed explicitly, but based on the project description and features, likely in use within the Javascript files.)
