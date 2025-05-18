# MyGallery Flask Demo
# MyGallery Flask Demo

## About

MyGallery is a small Flask application showcasing core cybersecurity ideas for coursework:

* **Authentication**
  * Local username + password (scrypt hashes)
  * Google OAuth 2.0 / OpenID Connect via *Flask‑Dance*
* **Authorization (RBAC)** – two roles stored in JSON:
  * **Reader** – can view every photo
  * **Writer** – can upload photos (but cannot see the gallery content)
* **Persistence** – users, password hashes and roles are kept in a single `users.json` file (no database)


## Installation

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
python -m pip install -r requirements.txt
export GOOGLE_OAUTH_CLIENT_ID=YOUR_ID
export GOOGLE_OAUTH_CLIENT_SECRET=YOUR_SECRET
python app.py                 
```

