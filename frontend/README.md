# SecureFix AI · Frontend

The dashboard is served by a **separate static server**, not by the API backend.

## Run the frontend server

From the project root:

```bash
python scripts/serve_frontend.py
```

Then open: **http://localhost:3000/dashboard.html**

The dashboard will use `http://localhost:8000` as the API base when served on port 3000 or 8080. Ensure the backend is running:

```bash
uvicorn triggers.webhook_listener:app --host 0.0.0.0 --port 8000 --reload
```

## Custom port or API URL

- **Port:** `python scripts/serve_frontend.py 8080`
- **API URL:** `http://localhost:3000/dashboard.html?api=http://your-backend:8000`
