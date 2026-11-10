# Deployment Guide: Render (Backend) & Vercel (Frontend)

This guide provides instructions for deploying the **Xray Binary** platform to production:
- **Backend Web Service**: [Render](https://render.com) (FastAPI + Graph Neural Network pipeline + Weisfeiler-Lehman Engine)
- **Frontend SPA / Static Site**: [Vercel](https://vercel.com) (Modern Tailwind UI, DitherVeil WebGL landing, Interactive Graph Visualizer)

---

## Architecture Overview

```
[Client Browser]
       │
       ├──► [Vercel: Frontend] (https://xray-binary.vercel.app)
       │         │
       │         ├── Landing Page (/)
       │         ├── Dashboard App (/app or /dashboard)
       │         └── API Proxy Rewrites (/api/*) ──────┐
       │                                               │
       └───────────────────────────────────────────────┼──► [Render: Web Service] (https://xray-binary-api.onrender.com)
                                                       │        │
                                                       │        ├── /api/v1/health (Health check)
                                                       │        ├── /api/v1/auth/* (Google OAuth & Session JWT)
                                                       │        ├── /api/v1/analyze (CFG Extraction & GIN Analysis)
                                                       │        ├── /api/v1/samples (Sample binaries & benchmark data)
                                                       │        └── /api/v1/settings (Detection engine thresholds)
```

---

## 1. Backend Deployment (Render)

Render runs the FastAPI server with dynamic `$PORT` handling and GNN analysis packages.

### Option A: 1-Click Blueprint (Recommended)
1. Fork or push your code to your GitHub / GitLab repository.
2. In the [Render Dashboard](https://dashboard.render.com), click **New +** > **Blueprint**.
3. Select your repository. Render will automatically read `render.yaml`.
4. Fill in the required environment variables:
   - `GOOGLE_CLIENT_ID`: Your Google Cloud OAuth Client ID (optional if using email/demo auth).
   - `GOOGLE_CLIENT_SECRET`: Your Google Cloud OAuth Client Secret (optional if using email/demo auth).
5. Click **Apply**. Render will build and deploy the service automatically.

### Option B: Manual Web Service Setup
If creating the service manually:
1. In Render Dashboard, click **New +** > **Web Service**.
2. Connect your Git repository.
3. Configure the settings:
   - **Name**: `xray-binary-api`
   - **Environment**: `Python 3`
   - **Region**: Oregon (US West) or Frankfurt (EU Central)
   - **Branch**: `main`
   - **Root Directory**: leave blank (root)
   - **Build Command**:
     ```bash
     pip install --upgrade pip && pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     uvicorn apps.api.main:app --host 0.0.0.0 --port $PORT
     ```
4. **Environment Variables**:
   | Variable | Value | Notes |
   |---|---|---|
   | `PYTHONPATH` | `packages:.` | Required for importing `packages.analysis.*` |
   | `PYTHON_VERSION` | `3.11.9` or `3.12.0` | Recommended Python version |
   | `GOOGLE_CLIENT_ID` | `your-google-client-id` | For Google Sign-In |
   | `GOOGLE_CLIENT_SECRET` | `your-google-client-secret` | For Google OAuth code exchange |
5. Click **Create Web Service**.
6. Note down your Render service URL (e.g., `https://xray-binary-api.onrender.com`).

### Verify Render Deployment
Test the health endpoint from your terminal or browser:
```bash
curl https://xray-binary-api.onrender.com/api/v1/health
```
Expected response:
```json
{
  "status": "healthy",
  "pipeline_mode": "weisfeiler_lehman_and_gin_fusion",
  "auth_configured": true
}
```

---

## 2. Frontend Deployment (Vercel)

The frontend is an interactive single-page application and landing page with built-in API proxy routing and asset caching.

### Step-by-Step Vercel Setup
1. In the [Vercel Dashboard](https://vercel.com/dashboard), click **Add New...** > **Project**.
2. Select your `xray-binary-docs` GitHub repository.
3. In the project configuration:
   - **Framework Preset**: `Other`
   - **Root Directory**: `./` (leave default)
   - **Build Command**: leave empty (or `npm run build` which does `echo 'Ready'`)
   - **Output Directory**: leave empty
4. *(Optional)* If you already know your Render backend URL, update the rewrite destination in `vercel.json`:
   ```json
   {
     "source": "/api/:match*",
     "destination": "https://<your-render-service-name>.onrender.com/api/:match*"
   }
   ```
   *(Or push the updated `vercel.json` to your repository branch).*
5. Click **Deploy**. Vercel will deploy within seconds.

---

## 3. Connecting Frontend to Backend

You have two seamless ways to connect the Vercel frontend to your Render backend:

### Method 1: Zero-Config UI Setting (Instant)
1. Open your deployed Vercel application in your browser (e.g. `https://xray-binary.vercel.app/app`).
2. Log in (or use test analyst credentials `analyst@xray-binary.io` / `password`).
3. Click the **Settings** tab in the left sidebar.
4. Scroll to the **Engine Diagnostics & Telemetry** section.
5. In the **Render Backend Web Service URL** field, paste your Render URL:
   ```
   https://xray-binary-api.onrender.com
   ```
6. Click **Save**.
7. The diagnostics probe will automatically run and confirm:
   - Latency in milliseconds
   - Backend health status (`healthy`)
   - GIN / Weisfeiler-Lehman pipeline readiness
   - Google OAuth provider synchronization

### Method 2: Vercel Proxy Rewrite (Seamless Same-Origin)
In `vercel.json` (and `apps/web/vercel.json`), set:
```json
"rewrites": [
  {
    "source": "/api/:match*",
    "destination": "https://YOUR-RENDER-SERVICE.onrender.com/api/:match*"
  }
]
```
Commit and push. All requests from the frontend to `/api/*` will be proxied seamlessly without any browser CORS overhead.

---

## 4. Google OAuth Configuration (For Production)

If using Google One-Tap or Google Sign-In with your custom domain:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Select your OAuth 2.0 Client ID.
3. Under **Authorized JavaScript origins**, add:
   - Your Vercel frontend domain: `https://your-app.vercel.app`
   - Custom domain (if applicable): `https://xray.yourdomain.com`
   - Localhost (for development): `http://localhost:8000`, `http://127.0.0.1:8000`
4. Under **Authorized redirect URIs**, add:
   - `https://your-app.vercel.app`
   - `https://your-app.vercel.app/app`
   - `https://your-render-service.onrender.com/api/v1/auth/google/callback`
5. Save the configuration in Google Cloud Console.

---

## 5. Deployment Verification Checklist

| Item | Test | Expected Result |
|---|---|---|
| **Backend Health** | `GET /api/v1/health` | HTTP 200 `{"status": "healthy"}` |
| **Auth Config** | `GET /api/v1/auth/config` | HTTP 200 with `client_id` (masked or configured) |
| **Landing Page** | `GET /` | HTTP 200, WebGL DitherVeil canvas rendering |
| **Auth Gate** | Direct navigate `/app` unauthenticated | Login gate displayed, no sensitive data leaked |
| **Diagnostics Probe** | Settings -> Test Backend Connection | Green checkmark, `< 250ms` latency |
| **Sample Analysis** | Run analysis on preset sample binary | Graph nodes rendered, motifs detected, report exportable |

---

## Troubleshooting

- **Render Cold Starts**: On Render's Free tier, services spin down after 15 minutes of inactivity. The first request after sleep may take ~30-50 seconds. The frontend includes automatic connection diagnostics and retry logic.
- **CORS Errors**: The backend CORS middleware in `apps/api/main.py` is configured with `allow_origin_regex=r"https?://.*"`, allowing requests from any Vercel domain or preview URL (`*.vercel.app`) with credentials enabled.
- **Port Binding**: Render requires dynamic port binding via `$PORT`. Both `apps/api/main.py` and `Dockerfile` automatically detect and bind to `${PORT:-8000}`.

