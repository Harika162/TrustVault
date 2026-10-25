import { useEffect, useState } from "react";
import "./App.css";

const API = "/api";

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    credentials: "include",
    ...options,
    headers: {
      ...(options.body instanceof FormData
        ? {}
        : { "Content-Type": "application/json" }),
      ...(options.headers || {}),
    },
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.message || `Request failed (${response.status})`);
  }

  return data;
}

function App() {
  const [isRegister, setIsRegister] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [user, setUser] = useState(null);
  const [documents, setDocuments] = useState([]);
  const [file, setFile] = useState(null);
  const [search, setSearch] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiRequest("/me")
      .then((data) => {
        setUser(data.user);
        return loadDocuments();
      })
      .catch(() => {
        // No active session.
      });

    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadDocuments(searchTerm = search) {
    try {
      const query = searchTerm.trim()
        ? `?q=${encodeURIComponent(searchTerm.trim())}`
        : "";

      const data = await apiRequest(`/documents${query}`);
      setDocuments(data.documents || []);
    } catch (err) {
      setError(err.message);
    }
  }

  function resetNotices() {
    setMessage("");
    setError("");
  }

  async function handleAuth(event) {
    event.preventDefault();
    resetNotices();
    setBusy(true);

    try {
      const payload = isRegister
        ? { name: name.trim(), email: email.trim(), password }
        : { email: email.trim(), password };

      const data = await apiRequest(
        isRegister ? "/register" : "/login",
        {
          method: "POST",
          body: JSON.stringify(payload),
        }
      );

      if (isRegister) {
        setMessage(data.message || "Account created. Please sign in.");
        setIsRegister(false);
        setPassword("");
      } else {
        setUser(data.user);
        setMessage(data.message || "Signed in successfully.");
        setPassword("");
        await loadDocuments("");
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleLogout() {
    resetNotices();

    try {
      await apiRequest("/logout", {
        method: "POST",
        body: "{}",
      });

      setUser(null);
      setDocuments([]);
      setFile(null);
      setMessage("You have been signed out.");
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleUpload(event) {
    event.preventDefault();
    resetNotices();

    if (!file) {
      setError("Please select a document first.");
      return;
    }

    const formData = new FormData();
    formData.append("document", file);

    setBusy(true);

    try {
      const data = await apiRequest("/documents", {
        method: "POST",
        body: formData,
      });

      setMessage(data.message || "Document uploaded.");
      setFile(null);
      event.target.reset();
      await loadDocuments();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete(documentId) {
    if (!window.confirm("Delete this document permanently?")) return;

    resetNotices();

    try {
      const data = await apiRequest(`/documents/${documentId}`, {
        method: "DELETE",
      });

      setMessage(data.message || "Document deleted.");
      await loadDocuments();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleVerify(documentId) {
    resetNotices();

    try {
      const data = await apiRequest(
        `/documents/${documentId}/verify`
      );

      setMessage(
        `${data.filename}: ${
          data.integrity_ok
            ? "Integrity verified"
            : "Verification failed"
        }`
      );
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleSearch(event) {
    event.preventDefault();
    await loadDocuments(search);
  }

  return (
    <div className="app-container">
      <nav className="navbar">
        <h2 className="logo">🔐 TrustVault</h2>

        <span className="nav-tagline">
          Secure Document Sharing
        </span>

        {user && (
          <button
            type="button"
            className="switch-button"
            onClick={handleLogout}
          >
            Sign Out
          </button>
        )}
      </nav>

      <main className="auth-container">
        {message && (
          <div
            className="flash-message success-message"
            role="status"
          >
            {message}
          </div>
        )}

        {error && (
          <div
            className="flash-message error-message"
            role="alert"
          >
            {error}
          </div>
        )}

        {!user ? (
          <section className="auth-card">
            <div className="auth-form-panel">
              <div className="auth-form-content">
                <div className="auth-icon">🔒</div>

                <h1>
                  {isRegister ? "Create Account" : "Sign In"}
                </h1>

                <p className="subtitle">
                  {isRegister
                    ? "Create your secure TrustVault account"
                    : "Welcome back! Sign in to your account"}
                </p>

                <form onSubmit={handleAuth}>
                  {isRegister && (
                    <div className="form-group">
                      <label htmlFor="name">Full Name</label>

                      <input
                        id="name"
                        type="text"
                        placeholder="Enter your full name"
                        value={name}
                        onChange={(event) =>
                          setName(event.target.value)
                        }
                        maxLength={100}
                        required
                      />
                    </div>
                  )}

                  <div className="form-group">
                    <label htmlFor="email">
                      Email Address
                    </label>

                    <input
                      id="email"
                      type="email"
                      placeholder="Enter your email"
                      value={email}
                      onChange={(event) =>
                        setEmail(event.target.value)
                      }
                      maxLength={120}
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label htmlFor="password">Password</label>

                    <input
                      id="password"
                      type="password"
                      placeholder={
                        isRegister
                          ? "Create a password (8+ characters)"
                          : "Enter your password"
                      }
                      value={password}
                      onChange={(event) =>
                        setPassword(event.target.value)
                      }
                      minLength={isRegister ? 8 : undefined}
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    className="auth-button"
                    disabled={busy}
                  >
                    {busy
                      ? "Please wait..."
                      : isRegister
                      ? "Create Account"
                      : "Sign In"}
                  </button>
                </form>

                <p className="switch-text">
                  {isRegister
                    ? "Already have an account?"
                    : "Don't have an account?"}

                  <button
                    type="button"
                    className="switch-button"
                    onClick={() => {
                      setIsRegister((value) => !value);
                      resetNotices();
                    }}
                  >
                    {isRegister ? "Sign In" : "Register"}
                  </button>
                </p>
              </div>
            </div>

            <div className="welcome-panel">
              <div className="welcome-content">
                <div className="welcome-brand">
                  <span className="brand-lock">🔐</span>
                  TrustVault
                </div>

                <h2>Welcome back!</h2>

                <p className="welcome-subtitle">
                  Pick up where you left off.
                  <br />
                  Your documents are safe with us.
                </p>

                <div className="security-illustration">
                  <div className="illustration-circle"></div>

                  <div className="document-stack">
                    {["one", "two", "three"].map((item) => (
                      <div
                        className={`document-card document-${item}`}
                        key={item}
                      >
                        <div className="document-icon">📄</div>

                        <div className="document-lines">
                          <span></span>
                          <span></span>
                          <span></span>
                        </div>
                      </div>
                    ))}

                    <div className="security-shield">🔒</div>
                  </div>
                </div>

                <div className="welcome-bottom">
                  <span className="status-dot"></span>
                  Secure · Private · Trusted
                </div>
              </div>
            </div>
          </section>
        ) : (
          <section className="auth-card dashboard-card">
            {/* Dashboard content continues here */}
          </section>
        )}
      </main>
    </div>
  );
}

export default App;