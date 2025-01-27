from flask import Flask, request, render_template, abort
from flask_limiter import Limiter
from flask_talisman import Talisman
import your_encryption_script as enc

app = Flask(__name__, static_folder='.', static_url_path='')

# Security headers
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'style-src': ["'self'", "'unsafe-inline'"],
    'script-src': ["'self'", "'unsafe-inline'"]
})

# Rate limiting
limiter = Limiter(app=app, key_func=lambda: request.remote_addr)
limiter.init_app(app)

@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def index():
    result = None
    error = None
    method = 'aes'  # Default to AES
    
    if request.method == "POST":
        method = request.form.get("method", "aes")
        text = request.form.get("text", "")
        action = request.form.get("action")
        key = request.form.get("key", "")[:32]  # Limit key to 32 chars

        try:
            if action == "encrypt":
                result = enc.encrypt_text(text, method, key)
            elif action == "decrypt":
                result = enc.decrypt_text(text, method, key)
        except Exception as e:
            error = f"Error: {str(e)}"

    return render_template("index.html", result=result, error=error, method=method)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
