from flask import Flask, request, render_template
from flask_limiter import Limiter

app = Flask(__name__, static_folder='static', template_folder='templates')
limiter = Limiter(app=app, key_func=lambda: request.remote_addr)

@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def index():
    result = None
    error = None
    method = 'custom'  # Default method
    
    if request.method == "POST":
        method = request.form.get("method", "custom")
        text = request.form.get("text", "").strip()
        action = request.form.get("action")

        try:
            if not text:
                raise ValueError("Input text cannot be empty")
                
            if action == "encrypt":
                result = you_sc.encrypt_text(text, method)
            elif action == "decrypt":
                result = you_sc.decrypt_text(text, method)
        except Exception as e:
            error = f"Error: {str(e)}"

    return render_template("index.html", result=result, error=error, method=method)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
