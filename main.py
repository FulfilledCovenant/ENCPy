from flask import Flask, request, render_template
import you_sc as enc

app = Flask(__name__, static_folder='.', static_url_path='')

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    method = 'custom'  # Default method

    if request.method == "POST":
        method = request.form.get("method", "custom")
        text = request.form.get("text", "")
        action = request.form.get("action")

        try:
            if action == "encrypt":
                result = enc.encrypt_text(text, method)
            elif action == "decrypt":
                result = enc.decrypt_text(text, method)
        except Exception as e:
            error = f"Error: {str(e)}"

    return render_template("index.html", result=result, error=error, method=method)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
