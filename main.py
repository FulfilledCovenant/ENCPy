from flask import Flask, request, render_template
import you_sc as enc  # Assuming you named your encryption file 'your_encryption_script.py'

app = Flask(__name__, static_folder='.', static_url_path='')

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        if "encrypt" in request.form:
            text = request.form.get("text")
            result = enc.encrypt_text(text)
        elif "decrypt" in request.form:
            text = request.form.get("text")
            result = enc.decrypt_text(text)

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
