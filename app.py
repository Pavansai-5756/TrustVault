
from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>TrustVault</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f1f5f9;
                text-align: center;
                padding: 80px 20px;
            }
            .container {
                max-width: 650px;
                margin: auto;
                background: white;
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 4px 15px #00000015;
            }
            h1 {
                color: #173b70;
            }
            p {
                color: #475569;
                line-height: 1.6;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>TrustVault</h1>
            <h2>Secure Document Sharing</h2>
            <p>Store documents securely, control access, and maintain
            a reliable audit trail of document activity.</p>
            <p>Your secure document workspace starts here.</p>
        </div>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(debug=True)
