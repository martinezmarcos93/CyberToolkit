from flask import Flask, render_template, jsonify, request
import sys
import os

# Asegurar que el directorio padre esté en el path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import TOOL_STATUS, TOOL_NAMES

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html", tools=TOOL_NAMES, status=TOOL_STATUS)

@app.route("/api/tools", methods=["GET"])
def get_tools():
    """API REST: Lista todas las herramientas disponibles."""
    tools_list = [{"id": k, "name": v, "status": TOOL_STATUS.get(k)} for k, v in TOOL_NAMES.items()]
    return jsonify({"status": "success", "tools": tools_list})

@app.route("/api/reports", methods=["GET"])
def get_reports():
    """API REST: Lista todos los reportes generados."""
    outputs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs")
    reports = []
    if os.path.exists(outputs_dir):
        import glob
        for file in glob.glob(os.path.join(outputs_dir, "*.*")):
            reports.append(os.path.basename(file))
    return jsonify({"status": "success", "reports": reports})

# Punto de entrada para tests/ejecución directa
if __name__ == "__main__":
    # En producción usar Waitress o Gunicorn
    app.run(host="127.0.0.1", port=5000, debug=True)
