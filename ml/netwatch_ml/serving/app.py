from fastapi import FastAPI
from fastapi.responses import JSONResponse
app = FastAPI(title="NetWatch ML", version="0.2.0")
@app.get("/health/live")
def live(): return {"status":"alive","stage":"foundation"}
@app.get("/health/ready")
def ready(): return JSONResponse(status_code=503, content={"status":"not_ready","reason":"no_validated_model"})
@app.post("/v1/predict")
def predict(): return JSONResponse(status_code=503, content={"error":"no_validated_model"})
