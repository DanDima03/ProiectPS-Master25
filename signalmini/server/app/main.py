from fastapi import FastAPI
from .db import engine, Base
from .routes_users import router as users_router
from .routes_keys import router as keys_router
from .routes_messages import router as msg_router

app = FastAPI(title="SignalMini Server")

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

app.include_router(users_router)
app.include_router(keys_router)
app.include_router(msg_router)

@app.get("/")
def root():
    return {"ok": True, "service": "signalmini"}
