from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

fake_user_db = {
    "alice": {"username": "alice", "password": "secret123"}
}

# JWT config
SECRET_KEY = "super-secret-key"
REFRESH_SECRET_KEY = "super-refresh-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

oauth2_schema = OAuth2PasswordBearer(tokenUrl="login")


# ------------------------------
# Token Functions
# ------------------------------
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


def verify_refresh_token(token: str):
    try:
        payload = jwt.decode(token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


# ------------------------------
# LOGIN
# ------------------------------
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), response: Response = None):
    user = fake_user_db.get(form_data.username)

    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token({"sub": user["username"]})
    refresh_token = create_refresh_token({"sub": user["username"]})

    # Set Refresh Token in cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax"
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# ------------------------------
# REFRESH TOKEN EXCHANGE
# ------------------------------
@app.post("/refresh")
def refresh_token(refresh_token: Optional[str] = Cookie(None)):
    if refresh_token is None:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    username = verify_refresh_token(refresh_token)

    # create new tokens
    new_access_token = create_access_token({"sub": username})

    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }


# ------------------------------
# Protected Route Example
# ------------------------------
@app.get("/user/me")
def me(
    token: Optional[str] = Depends(oauth2_schema),
    jwt_cookie: Optional[str] = Cookie(None)
):
    if token:
        username = verify_token(token)
    elif jwt_cookie:
        username = verify_token(jwt_cookie)
    else:
        raise HTTPException(status_code=401, detail="Missing token or cookie")
    
    return {"message": f"Hello, {username}! You are authenticated."}
