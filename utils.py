from datetime import datetime, timedelta, date
from jose import JWTError, jwt

SECRET_KEY = "BARAKABAMA"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})

    birth_date = data.get("birth_date")
    if birth_date and isinstance(birth_date, (datetime, date)):
        to_encode["birth_date"] = birth_date.isoformat()

    to_encode.update({
        "id": data["id"],
        "first_name": data.get("first_name", ""),
        "last_name": data.get("last_name", ""),
        "email": data.get("email", ""),
        "phone": data.get("phone", ""),
        "is_owner": data.get("is_owner", False),
        "owner_id": data.get("owner_id", None)
    })

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
