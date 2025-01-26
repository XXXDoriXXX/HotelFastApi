import os
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Body, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session

from dependencies import get_current_user
from models import Person
from schemas import LoginRequest, Token, PersonCreate, PersonBase, PersonUpdate
from database import get_db
from crud import authenticate_user, create_person, create_owner, create_client, update_person, get_password_hash, \
    verify_password
from utils import create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])
UPLOAD_DIRECTORY = "uploaded_images/profiles"
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)


@router.post("/register", response_model=PersonBase, status_code=status.HTTP_201_CREATED)
def register(user: PersonCreate, db: Session = Depends(get_db)):
    existing_user = db.query(Person).filter(
        (Person.email == user.email) | (Person.phone == user.phone)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email or phone already exists."
        )
    if user.is_owner:
        new_owner = create_owner(db, user.dict())
        return new_owner.person
    else:
        new_client = create_client(db, user.dict())
        return new_client.person
@router.post("/login", response_model=Token)
def login(login_request: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, login_request.email, login_request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token({
        "id": user["id"],
        "email": user["email"],
        "is_owner": user["is_owner"],
        "first_name": user["first_name"],
        "last_name": user["last_name"],
        "phone": user["phone"],
        "owner_id": user.get("owner_id")
    })

    return {"access_token": access_token, "token_type": "bearer"}

class ProfileUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None
    profile_image: Optional[UploadFile] = None
@router.put("/me")
def update_profile(
    request: ProfileUpdateRequest,  # Модель запиту з усіма можливими полями
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["id"]

    # Отримуємо користувача
    user = db.query(Person).filter(Person.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Перевірка пароля при зміні email або пароля
    if (request.email or request.new_password) and not verify_password(
        request.current_password, user.password
    ):
        raise HTTPException(status_code=403, detail="Invalid current password")

    # Оновлення імені
    if request.first_name:
        user.first_name = request.first_name
    if request.last_name:
        user.last_name = request.last_name

    # Оновлення email
    if request.email:
        user.email = request.email

    # Оновлення телефону
    if request.phone:
        user.phone = request.phone

    # Оновлення пароля
    if request.new_password:
        user.password = get_password_hash(request.new_password)

    # Оновлення профільного зображення
    if request.profile_image:
        # Зберігаємо файл і оновлюємо шлях
        file_extension = request.profile_image.filename.split(".")[-1].lower()
        if file_extension not in ["jpg", "jpeg", "png"]:
            raise HTTPException(status_code=400, detail="Invalid file format")

        filename = f"{uuid4()}.{file_extension}"
        file_path = os.path.join(UPLOAD_DIRECTORY, filename)
        with open(file_path, "wb") as f:
            f.write(request.profile_image.file.read())

        user.profile_image = f"/{UPLOAD_DIRECTORY}/{filename}"

    # Зберігаємо зміни
    db.commit()
    db.refresh(user)

    return {
        "message": "Profile updated successfully",
        "profile_image": user.profile_image,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "phone": user.phone,
    }
