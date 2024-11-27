from sqlalchemy.orm import Session
from passlib.context import CryptContext
from models import User
from schemas import UserCreate

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Функция для хеширования пароля
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Функция для создания пользователя
def create_user(db: Session, user: UserCreate):
    db_user = User(username=user.username, password_hash=get_password_hash(user.password))
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Функция для получения пользователя по имени
def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()
