from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer  # Правильный импорт
from sqlalchemy.orm import Session
import crud, models, schemas
from database import SessionLocal, engine
from dependencies import create_access_token, get_current_user
from passlib.context import CryptContext  # Для хэширования паролей
from fastapi.security import OAuth2PasswordRequestForm  # Для получения данных из формы

# Создание базы данных
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Настройка OAuth2PasswordBearer (для получения токена из запроса)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Инициализация контекста для хэширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Функция для получения сессии базы данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Регистрация нового пользователя
@app.post("/register/", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db=db, user=user)

# Получение токена
@app.post("/token/")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.get_user_by_username(db, form_data.username)
    if not user or not pwd_context.verify(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}
