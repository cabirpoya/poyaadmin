Hugging Face's logo
Hugging Face
Models
Datasets
Spaces
Posts
Docs
Enterprise
Pricing



Spaces:

CabirPoya
/
poyaadmin


like
0
App
Files
Community
Settings
poyaadmin
/
main.py

CabirPoya's picture
CabirPoya
Update main.py
b968fbe
verified
2 minutes ago
raw

Copy download link
history
blame
edit
delete

2.8 kB
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError

from auth import SECRET_KEY, ALGORITHM, verify_password, create_access_token, get_password_hash
from database import get_db
from models import User

app = FastAPI()

# تنظیم OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# بررسی توکن و دریافت کاربر جاری
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.query(User).filter(User.username == payload["sub"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="کاربر یافت نشد")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="توکن نامعتبر است")

# مسیر حفاظت‌شده
@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username}

# مسیر ورود (Login)
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()

    if not user:
        raise HTTPException(status_code=400, detail="نام کاربری نادرست است")

    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="رمز عبور نادرست است")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# مدل ورودی برای ثبت‌نام
class RegisterForm(BaseModel):
    username: str
    password: str

# مسیر ثبت‌نام (Register)
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(form: RegisterForm, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == form.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="این نام کاربری قبلاً ثبت شده است")

    hashed_pw = get_password_hash(form.password)
    new_user = User(username=form.username, hashed_password=hashed_pw)

    db.add(new_user)
    try:
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=500, detail="خطا در ثبت اطلاعات")

    return {"message": "کاربر با موفقیت ثبت شد", "username": new_user.username}

