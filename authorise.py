from datetime import timedelta, datetime
from fastapi import APIRouter, Path, status, Depends, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError

router = APIRouter(
    prefix='/router_1',
    tags=['router_1']
)

bcrypt_context = CryptContext(
    schemes=['bcrypt'],
    deprecated='auto'
)
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='token')
SECRET_KEY = 'amit2410sahnibihar#'
ALGORITHM = 'HS256'


class RequestSchema(BaseModel):
    name: str
    roll: int


class UserResponse(BaseModel):
    userName: str
    userId: int


def create_access_token(
        user_name: str,
        user_id: int,
        expires_delta: timedelta
):
    encode = {'sub': user_name, 'id': user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


@router.post(
    '/save_details/{id}',
    status_code=status.HTTP_201_CREATED
)
def save_details(
        schema: RequestSchema,
        id: str
):
    """
    Function to get the details of person
    :return: dict
    """
    return {
        "name": schema.name,
        "id": bcrypt_context.hash(id)
    }


@router.post('/token')
def get_token(request_from: OAuth2PasswordRequestForm = Depends()):
    token = create_access_token(request_from.username, 1, timedelta(minutes=20))
    return token


@router.get(
    '/UserDetails',
    response_model=UserResponse
)
async def get_user_details(
        token: str
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        user_name = payload.get('sub')
        id = payload.get('id')
        if user_name is None or id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User detail is empty"
            )
        return UserResponse(userName=user_name, userId=id)
        # return {'user_name': user_name, 'user_id': id}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorised user"
        )
