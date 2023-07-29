from datetime import timedelta, datetime
from fastapi import APIRouter, status, Depends, HTTPException
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from handlers import verify_password, get_current_user_password, dependency_use, authenticate_user
from models import UserDetailsSchema, UserResponse, UserSignInDetails

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

bcrypt_context = CryptContext(
    schemes=['bcrypt'],
    deprecated='auto'
)
# oauth2_bearer = OAuth2PasswordBearer(tokenUrl='token')
# SECRET_KEY = 'amit241097sahnibihar#'
# ALGORITHM = 'HS256'

user_details = []


# def create_access_token(
#         user_name: str,
#         user_id: int,
#         expires_delta: timedelta
# ):
#     encode = {'sub': user_name, 'id': user_id}
#     expires = datetime.utcnow() + expires_delta
#     encode.update({'exp': expires})
#     return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

#
# @router.post(
#     '/save_details/{id}',
#     status_code=status.HTTP_201_CREATED
# )
# def save_details(
#         schema: UserDetailsSchema,
#         id: str
# ):
#     """
#     Function to get the details of person
#     :return: dict
#     """
#     return {
#         "name": schema.name,
#         "id": bcrypt_context.hash(id)
#     }


# @router.get(
#     '/UserDetails',
#     response_model=UserResponse
# )
# async def get_user_details(
#         token: str
# ):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
#         user_name = payload.get('sub')
#         id = payload.get('id')
#         if user_name is None or id is None:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="User detail is empty"
#             )
#         return UserResponse(userName=user_name, userId=id)
#         # return {'user_name': user_name, 'user_id': id}
#     except JWTError:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="unauthorised user"
#         )


@router.post(
    '/SignUp',
    status_code=status.HTTP_201_CREATED
)
def sign_up(
        user_detail: UserDetailsSchema,
        validate: bool = Depends(dependency_use)
):
    """
    Method to authenticate user
    """
    if validate:
        print("start the sign up -------->")
    user_data = user_detail.__dict__
    name = user_data.get('name')
    password = user_data.get('password')
    password_2 = user_data.get('existingPassword')
    if password_2 is None:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail='password_2 must be given during sign up'
        )
    if not verify_password(password, password_2):
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail='Both password are not matched'
        )
    user = {
        'name': name,
        'password': bcrypt_context.hash(password)
    }
    user_details.append(user)
    return user_details


@router.post(
    '/signIn',
    status_code=status.HTTP_200_OK
)
def sign_in(
        user_detail: UserSignInDetails,
        validate: bool = Depends(dependency_use)
):
    """
    Method to authorize the user
    :param user_detail: obj
    :param validate: bool
    :return: str
    """
    if validate:
        print("signing in started-------->")
    user_detail = user_detail.__dict__
    user_name = user_detail['name']
    user_password = user_detail['password']
    hashed_password = get_current_user_password(user_details=user_details, user_name=user_name)
    if hashed_password is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    if not authenticate_user(bcrypt_context, user_password, hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="password is incorrect"
        )
    return "Successfully signed in"


@router.post('/token')
def get_token(request_from: OAuth2PasswordRequestForm = Depends()):
    hashed_password = get_current_user_password(
        user_details=user_details,
        user_name=request_from.username
    )
    # if authenticate_user(request_from.username, request_from.password, hashed_password)
    # token = create_access_token(request_from.username, 1, timedelta(minutes=20))
    return "done"
