from datetime import timedelta
from fastapi import APIRouter, status, Depends, HTTPException
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from handlers import verify_password, get_current_user_password, dependency_use, authenticate_user, create_access_token
from models import UserDetailsSchema, UserResponse, UserSignInDetails, CommonMessage

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

bcrypt_context = CryptContext(
    schemes=['bcrypt'],
    deprecated='auto'
)
# oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token') [it will call the respective api present in tokenUrl]

SECRET_KEY = 'amit241097sahnibihar#'
ALGORITHM = 'HS256'
user_details = []


@router.post(
    '/SignUp',
    status_code=status.HTTP_201_CREATED,
    response_model=CommonMessage
)
def sign_up(
        user_detail: UserDetailsSchema,
        validate: bool = Depends(dependency_use)
):
    """Method to sign up(save user details during signing-up)"""
    try:
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
        return {'message': f'Hey {name}, you are signed up'}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post(
    '/signIn',
    status_code=status.HTTP_200_OK
)
def sign_in(
        user_detail: UserSignInDetails,
        validate: bool = Depends(dependency_use)
):
    """Method to authenticate the user(check user details) & return token for authorization purpose"""
    try:
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
        token = create_access_token(
            user_name=user_name,
            user_id=1,
            expires_delta=timedelta(minutes=20),
            secret_key=SECRET_KEY,
            algorithm=ALGORITHM
        )
        return {'token': token}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get(
    '/authorize',
    response_model=UserResponse
)
async def get_user_details(token: str):
    """This will validate the token so that the user can use the resource after authorization"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        user_name = payload.get('name')
        id = payload.get('id')
        if user_name is None or id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User detail is empty"
            )
        return UserResponse(userName=user_name, userId=id)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorised user"
        )


@router.post('/token')
def get_token(request_from: OAuth2PasswordRequestForm = Depends()):
    """
    Method to get the token(same as sign in but here I used 'OAuth2PasswordRequestForm' for getting user details
    """
    try:
        hashed_password = get_current_user_password(
            user_details=user_details,
            user_name=request_from.username
        )
        if hashed_password is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='User not found'
            )
        if not authenticate_user(bcrypt_context, request_from.password, hashed_password):
            return HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Sorry! you are unauthorised to use this resource'
            )
        token = create_access_token(
            user_name=request_from.username,
            user_id=1,
            expires_delta=timedelta(minutes=20),
            secret_key=SECRET_KEY,
            algorithm=ALGORITHM
        )
        return {'token': token}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise e
