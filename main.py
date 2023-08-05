from fastapi import FastAPI, status
from authorise import router

app = FastAPI()
app.include_router(router)


@app.get(
    '/appDetails',
    status_code=status.HTTP_200_OK
)
def app_detail():
    return {
        'App detail': 'This application is to authenticate & authorization the users'
    }
