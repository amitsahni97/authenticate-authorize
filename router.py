from fastapi import FastAPI
from authorise import router

app = FastAPI()
app.include_router(router)


@app.get('/name')
def get_name():
    return {'name': 'amit'}
