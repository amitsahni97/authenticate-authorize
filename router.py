from fastapi import FastAPI
from authorise import router

app = FastAPI()
app.include_router(router)


@app.get('/')
def get_name():
    return {'details': 'this is router of my application'}
