from fastapi import FastAPI
from pydantic import BaseModel
from functions import generate_proof, verify_proof
import os
import json

result_path = "./results"


app = FastAPI()

class ProofRequest(BaseModel):
    input_data: list  # Input data for generating the proof

data_dict = {
    0: {
        "input_data": [[i for i in range(1600)]]
    }
}


# Paths for calibration files
calibration_file = "./results/calibration.json"


@app.get("/")
def home():
    return {
                "Title": "Hello zkML",
                "Link": "http://127.0.0.1:8000/docs"

            }

@app.get("/data/{data_id}")
def get_data(data_id: int):
    return data_dict[data_id]

@app.post("/add-data/{data_id}")
def add_data(data_id: int, input_data: ProofRequest):
    if data_id in data_dict:
        return {"Error": "data_id has already existed"}
    else:
        data_dict[data_id] = input_data

        # # convert format: ProofRequest --> dict
        # if hasattr(input_data, "to_dict"):
        #     input_data_dict = input_data.to_dict()
        # else:
        #     input_data_dict = {
        #         "input_data": input_data.input_data,
        #     }
        # # save input.json
        # data_path = os.path.join(result_path, "input.json")
        # with open(data_path, 'w', encoding='utf-8') as f:
        #     json.dump(input_data_dict, f, ensure_ascii=False)

        return data_dict[data_id]

@app.post("/generate-proof/{data_id}")
def generate_proof_endpoint(data_id: int=None):
    input_data = data_dict[data_id]
    # convert format: ProofRequest --> dict
    if hasattr(input_data, "to_dict"):
        input_data_dict = input_data.to_dict()
    else:
        input_data_dict = {
            "input_data": input_data.input_data,
        }
    # save input.json
    data_path = os.path.join(result_path, "input.json")
    with open(data_path, 'w', encoding='utf-8') as f:
        json.dump(input_data_dict, f, ensure_ascii=False)

    input_data = os.path.join(result_path, "input.json")
    res = generate_proof(input_data)
    return res

@app.get("/verify-proof/")
def verify_proof_endpoint():
    res = verify_proof()
    return res
