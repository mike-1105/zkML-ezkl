from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
import shutil
from fastapi import Query
import asyncio

import os

from functions import generate_proof, verify_proof


app = FastAPI()

UPLOAD_DIR = "./uploaded_files"




@app.post("/uploadfile/")
async def upload_file(file: UploadFile = File(...)):
    # get file name
    filename = file.filename
    # set file saving path
    # file_location = f"./uploaded_files/{filename}"
    file_location = os.path.join(UPLOAD_DIR, filename)
    # save the file to the file path
    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {"filename": filename, "file_location": file_location}

@app.get("/downloadfile/")
async def download_file(filename: str = Query(..., description="The name of the file to download")):
    file_path = os.path.join(UPLOAD_DIR, filename)
    # Check exited file or not
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    # Return and download
    return FileResponse(file_path, media_type='application/octet-stream',
                        headers={"Content-Disposition": f"attachment; filename={filename}"})



def calculate():
    input_data = os.path.join(UPLOAD_DIR, "input.json")
    res = generate_proof(input_data)
    return "successfully generate the proof and save to test.pf file. Pls click the download button"

@app.get("/calculate")
def calculate_endpoint():
    result = calculate()
    return {"result": result}


@app.get("/")
async def main():
    default_filename0 = "test.pf"
    default_filename1 = "Verifier.sol"
    default_filename2 = "Verifier.abi"
    content = f"""
    <html>
        <body>
            <h2>1. Upload a data file (xxx.json)</h2>
            <form action="/uploadfile/" method="post" enctype="multipart/form-data">
                <input type="file" name="file">
                <input type="submit">
            </form>
            
            <button id="calculate-btn">Generate the proof</button>
            <p id="calc-result"></p>

            <script>
                document.getElementById("calculate-btn").onclick = async function() {{
                    const response = await fetch('/calculate');
                    const data = await response.json();
                    // show result
                    document.getElementById("calc-result").textContent = "Result: " + data.result;
                }};
            </script>


            <form action="/downloadfile/" method="get">
                <input type="text" name="filename" id="filename" value="{default_filename0}" required>
                <input type="submit" value="Download">
            </form>
            
            <h2>2. Upload the proof (test.pf)</h2>
            <form action="/uploadfile/" method="post" enctype="multipart/form-data">
                <input type="file" name="file">
                <input type="submit">
            </form>
            
            <h2>3. Download the EVM files</h2>
            <form action="/downloadfile/" method="get">
                <label for="filename">Enter Filename:</label>
                <input type="text" name="filename" id="filename" value="{default_filename1}" required>
                <input type="submit" value="Download">
            </form>
            </br>
            <form action="/downloadfile/" method="get">
                <label for="filename">Enter Filename:</label>
                <input type="text" name="filename" id="filename" value="{default_filename2}" required>
                <input type="submit" value="Download">
            </form>
            
            


        </body>
    </html>
    """
    return HTMLResponse(content=content)

