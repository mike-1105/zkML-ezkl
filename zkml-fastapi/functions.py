import ezkl
import json
import os
import asyncio

result_path = "./results"

def generate_settings():
    model_path = os.path.join(result_path, "network.onnx")
    settings_path = os.path.join(result_path, "settings.json")

    py_run_args = ezkl.PyRunArgs()
    py_run_args.input_visibility = "private"
    py_run_args.output_visibility = "public"
    py_run_args.param_visibility = "fixed"

    res = ezkl.gen_settings(model_path, settings_path, py_run_args=py_run_args)
    assert res == True, "ERROR: generate_settings"
    with open(os.path.join(result_path, "settings.json"), 'r') as f:
        data = json.load(f)
    return data

async def calibrate_settings(input_data, max_logrows=12, scales=[30]):
    # data_path = os.path.join(result_path, "input.json")
    model_path = os.path.join(result_path, "network.onnx")
    settings_path = os.path.join(result_path, "settings.json")

    res = await ezkl.calibrate_settings(
                                            input_data,
                                            model_path,
                                            settings_path,
                                            max_logrows=max_logrows,
                                            scales=scales
                                        )
    assert res == True, "ERROR: calibration"

def compile_circuit():
    model_path = os.path.join(result_path, "network.onnx")
    compiled_model_path = os.path.join(result_path, "network.compiled")
    settings_path = os.path.join(result_path, "settings.json")

    res = ezkl.compile_circuit(model_path, compiled_model_path, settings_path)
    assert res == True, "ERROR: compile"

async def srs():
    # Before we can setup the circuit params, we need a SRS (Structured Reference String).
    # The SRS is used to generate the proofs.
    settings_path = os.path.join(result_path, "settings.json")
    res = await ezkl.get_srs(settings_path)
    assert res == True

def ezkl_setup():
    # Here we setup the circuit params, we got keys and circuit parameters
    # Everything anyone has ever needed for zk
    compiled_model_path = os.path.join(result_path, "network.compiled")
    pk_path = os.path.join(result_path, "test.pk")
    vk_path = os.path.join(result_path, "test.vk")

    res = ezkl.setup(
        compiled_model_path,
        vk_path,
        pk_path,
    )

    assert res == True


def generate_vk_pk(input_data):

    generate_settings()
    asyncio.run(calibrate_settings(input_data, max_logrows=12, scales=[30]))
    compile_circuit()
    asyncio.run(srs())
    ezkl_setup() # generate proving key (pk) and verification key (vk)
    print("vk, pk keys are generated")

async def generate_witness():
    # Now generate the witness file
    data_path = os.path.join(result_path, "input.json")
    compiled_model_path = os.path.join(result_path, "network.compiled")
    witness_path = os.path.join(result_path, "witness.json")

    res = await ezkl.gen_witness(data_path, compiled_model_path, witness_path)
    assert os.path.isfile(witness_path)

    # with open(os.path.join(result_path, "witness.json"), 'r') as f:
    #     witness_data = json.load(f)
    # return witness_data






def generate_proof(input_data):
    # Generate proof using the proving key and input data
    # Generate the proof
    generate_vk_pk(input_data)
    asyncio.run(generate_witness())

    witness_path = os.path.join(result_path, "witness.json")
    compiled_model_path = os.path.join(result_path, "network.compiled")
    pk_path = os.path.join(result_path, "test.pk")
    proof_path = os.path.join(result_path, "test.pf")

    res = ezkl.prove(
        witness_path,
        compiled_model_path,
        pk_path,
        proof_path,
        "single",
    )

    assert os.path.isfile(proof_path)
    return res

def verify_proof():
    # Verify the proof
    proof_path = os.path.join(result_path, "test.pf")
    settings_path = os.path.join(result_path, "settings.json")
    vk_path = os.path.join(result_path, "test.vk")

    res = ezkl.verify(
        proof_path,
        settings_path,
        vk_path,
    )
    assert res == True
    return {"data": "Proof is verified"}






if __name__ == '__main__':
    # with open(os.path.join(result_path, "input.json"), 'r') as f:
    #     input_data = json.load(f)
    input_data = os.path.join(result_path, "input.json")
    res = generate_proof(input_data)
    print(res)
