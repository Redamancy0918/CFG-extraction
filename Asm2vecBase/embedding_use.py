


import torch
import asm2vec_base_util as asm2vec_base_obj
device = 'cuda' if torch.cuda.is_available() else 'cpu'



Asm2vecBase_8 = asm2vec_base_obj.load_asm2vec_base_model(r"./Asm2vecBase/asm2vec_checkpoints/s372_model_8_50.pt", device=device)
Asm2vecBase_16 = asm2vec_base_obj.load_asm2vec_base_model(r"./Asm2vecBase/asm2vec_checkpoints/s372_model_16_50.pt", device=device)
Asm2vecBase_32 = asm2vec_base_obj.load_asm2vec_base_model(r"./Asm2vecBase/asm2vec_checkpoints/s372_model_32_50.pt", device=device)
Asm2vecBase_64 = asm2vec_base_obj.load_asm2vec_base_model(r"./Asm2vecBase/asm2vec_checkpoints/s372_model_64_50.pt", device=device)
Asm2vecBase_128 = asm2vec_base_obj.load_asm2vec_base_model(r"./Asm2vecBase/asm2vec_checkpoints/s372_model_128_50.pt", device=device)
Asm2vecBase_256 = asm2vec_base_obj.load_asm2vec_base_model(r"./Asm2vecBase/asm2vec_checkpoints/s372_model_256_50.pt", device=device)

def _Asm2VecBase(model,hex_asm):
    func2vec_origin_list = []

    for hex_asm_item in hex_asm:
        hex2vec_list = asm2vec_base_obj.str_hex_to_bytes(hex_asm_item)
        hex2vec_list, opcode_oprand_seq = asm2vec_base_obj.get_asm_input_vector(hex2vec_list)

        # 假设 hex2vec_list 是一个列表的列表，其中每个子列表都需要转换为张量
        hex2vec_tensor_list = [torch.tensor(sublist) for sublist in hex2vec_list]

        hex2vec_tensor = torch.stack(hex2vec_tensor_list)
        fun2vec_origin = torch.mean(hex2vec_tensor, dim=0)
        # 开始对每一行的代码求平均值，得到函数的vec
        func2vec_origin_list.append(fun2vec_origin)
    func2vec_origin_tensor = torch.stack(func2vec_origin_list).to(device)
    embedding_func_vec = model.linear_f(func2vec_origin_tensor)

    return embedding_func_vec
def _Asm2VecBase1(model,hex_asm):
    func2vec_origin_list = []
    # print("-"*50)
    # print(hex_asm)
    # code_list = []


    # exit()
    for hex_asm_item in hex_asm:
        hex2vec_list = asm2vec_base_obj.str_hex_to_bytes(hex_asm_item)
        hex2vec_list, opcode_oprand_seq = asm2vec_base_obj.get_asm_input_vector(hex2vec_list)
        # hex2vec_list = hex2vec_list
        fun2vec_origin = [0.0] * len(hex2vec_list[0])


        # 开始对每一行的代码求平均值，得到函数的vec
        for i in hex2vec_list:
            for j in range(len(i)):
                fun2vec_origin[j] += i[j]
        opcode_seq_len = len(hex2vec_list)
        for i in range(len(fun2vec_origin)):
            fun2vec_origin[i] = fun2vec_origin[i] / opcode_seq_len
        func2vec_origin_list.append(fun2vec_origin)
    func2vec_origin_list = torch.tensor(func2vec_origin_list).to(device)
    embedding_func_vec = model.linear_f(func2vec_origin_list)

    return embedding_func_vec

def Asm2VecBase_8(model=Asm2vecBase_8,hex_asm="56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"):
    return _Asm2VecBase(model,hex_asm)
def Asm2VecBase_16(model=Asm2vecBase_16,hex_asm="56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"):
    return _Asm2VecBase(model,hex_asm)
def Asm2VecBase_32(model=Asm2vecBase_32,hex_asm="56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"):
    return _Asm2VecBase(model,hex_asm)
def Asm2VecBase_64(model=Asm2vecBase_64,hex_asm="56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"):
    return _Asm2VecBase(model,hex_asm)
def Asm2VecBase_128(model=Asm2vecBase_128,hex_asm="56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"):
    return _Asm2VecBase(model,hex_asm)
def Asm2VecBase_256(model=Asm2vecBase_256,hex_asm="56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"):
    return _Asm2VecBase(model, hex_asm)

if __name__ == '__main__':
    asm2vec_s372_base_16(
                         hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"])
