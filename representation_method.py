import json
from capstone import *
import binascii
import sys
import multiprocessing as mp
import ast
from MGNE.use_mgne import  MGNE_node_embedding
sys.path.append(r"./Asm2vecPlus")
sys.path.append(r"./Asm2vecBase/")
sys.path.append(r"./MGNE/")
# from Asm2vecPlus.embedding_use import Asm2VecPlus_8,Asm2VecPlus_16,Asm2VecPlus_32,Asm2VecPlus_64,Asm2VecPlus_128,Asm2VecPlus_256
# from Asm2vecPlus.init_vector_generation import get_seq_encoder

from Asm2vecPlus.embedding_use import Asm2VecPlus_8,Asm2VecPlus_16,Asm2VecPlus_32,Asm2VecPlus_64,Asm2VecPlus_128,Asm2VecPlus_256
from Asm2vecPlus.init_vector_generation import get_seq_encoder1

from Asm2vecBase.embedding_use import Asm2VecBase_8,Asm2VecBase_16,Asm2VecBase_32,Asm2VecBase_64,Asm2VecBase_128,Asm2VecBase_256
# print(asm2vec_s372_base_16(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]))
# exit()
import torch
device = 'cuda' if torch.cuda.is_available() else 'cpu'
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True


def split_basicblock_byte(asm_bytes):
    code_list = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    HexCode = binascii.unhexlify(asm_bytes)
    for item in md.disasm(HexCode, 0):
        hex_string = ''.join(['{:02x}'.format(b) for b in item.bytes])
        code_list.append(hex_string)
    return code_list



def representation_method_func(basicblock_byte_seq,representation_method,offspring=1,instructions_in_vertex=1):
    basicblock_vec_list=[]
    if basicblock_byte_seq==[]:
        basicblock_byte_seq =['90']
    if representation_method=="malconv":

        basicblock_vec_list=malconv(basicblock_byte_seq)

        return basicblock_vec_list
    elif representation_method == "n_gram_1":
        basicblock_vec_list=n_gram_1(dim=400, hex_asm=basicblock_byte_seq)
        return basicblock_vec_list
    elif representation_method == "n_gram_2":
        basicblock_vec_list=n_gram_2(dim=400, hex_asm=basicblock_byte_seq)
        return basicblock_vec_list
    elif representation_method == "n_gram_3":
        basicblock_vec_list=n_gram_3(dim=400, hex_asm=basicblock_byte_seq)
        return basicblock_vec_list
    # elif representation_method == "Asm2VecPlus_8":
    #     Asm2VecPlus_8_vec_list,Asm2VecPlus_16_vec_list,Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,Asm2VecPlus_128_vec_list,Asm2VecPlus_256_vec_list=Asm2VecPlus(hex_asm=basicblock_byte_seq)
    #     return Asm2VecPlus_8_vec_list,Asm2VecPlus_16_vec_list,Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,Asm2VecPlus_128_vec_list,Asm2VecPlus_256_vec_list
    elif representation_method == "Asm2VecBase_8":
        Asm2VecPlus_8_vec_list,Asm2VecPlus_16_vec_list,Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,Asm2VecPlus_128_vec_list,Asm2VecPlus_256_vec_list=Asm2VecBase1(hex_asm=basicblock_byte_seq)
        return Asm2VecPlus_8_vec_list,Asm2VecPlus_16_vec_list,Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,Asm2VecPlus_128_vec_list,Asm2VecPlus_256_vec_list
    elif representation_method == "Magic":
        basicblock_vec_list=Magic(hex_asm=basicblock_byte_seq,offspring=offspring,instructions_in_vertex=instructions_in_vertex)
        return basicblock_vec_list
    elif representation_method == "init_vector_374":
        basicblock_vec_list = init_vecotr_374(hex_asm=basicblock_byte_seq)
        return basicblock_vec_list
    elif representation_method == "LSTM_MGNE_8":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="LSTM_MGNE_8")
        return basicblock_vec_list
    elif representation_method == "LSTM_MGNE_16":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="LSTM_MGNE_16")
        return basicblock_vec_list
    elif representation_method == "LSTM_MGNE_32":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="LSTM_MGNE_32")
        return basicblock_vec_list
    elif representation_method == "LSTM_MGNE_64":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="LSTM_MGNE_64")
        return basicblock_vec_list
    elif representation_method == "LSTM_MGNE_128":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="LSTM_MGNE_128")
        return basicblock_vec_list
    elif representation_method == "LSTM_MGNE_256":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="LSTM_MGNE_256")
        return basicblock_vec_list


    elif representation_method == "L_LSTM_MGNE_8":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="L_LSTM_MGNE_8")
        return basicblock_vec_list
    elif representation_method == "L_LSTM_MGNE_16":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="L_LSTM_MGNE_16")
        return basicblock_vec_list
    elif representation_method == "L_LSTM_MGNE_256":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="L_LSTM_MGNE_256")
        return basicblock_vec_list



    elif representation_method == "BERT_MGNE_8":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="BERT_MGNE_8")
        return basicblock_vec_list
    elif representation_method == "BERT_MGNE_16":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="BERT_MGNE_16")
        return basicblock_vec_list
    elif representation_method == "BERT_MGNE_32":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="BERT_MGNE_32")
        return basicblock_vec_list
    elif representation_method == "BERT_MGNE_64":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="BERT_MGNE_64")
        return basicblock_vec_list
    elif representation_method == "BERT_MGNE_128":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="BERT_MGNE_128")
        return basicblock_vec_list
    elif representation_method == "BERT_MGNE_256":
        basicblock_vec_list = MGNE_node_embedding(hex_asm=basicblock_byte_seq,dim="BERT_MGNE_256")
        return basicblock_vec_list

    # elif representation_method == "Asm2VecBase_8":
    #     Asm2VecBase_8_vec_list = _Asm2VecBase_8(hex_asm=basicblock_byte_seq)
    #     return Asm2VecBase_8_vec_list
    # elif representation_method == "Asm2VecBase_16":
    #     Asm2VecBase_16_vec_list= _Asm2VecBase_16(hex_asm=basicblock_byte_seq)
    #     return  Asm2VecBase_16_vec_list
    # elif representation_method == "Asm2VecBase_32":
    #     Asm2VecBase_32_vec_list= _Asm2VecBase_32(hex_asm=basicblock_byte_seq)
    #     return Asm2VecBase_32_vec_list
    # elif representation_method == "Asm2VecBase_64":
    #     Asm2VecBase_64_vec_list = _Asm2VecBase_64(hex_asm=basicblock_byte_seq)
    #     return Asm2VecBase_64_vec_list
    # elif representation_method == "Asm2VecBase_128":
    #     Asm2VecBase_128_vec_list= _Asm2VecBase_128(hex_asm=basicblock_byte_seq)
    #     return Asm2VecBase_128_vec_list
    # elif representation_method == "Asm2VecBase_256":
    #     Asm2VecBase_256_vec_list = _Asm2VecBase_256(hex_asm=basicblock_byte_seq)
    #     return Asm2VecBase_256_vec_list

    # elif representation_method == "Asm2VecPlus_8":
    #     Asm2VecPlus_8_vec_list=_Asm2VecPlus_8(hex_asm=basicblock_byte_seq)
    #     return Asm2VecPlus_8_vec_list
    # elif representation_method == "Asm2VecPlus_16":
    #     Asm2VecPlus_16_vec_list=_Asm2VecPlus_16(hex_asm=basicblock_byte_seq)
    #     return Asm2VecPlus_16_vec_list
    # elif representation_method == "Asm2VecPlus_32":
    #     Asm2VecPlus_32_vec_list=_Asm2VecPlus_32(hex_asm=basicblock_byte_seq)
    #     return Asm2VecPlus_32_vec_list
    # elif representation_method == "Asm2VecPlus_64":
    #     Asm2VecPlus_64_vec_list=_Asm2VecPlus_64(hex_asm=basicblock_byte_seq)
    #     return Asm2VecPlus_64_vec_list
    # elif representation_method == "Asm2VecPlus_128":
    #     Asm2VecPlus_128_vec_list=_Asm2VecPlus_64(hex_asm=basicblock_byte_seq)
    #     return Asm2VecPlus_128_vec_list
    # elif representation_method == "Asm2VecPlus_256":
    #     Asm2VecPlus_256_vec_list = _Asm2VecPlus_256(hex_asm=basicblock_byte_seq)
    #     return Asm2VecPlus_256_vec_list


def Asm2VecBase_get_basicblock_seq_vec_list(byte_sequences,representation_method="Asm2VecBase_8"):
    # print(byte_sequences)
    # print(representation_method)
    Asm2VecBase_8_vec_list,Asm2VecBase_16_vec_list,Asm2VecBase_32_vec_list,Asm2VecBase_64_vec_list,Asm2VecBase_128_vec_list,Asm2VecBase_256_vec_list\
        =representation_method_func(byte_sequences,representation_method)

    return  str(Asm2VecBase_8_vec_list).replace(" ", ""), str(Asm2VecBase_16_vec_list).replace(" ", ""), str(Asm2VecBase_32_vec_list).replace(" ", ""),\
    str(Asm2VecBase_64_vec_list).replace(" ", ""), str(Asm2VecBase_128_vec_list).replace(" ", ""), str(Asm2VecBase_256_vec_list).replace(" ", "")


def Asm2VecPlus_get_basicblock_seq_vec_list(byte_sequences,representation_method="Asm2VecPlus_8"):


    Asm2VecPlus_8_vec_list,Asm2VecPlus_16_vec_list,Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,Asm2VecPlus_128_vec_list,Asm2VecPlus_256_vec_list\
        =representation_method_func(byte_sequences,representation_method)

    return  str(Asm2VecPlus_8_vec_list).replace(" ", ""), str(Asm2VecPlus_16_vec_list).replace(" ", ""), str(Asm2VecPlus_32_vec_list).replace(" ", ""),\
    str(Asm2VecPlus_64_vec_list).replace(" ", ""), str(Asm2VecPlus_128_vec_list).replace(" ", ""), str(Asm2VecPlus_256_vec_list).replace(" ", "")


# def Asm2VecPlus_get_basicblock_seq_vec_list_8(byte_sequences,representation_method="Asm2VecPlus_8"):
#
#
#     Asm2VecPlus_8_vec_list=representation_method_func(byte_sequences,representation_method)
#
#     return  str(Asm2VecPlus_8_vec_list).replace(" ", "")
#
# def Asm2VecPlus_get_basicblock_seq_vec_list_16(byte_sequences,representation_method="Asm2VecPlus_16"):
#
#
#     Asm2VecPlus_16_vec_list=representation_method_func(byte_sequences,representation_method)
#
#     return  str(Asm2VecPlus_16_vec_list).replace(" ", "")
#
# def Asm2VecPlus_get_basicblock_seq_vec_list_32(byte_sequences,representation_method="Asm2VecPlus_32"):
#
#
#     Asm2VecPlus_32_vec_list=representation_method_func(byte_sequences,representation_method)
#
#     return  str(Asm2VecPlus_32_vec_list).replace(" ", "")
#
# def Asm2VecPlus_get_basicblock_seq_vec_list_64(byte_sequences,representation_method="Asm2VecPlus_64"):
#
#
#     Asm2VecPlus_64_vec_list=representation_method_func(byte_sequences,representation_method)
#
#     return  str(Asm2VecPlus_64_vec_list).replace(" ", "")
#
# def Asm2VecPlus_get_basicblock_seq_vec_list_128(byte_sequences,representation_method="Asm2VecPlus_128"):
#
#
#     Asm2VecPlus_128_vec_list=representation_method_func(byte_sequences,representation_method)
#
#     return  str(Asm2VecPlus_128_vec_list).replace(" ", "")
# def Asm2VecPlus_get_basicblock_seq_vec_list_256(byte_sequences,representation_method="Asm2VecPlus_256"):
#
#
#     Asm2VecPlus_256_vec_list=representation_method_func(byte_sequences,representation_method)
#
#     return  str(Asm2VecPlus_256_vec_list).replace(" ", "")

# def get_basicblock_seq_vec_list1(byte_sequences,representation_method="n_gram_1",offspring=1,instructions_in_vertex=1):
#     seq_vec_list=[]
#
#     for basicblock in byte_sequences:
#         basicblock_byte_seq=split_basicblock_byte(basicblock)
#         basicblock_vec_list=representation_method_func(basicblock_byte_seq,representation_method,offspring,instructions_in_vertex)
#         seq_vec_list.append(basicblock_vec_list)
#     return str(seq_vec_list).replace(" ", "")


# def init_vector_374_get_basicblock_seq_vec_list(byte_sequences,representation_method="init_vector_374"):
#     init_vector_374_list=representation_method_func(byte_sequences,representation_method)
#     return  str(init_vector_374_list).replace(" ", "")


def get_basicblock_seq_vec_list(byte_sequences,representation_method="n_gram_1",offspring=1,instructions_in_vertex=1):

    basicblock_vec_list=representation_method_func(byte_sequences,representation_method,offspring,instructions_in_vertex)

    return str(basicblock_vec_list).replace(" ", "")


def round_list(vec_list,round_num=4):
    rounded_three_dimensional_list = [
        [
            [round(num, round_num) for num in inner_list] for inner_list in inner_inner_list
        ]
        for inner_inner_list in vec_list
    ]
    return rounded_three_dimensional_list


def process_hex_asm_item(hex_asm_item):
    if hex_asm_item == '':
        hex_asm_item = "90"

    HexCode = binascii.unhexlify(hex_asm_item)
    code_list = []
    for item in md.disasm(HexCode, 0):
        hex_string = ''.join(['{:02x}'.format(b) for b in item.bytes])
        code_list.append(hex_string)

    try:
        return [
            Asm2VecBase_8(hex_asm=code_list).tolist(),
            Asm2VecBase_16(hex_asm=code_list).tolist(),
            Asm2VecBase_32(hex_asm=code_list).tolist(),
            Asm2VecBase_64(hex_asm=code_list).tolist(),
            Asm2VecBase_128(hex_asm=code_list).tolist(),
            Asm2VecBase_256(hex_asm=code_list).tolist()
        ]
    except:
        # 如果有异常，处理代码在这里
        hex_asm_item = "90"
        HexCode = binascii.unhexlify(hex_asm_item)
        code_list = []
        for item in md.disasm(HexCode, 0):
            hex_string = ''.join(['{:02x}'.format(b) for b in item.bytes])
            code_list.append(hex_string)
        return [
            Asm2VecBase_8(hex_asm=code_list).tolist(),
            Asm2VecBase_16(hex_asm=code_list).tolist(),
            Asm2VecBase_32(hex_asm=code_list).tolist(),
            Asm2VecBase_64(hex_asm=code_list).tolist(),
            Asm2VecBase_128(hex_asm=code_list).tolist(),
            Asm2VecBase_256(hex_asm=code_list).tolist()
        ]

def Asm2VecBase(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]):
    # 初始化列表
    Asm2VecBase_lists = [[] for _ in range(6)]
    processes_num=8
    len_data=len(hex_asm)

    with mp.Pool(processes=processes_num) as pool:
                # 将 hex_asm 列表中的每个元素映射到 process_hex_asm_item 函数
            results = pool.map(process_hex_asm_item, hex_asm)
    # 汇总结果
    for vecs in results:
        for i, vec in enumerate(vecs):
            Asm2VecBase_lists[i].append(vec)

    # 对每个列表进行四舍五入处理
    for i in range(6):
        Asm2VecBase_lists[i] = round_list(Asm2VecBase_lists[i], round_num=4)

    return Asm2VecBase_lists[0],Asm2VecBase_lists[1],Asm2VecBase_lists[2],Asm2VecBase_lists[3],Asm2VecBase_lists[4],Asm2VecBase_lists[5]

def Asm2VecBase1(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]):

    Asm2VecBase_8_vec_list = []
    Asm2VecBase_16_vec_list = []
    Asm2VecBase_32_vec_list = []
    Asm2VecBase_64_vec_list = []
    Asm2VecBase_128_vec_list = []
    Asm2VecBase_256_vec_list = []


    for hex_asm_item in hex_asm:
        if hex_asm_item=='':
            hex_asm_item="90"

        HexCode = binascii.unhexlify(hex_asm_item)
        code_list=[]
        for item in md.disasm(HexCode, 0):
            hex_string = ''.join(['{:02x}'.format(b) for b in item.bytes])
            code_list.append(hex_string)


        try:
            Asm2VecBase_8_vec_list.append(Asm2VecBase_8(hex_asm=code_list).tolist())

            Asm2VecBase_16_vec_list.append(Asm2VecBase_16(hex_asm=code_list).tolist())
            Asm2VecBase_32_vec_list.append(Asm2VecBase_32(hex_asm=code_list).tolist())
            Asm2VecBase_64_vec_list.append(Asm2VecBase_64(hex_asm=code_list).tolist())
            Asm2VecBase_128_vec_list.append(Asm2VecBase_128(hex_asm=code_list).tolist())
            Asm2VecBase_256_vec_list.append(Asm2VecBase_256(hex_asm=code_list).tolist())
        except:
            hex_asm_item = "90"
            HexCode = binascii.unhexlify(hex_asm_item)
            code_list = []
            for item in md.disasm(HexCode, 0):
                hex_string = ''.join(['{:02x}'.format(b) for b in item.bytes])
                code_list.append(hex_string)

            Asm2VecBase_8_vec_list.append(Asm2VecBase_8(hex_asm=code_list).tolist())

            Asm2VecBase_16_vec_list.append(Asm2VecBase_16(hex_asm=code_list).tolist())
            Asm2VecBase_32_vec_list.append(Asm2VecBase_32(hex_asm=code_list).tolist())
            Asm2VecBase_64_vec_list.append(Asm2VecBase_64(hex_asm=code_list).tolist())
            Asm2VecBase_128_vec_list.append(Asm2VecBase_128(hex_asm=code_list).tolist())
            Asm2VecBase_256_vec_list.append(Asm2VecBase_256(hex_asm=code_list).tolist())





    # print(Asm2VecPlus_8_vec_list)
    # exit()
    Asm2VecBase_8_vec_list = round_list(Asm2VecBase_8_vec_list,round_num=4)
    Asm2VecBase_16_vec_list = round_list(Asm2VecBase_16_vec_list,round_num=4)
    Asm2VecBase_32_vec_list = round_list(Asm2VecBase_32_vec_list,round_num=4)
    Asm2VecBase_64_vec_list = round_list(Asm2VecBase_64_vec_list,round_num=4)
    Asm2VecBase_128_vec_list = round_list(Asm2VecBase_128_vec_list,round_num=4)
    Asm2VecBase_256_vec_list = round_list(Asm2VecBase_256_vec_list,round_num=4)


    return Asm2VecBase_8_vec_list,Asm2VecBase_16_vec_list,Asm2VecBase_32_vec_list,Asm2VecBase_64_vec_list,Asm2VecBase_128_vec_list,Asm2VecBase_256_vec_list



def _Asm2VecPlus_8(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]):
    Asm2VecPlus_8_vec_list = []
    for hex_asm_item in hex_asm:
        if hex_asm_item=='':
            hex_asm_item="90"
        initial_vector =get_seq_encoder1(hex_asm_item)

        initial_vector= torch.tensor(initial_vector).to(device)
        try:
            Asm2VecPlus_8_vec_list.append(Asm2VecPlus_8(initial_vector).tolist())
        except:
            hex_asm_item="90"
            initial_vector = get_seq_encoder1(hex_asm_item)
            initial_vector = torch.tensor(initial_vector).to(device)
            Asm2VecPlus_8_vec_list.append(Asm2VecPlus_8(initial_vector).tolist())

    Asm2VecPlus_8_vec_list = round_list(Asm2VecPlus_8_vec_list,round_num=4)
    return Asm2VecPlus_8_vec_list

def _Asm2VecPlus_16(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]):
    Asm2VecPlus_16_vec_list = []
    for hex_asm_item in hex_asm:
        if hex_asm_item=='':
            hex_asm_item="90"
        initial_vector =get_seq_encoder1(hex_asm_item)
        initial_vector= torch.tensor(initial_vector).to(device)
        try:
            Asm2VecPlus_16_vec_list.append(Asm2VecPlus_16(initial_vector).tolist())
        except:
            hex_asm_item="90"
            initial_vector = get_seq_encoder1(hex_asm_item)
            initial_vector = torch.tensor(initial_vector).to(device)
            Asm2VecPlus_16_vec_list.append(Asm2VecPlus_16(initial_vector).tolist())

    Asm2VecPlus_16_vec_list = round_list(Asm2VecPlus_16_vec_list,round_num=4)
    return Asm2VecPlus_16_vec_list

def _Asm2VecPlus_32(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]):
    Asm2VecPlus_32_vec_list = []
    for hex_asm_item in hex_asm:
        if hex_asm_item=='':
            hex_asm_item="90"
        initial_vector =get_seq_encoder1(hex_asm_item)
        initial_vector= torch.tensor(initial_vector).to(device)
        try:
            Asm2VecPlus_32_vec_list.append(Asm2VecPlus_16(initial_vector).tolist())
        except:
            hex_asm_item="90"
            initial_vector = get_seq_encoder1(hex_asm_item)
            initial_vector = torch.tensor(initial_vector).to(device)
            Asm2VecPlus_32_vec_list.append(Asm2VecPlus_16(initial_vector).tolist())
    Asm2VecPlus_32_vec_list = round_list(Asm2VecPlus_32_vec_list,round_num=4)
    return Asm2VecPlus_32_vec_list

def _Asm2VecPlus_64(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]):
    Asm2VecPlus_64_vec_list = []
    for hex_asm_item in hex_asm:
        if hex_asm_item=='':
            hex_asm_item="90"
        initial_vector =get_seq_encoder1(hex_asm_item)
        initial_vector= torch.tensor(initial_vector).to(device)
        try:
            Asm2VecPlus_64_vec_list.append(Asm2VecPlus_64(initial_vector).tolist())
        except:
            hex_asm_item="90"
            initial_vector = get_seq_encoder1(hex_asm_item)
            initial_vector = torch.tensor(initial_vector).to(device)
            Asm2VecPlus_64_vec_list.append(Asm2VecPlus_16(initial_vector).tolist())

    Asm2VecPlus_64_vec_list = round_list(Asm2VecPlus_64_vec_list,round_num=4)
    return Asm2VecPlus_64_vec_list

def _Asm2VecPlus_128(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]):
    Asm2VecPlus_128_vec_list = []
    for hex_asm_item in hex_asm:
        if hex_asm_item=='':
            hex_asm_item="90"
        initial_vector =get_seq_encoder1(hex_asm_item)
        initial_vector= torch.tensor(initial_vector).to(device)
        try:
            Asm2VecPlus_128_vec_list.append(Asm2VecPlus_64(initial_vector).tolist())
        except:
            hex_asm_item="90"
            initial_vector = get_seq_encoder1(hex_asm_item)
            initial_vector = torch.tensor(initial_vector).to(device)
            Asm2VecPlus_128_vec_list.append(Asm2VecPlus_128(initial_vector).tolist())

    Asm2VecPlus_128_vec_list = round_list(Asm2VecPlus_128_vec_list,round_num=4)
    return Asm2VecPlus_128_vec_list\

def _Asm2VecPlus_256(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]):
    Asm2VecPlus_256_vec_list = []
    for hex_asm_item in hex_asm:
        if hex_asm_item=='':
            hex_asm_item="90"
        initial_vector =get_seq_encoder1(hex_asm_item)
        initial_vector= torch.tensor(initial_vector).to(device)
        try:
            Asm2VecPlus_256_vec_list.append(Asm2VecPlus_256(initial_vector).tolist())
        except:
            hex_asm_item="90"
            initial_vector = get_seq_encoder1(hex_asm_item)
            initial_vector = torch.tensor(initial_vector).to(device)
            Asm2VecPlus_256_vec_list.append(Asm2VecPlus_256(initial_vector).tolist())

    Asm2VecPlus_256_vec_list = round_list(Asm2VecPlus_256_vec_list,round_num=4)
    return Asm2VecPlus_256_vec_list



def Asm2VecPlus(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]):
    Asm2VecPlus_8_vec_list = []
    Asm2VecPlus_16_vec_list = []
    Asm2VecPlus_32_vec_list = []
    Asm2VecPlus_64_vec_list = []
    Asm2VecPlus_128_vec_list = []
    Asm2VecPlus_256_vec_list = []

    for hex_asm_item in hex_asm:
        if hex_asm_item=='':
            hex_asm_item="90"
        initial_vector =get_seq_encoder1(hex_asm_item)
        # print(initial_vector)
        # exit()
        initial_vector= torch.tensor(initial_vector).to(device)

        try:
            Asm2VecPlus_8_vec_list.append(Asm2VecPlus_8(initial_vector).tolist())
            Asm2VecPlus_16_vec_list.append(Asm2VecPlus_16(initial_vector).tolist())
            Asm2VecPlus_32_vec_list.append(Asm2VecPlus_32(initial_vector).tolist())
            Asm2VecPlus_64_vec_list.append(Asm2VecPlus_64(initial_vector).tolist())
            Asm2VecPlus_128_vec_list.append(Asm2VecPlus_128(initial_vector).tolist())
            Asm2VecPlus_256_vec_list.append(Asm2VecPlus_256(initial_vector).tolist())
        except:
            hex_asm_item="90"
            initial_vector = get_seq_encoder1(hex_asm_item)
            initial_vector = torch.tensor(initial_vector).to(device)
            Asm2VecPlus_8_vec_list.append(Asm2VecPlus_8(initial_vector).tolist())
            Asm2VecPlus_16_vec_list.append(Asm2VecPlus_16(initial_vector).tolist())
            Asm2VecPlus_32_vec_list.append(Asm2VecPlus_32(initial_vector).tolist())
            Asm2VecPlus_64_vec_list.append(Asm2VecPlus_64(initial_vector).tolist())
            Asm2VecPlus_128_vec_list.append(Asm2VecPlus_128(initial_vector).tolist())
            Asm2VecPlus_256_vec_list.append(Asm2VecPlus_256(initial_vector).tolist())

    Asm2VecPlus_8_vec_list = round_list(Asm2VecPlus_8_vec_list,round_num=4)
    Asm2VecPlus_16_vec_list = round_list(Asm2VecPlus_16_vec_list,round_num=4)
    Asm2VecPlus_32_vec_list = round_list(Asm2VecPlus_32_vec_list,round_num=4)
    Asm2VecPlus_64_vec_list = round_list(Asm2VecPlus_64_vec_list,round_num=4)
    Asm2VecPlus_128_vec_list = round_list(Asm2VecPlus_128_vec_list,round_num=4)
    Asm2VecPlus_256_vec_list = round_list(Asm2VecPlus_256_vec_list,round_num=4)


    return Asm2VecPlus_8_vec_list,Asm2VecPlus_16_vec_list,Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,Asm2VecPlus_128_vec_list,Asm2VecPlus_256_vec_list




def init_vecotr_374(hex_asm="56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"):
    vec_list = []
    for hex_asm_item in hex_asm:
        if hex_asm_item == '':
            hex_asm_item = "90"
        initial_vector = get_seq_encoder1(hex_asm_item)
        vec_list.append(initial_vector)
    # print(vec_list)
    return vec_list



    # vec_list = round_list(initial_vector,round_num=4)




















def check_features_length(features):
    """
    检查特征列表中每个子列表的长度，确保它们都是非空且长度一致。
    如果有长度不一致的情况，打印出不一致的子列表的索引和长度。
    """
    # 存储所有子列表的长度
    lengths = []
    for i, sublist in enumerate(features):
        # 检查子列表是否为空
        if not sublist:
            print(f"子列表 {i} 是空的。")
            print(sublist)
        else:
            # 记录非空子列表的长度
            lengths.append((i, len(sublist)))
    # 检查长度是否一致
    if lengths:
        first_length = lengths[0][1]
        for index, length in lengths:
            if length != first_length:
                print(f"子列表 {index} 的长度是 {length}，与第一个子列表的长度 {first_length} 不一致。")
    return lengths

def malconv(hex_asm="56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"):
    vec_list=[]


    for hex_asm_item in hex_asm:
        vec=[0]*256
        hex_asm_pretreat=""
        for i in range(len(hex_asm_item)):
            hex_asm_pretreat=hex_asm_pretreat+hex_asm_item[i]
            if (i+1) % 2==0:
                hex_asm_pretreat=hex_asm_pretreat+" "
        # print(hex_asm_pretreat)
        hex_asm_pretreat=hex_asm_pretreat.split()
        # print(hex_asm_pretreat)
        for i in range(len(hex_asm_pretreat)):
            hex_asm_pretreat[i]=int(hex_asm_pretreat[i],16)
            vec[hex_asm_pretreat[i]]+=1
        vec_list.append(vec)
    # print(hex_asm_pretreat)
    return vec_list

with open("./n_gram_1/" + 'vocab.json', 'r', encoding='utf-8') as fp:
    n_gram_1_vocab = json.load(fp)

def n_gram_1(dim=400,hex_asm="56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"):

    vec_list = []
    for hex_asm_item in hex_asm:
        vec = [0] * dim

        HexCode = binascii.unhexlify(hex_asm_item)
        for item in md.disasm(HexCode, 0):
            if item.mnemonic in n_gram_1_vocab:
                vec[n_gram_1_vocab[item.mnemonic]] += 1
        vec_list.append(vec)
    return vec_list

with open("./n_gram_2/" + 'vocab.json', 'r', encoding='utf-8') as fp:
    n_gram_2_vocab = json.load(fp)
#2-gram ,长度为1024
def n_gram_2(dim=400,hex_asm="56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"):
    vec_len=dim
    vec_list = []
    for hex_asm_item in hex_asm:
        vec = [0] * vec_len

        HexCode = binascii.unhexlify(hex_asm_item)

        Hex_list=[]
        for item in md.disasm(HexCode, 0):
            Hex_list.append(item.mnemonic)

        for i in range(len(Hex_list)-1):
            if Hex_list[i]+" "+Hex_list[i+1] in n_gram_2_vocab:
                index=int(n_gram_2_vocab[Hex_list[i]+" "+Hex_list[i+1]])
                if index < vec_len:
                    vec[index]+=1
        vec_list.append(vec)
    return vec_list

with open("./n_gram_3/" + 'vocab.json', 'r', encoding='utf-8') as fp:
    n_gram_3_vocab = json.load(fp)
#2-gram ,长度为1024
def n_gram_3(dim=400,hex_asm="56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"):
    vec_len=dim
    vec_list = []
    for hex_asm_item in hex_asm:
        vec = [0] * vec_len

        HexCode = binascii.unhexlify(hex_asm_item)

        Hex_list=[]
        for item in md.disasm(HexCode, 0):
            Hex_list.append(item.mnemonic)

        for i in range(len(Hex_list)-2):
            if Hex_list[i]+" "+Hex_list[i+1]+" "+Hex_list[i+2] in n_gram_3_vocab:
                index=int(n_gram_3_vocab[Hex_list[i]+" "+Hex_list[i+1]+" "+Hex_list[i+2]])
                if index < vec_len:
                    vec[index]+=1
        vec_list.append(vec)
    return vec_list

def split_basicblock_byte(asm_bytes):
    code_list = []

    HexCode = binascii.unhexlify(asm_bytes)
    for item in md.disasm(HexCode, 0):
        hex_string = ''.join(['{:02x}'.format(b) for b in item.bytes])
        code_list.append(hex_string)
    return code_list


def avrage_res(vectors):
    average_vector = [sum(x) / len(x) for x in zip(*vectors)]
    return average_vector

def add_res(vectors):
    add_vectors=[sum(x) for x in zip(*vectors)]
    return add_vectors


def instruction_count(hex_asm):
    instruction_count_list = []
    for hex_asm_item in hex_asm:
        a = len(split_basicblock_byte(hex_asm_item))
        instruction_count_list.append(a)
    return instruction_count_list

def parse_dict_string(dict_string):
    # 移除字符串两端的大括号
    dict_string = dict_string.strip()[1:-1]

    # 分割键值对
    pairs = dict_string.split(",")

    # 解析每个键值对
    result = {}
    for pair in pairs:
        key, value = pair.split(":")

        # 移除键两端的引号
        key = key.strip("'\"")

        # 将值转换为整数
        value = int(value)

        result[key] = value

    return result
def Magic(hex_asm="",offspring=1,instructions_in_vertex=1):


    # bytes=""
    # for i in hex_asm:
    #     bytes+=i
    # hex_asm=bytes
    feature_vector_list=[]

    if type(offspring)==str:
        offspring=parse_dict_string(offspring)
    if type(instructions_in_vertex)==str:
        instructions_in_vertex=parse_dict_string(instructions_in_vertex)



    offspring_list=[]
    for value in offspring.values():
        offspring_list.append(value)

    instructions_in_vertex_list=[]
    for value in instructions_in_vertex.values():
        instructions_in_vertex_list.append(value)
    i=0
    for bytes in hex_asm:
        HexCode = binascii.unhexlify(bytes)

        # 解析字节序列中的指令
        instructions = list(md.disasm(HexCode, 0x1000))

        # 初始化特征计数
        numeric_constants = 0
        transfer_instructions = 0
        call_instructions = 0
        arithmetic_instructions = 0
        compare_instructions = 0
        mov_instructions = 0
        termination_instructions = 0
        data_declaration_instructions = 0
        total_instructions = len(instructions)


        # 遍历指令提取特征
        # print(instructions)
        # exit()
        for insn in instructions:

            for op in insn.operands:
                if op.type == CS_OP_IMM:  # Check for immediate operand type
                    numeric_constants += 1
                    break  # Once an immediate value is found, no need to check further

            if insn.mnemonic in ['jmp', 'jne', 'je', 'ja', 'jb', 'jg', 'jl', 'jle', 'jge', 'jbe', 'jae', 'jna', 'jnb', 'jno', 'jnp', 'jns', 'jnz', 'jo', 'jp', 'js', 'jz']:
                transfer_instructions += 1
            if insn.mnemonic == 'call':
                call_instructions += 1
            if insn.mnemonic in ['add', 'sub', 'mul', 'div', 'inc', 'dec', 'adc', 'sbb', 'imul', 'idiv', 'neg', 'not', 'and', 'or', 'xor', 'shl', 'shr', 'sal', 'sar', 'rol', 'ror']:
                arithmetic_instructions += 1
            if insn.mnemonic in ['cmp', 'test', 'setae', 'setb', 'setbe', 'setc', 'sete', 'setg', 'setge', 'setl', 'setle', 'setna', 'setnae', 'setnb', 'setnbe', 'setnc', 'setne', 'setng', 'setnge', 'setnl', 'setnle', 'setno', 'setnp', 'setns', 'setnz', 'seto', 'setp', 'setpe', 'setpo', 'sets', 'setz']:
                compare_instructions += 1
            if insn.mnemonic.startswith('mov') or insn.mnemonic in ['xchg', 'movzx', 'movsx', 'lea', 'cmovae', 'cmovb', 'cmovbe', 'cmovg', 'cmovge', 'cmovl', 'cmovle', 'cmovne', 'cmovno', 'cmovnp', 'cmovns', 'cmovnz', 'cmovo', 'cmovp', 'cmovpe', 'cmovpo', 'cmovs', 'cmovz']:
                mov_instructions += 1
            if insn.mnemonic in ['ret', 'retn', 'retf', 'iret', 'iretd', 'iretq', 'sysenter', 'sysexit', 'syscall', 'sysret']:
                termination_instructions += 1
            # 数据声明指令通常在源码中声明，而非在字节码中
        # instructions_in_vertex_count=0
        # if type(instructions_in_vertex)==str:
        #     instructions_in_vertex=eval(instructions_in_vertex)
        # if type(offspring)==str:
        #     offspring=eval(offspring)
        # for val in instructions_in_vertex.values():
        #     instructions_in_vertex_count+=val

        # print(offspring)
        # offspring_count=0
        # for val in offspring.values():
        #     offspring_count+=val
        try:
            offspring_count=offspring_list[i]
            instructions_in_vertex_count=instructions_in_vertex_list[i]
        except:
            offspring_count=0
            instructions_in_vertex_count=0
        i=i+1
        # 组装特征向量
        feature_vector = [
            numeric_constants,
            transfer_instructions,
            call_instructions,
            arithmetic_instructions,
            compare_instructions,
            mov_instructions,
            termination_instructions,
            data_declaration_instructions,
            total_instructions,
            offspring_count,
            instructions_in_vertex_count
        ]
        feature_vector_list.append(feature_vector)
    return feature_vector_list

if __name__ == '__main__':


    # a=eval("{4198400: 6, 4198420: 4, 4198425: 2, 4198910: 3, 4198916: 3, 4198893: 2, 4198896: 3, 4198899: 1, 4198901: 2, 4198989: 2, 4198906: 5, 4199112: 1, 4199117: 3, 4267729: 8, 4267746: 12, 4267841: 2, 4267844: 8}")
    # for val in a.values():
    #     print(val)
    # print(a)
    # exit()
    # print(add_res([[1,1],[2,3]]))
    print(Magic(hex_asm=['538b8531b9e35a68cae50697503b0fa0e092161a583a8bf802d4c186b8a634e7cfbd610cd75997b3cd91b57ff4', '86b8a634e7cfbd610cd75997b3cd91b57ff4'],offspring="{4261814: 1, 4261841: 1}",instructions_in_vertex="{4261814: 15, 4261841: 7}"))
    print(n_gram_1(dim=400,hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3","56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]))
    print(n_gram_2(dim=400,hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3","56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]))
    print(n_gram_3(dim=400,hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3","56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]))
    print(malconv(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3","56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"]))
    exit()
    # exit()
    # print(malconv(a))
    # print(n_gram_1(dim=256,hex_asm=a))
    # print(n_gram_2(dim=256,hex_asm=a))
    # print(n_gram_3(dim=256,hex_asm=a))
    # print(Asm2VecPlus())
    # 示例字节序列，应替换为您的具体字节码
    # byte_sequence_example = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"

    # 提取特征向量
    # feature_vector = Magic(byte_sequence_example,offspring=1)
    # print("Feature vector:", feature_vector)