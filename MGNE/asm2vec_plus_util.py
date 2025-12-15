import sys
# sys.path.append("/features_method/asm2vec_plus/")
from capstone import *
from capstone.x86 import *
import torch
import base64
# from .asm2vec_plus_model import ASM2VEC
from .xprint import to_hex, to_x, to_x_32

legacy_prefix_all_msg={"lock":[0x0,0xF0],"segment":[0x2E,0x36,0x3E,0x26,0x64,0x65],"oprandsize":[0x0,0x66],"address":[0x0,0x67]}
# def load_asm2vec_plus_model(path, device='cpu'):
#     checkpoint = torch.load(path, map_location=device)
#
#     model = ASM2VEC(*checkpoint['model_params'])
#     model.load_state_dict(checkpoint['model'])
#     model = model.to(device)
#     return model

def str_hex_to_bytes(str_hex):

    y = bytearray.fromhex(str_hex)
    z = list(y)


    asm_hex_str = b''

    for i in z:

        right = str(hex(i))[2:]

        if right == "0":
            right = "00"
        if len(right) == 1:
            right = "0" + right
        item = base64.b16decode(right.upper())
        asm_hex_str += item

    return asm_hex_str

def get_asm_msg(insn):
    # print(dir(insn))
    # exit()
    text1=""
    for i in range(insn.size):
        text1 += '%02X ' % insn.bytes[i]
    address=insn.address

    prefix=insn.prefix
    opcode=insn.opcode

    modrm=insn.modrm
    disp=insn.disp
    sib=insn.sib
    imme_cont=insn.op_count(X86_OP_IMM)

    if imme_cont!=0:
        op = insn.op_find(X86_OP_IMM, 1)
        imme="0x"+to_x(op.imm)
        imme=int(imme,16)
    else:
        imme=0

    # if prefix!=[0,0,0,0]:

    # print("\t%s" % (insn.mnemonic))
    # print("\t%s\t%s" % (insn.mnemonic, insn.op_str))
    # print(dir(insn.op_count))

    # print("\t机器码 : "+ str(asm_code))
    # print("\t地址addr : "+ str(address))
    # print("\t前缀prefix ：" + str(prefix))
    # print("\t操作码opcode : "+str(opcode))
    # print("\tmodrm : "+str(modrm))
    # print("\tsib : "+str(sib))
    # print(type(insn.disp))
    # print("\tdisp : "+hex(insn.disp))
    # print("\timme : "+hex(imme))
    # exit()

    # 打印操作数的REX前缀（非零值与x86_64指令相关）
    # print("\trex: 0x%x" % (insn.rex))
    return str(address),prefix,str(opcode[0]),str(modrm),str(sib),str(disp),str(imme),imme_cont


def msg_to_vector(normal,address,prefix,opcode,modrm,sib,disp,imme,imme_cont):

    # addr_vec=[0]*64
    opcode_vec=[0]*256
    # option_vec=[0]*8 #prefix[0,0,0,0]\modrm\sib\disp\imme
    option_vec = [0] * 5  # prefix[0,0,0,0]\modrm\sib\disp\imme
    prefix_vec=[0]*9  #1/6/1/1
    moderm_vec=[0]*20
    sib_vec=[0]*20
    # disp_flag=[0]
    disp_vec=[0]*32
    # imme_flag=[0]
    imme_vec=[0]*32
    address, opcode, modrm, sib, disp, imme=int(address),int(opcode),int(modrm),int(sib),int(disp),int(imme)
    address, modrm, sib, disp, imme= bin(address), bin(modrm), bin(sib), bin(disp), bin(imme)

    if disp[0]=="-":
        disp_flag=[1]
        disp=disp[1:]
    if imme[0]=="-":
        imme_flag=[1]
        imme=disp[1:]
    address, modrm, sib, disp, imme= address[2:], modrm[2:], sib[2:], disp[2:], imme[2:]

    #填充address至64位
    # if len(address)<64:
    #     address="0"*(64-len(address))+address
    #
    # for i in range(len(address)):
    #     addr_vec[i]=int(address[i])
    # print("addr_vec:"+str(addr_vec))

    #one-hot表示
    opcode_vec[opcode]=1


    if prefix[0]!=0 :
        option_vec[0]=1
    if prefix[1]!=0 :
        option_vec[0] = 1
    if prefix[2]!=0 :
        option_vec[0] = 1
    if prefix[3]!=0:
        option_vec[0] = 1

    if modrm!="0":
        option_vec[1]=1
    if sib!="0":
        option_vec[2]=1
    if disp!="0":
        option_vec[3]=1
    if imme_cont!=0:
        option_vec[4]=1

    if len(disp)>32:
        disp=disp[:32]

    if len(imme)>32:
        imme = imme[:32]

    if len(disp)<=32:
        disp="0"*(32-len(disp))+disp

    if len(imme)<=32:
        imme="0"*(32-len(imme))+imme

    for i in range(len(disp)):
        disp_vec[i] = int(disp[i])


    for i in range(len(imme)):
        imme_vec[i] = int(imme[i])
    # print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
    # print("\t机器码 : "+ str(asm_code))

    for i in range(len(prefix)):
        prefix[i]=int(prefix[i])

    for j in range(len(legacy_prefix_all_msg["lock"])):
        if prefix[0]==legacy_prefix_all_msg["lock"][j]:
            prefix_vec[0]=j
            break
    for j in range(len(legacy_prefix_all_msg["segment"])):
        if prefix[1] == legacy_prefix_all_msg["segment"][j]:
            prefix_vec[j+1] = 1
            break

    for j in range(len(legacy_prefix_all_msg["oprandsize"])):
        if prefix[2] == legacy_prefix_all_msg["oprandsize"][j]:
            prefix_vec[7] = j
            break
    for j in range(len(legacy_prefix_all_msg["address"])):
        if prefix[3] == legacy_prefix_all_msg["address"][j]:
            prefix_vec[8] = j
            break

    # print("prefix_vec:" + str(prefix_vec))


    if len(modrm)<8:
        modrm="0"*(8-len(modrm))+modrm
    # print("modrm:"+modrm)
    modrm_split1="0b"+modrm[:2]
    modrm_split2="0b"+modrm[2:5]
    modrm_split3="0b"+modrm[5:]
    modrm_int1 = int(modrm_split1,2)
    modrm_int2 = int(modrm_split2, 2)
    modrm_int3 = int(modrm_split3, 2)

    moderm_vec[modrm_int1] = 1
    moderm_vec[modrm_int2 + 4] = 1
    moderm_vec[modrm_int3 + 12] = 1

    if len(sib)<8:
        sib="0"*(8-len(sib))+sib
    # print("sib:"+sib)
    sib_split1="0b"+sib[:2]
    sib_split2="0b"+sib[2:5]
    sib_split3="0b"+sib[5:]
    sib_int1 = int(sib_split1,2)
    sib_int2 = int(sib_split2, 2)
    sib_int3 = int(sib_split3, 2)

    sib_vec[sib_int1] = 1
    sib_vec[sib_int2 + 4] = 1
    sib_vec[sib_int3 + 12] = 1

    # result_vec = opcode_vec + option_vec + prefix_vec + moderm_vec + sib_vec + disp_flag + disp_vec + imme_flag + imme_vec
    # result_vec=addr_vec+opcode_vec+option_vec+prefix_vec+moderm_vec+sib_vec+disp_flag+disp_vec+imme_flag+imme_vec
    result_vec=opcode_vec+option_vec+prefix_vec+moderm_vec+sib_vec+disp_vec+imme_vec
    # print("addr_vec:"+str(addr_vec))
    # print("opcode_vec:" + str(opcode_vec))
    # print("option_vec:"+str(option_vec))
    # print("disp_vec:"+str(disp_vec))
    # print("imme_vec:"+str(imme_vec))
    # print("prefix_vec:" + str(prefix_vec))
    # print("moderm_vec:" + str(moderm_vec))
    # print("sib_vec:" + str(sib_vec))
    # print("result_vec:\n"+str(result_vec))


    #对数组做归一化处理
    # if normal==True:
    #     not_zero_sum=0
    #     for i in result_vec:
    #         if i != 0:
    #             not_zero_sum+=i
    #     for i in range(len(result_vec)):
    #         if result_vec[i] != 0:
    #             result_vec[i]=result_vec[i]/not_zero_sum
    return result_vec



def get_asm_input_vector(X86_CODE32,normal=True):

    arch, mode, code, comment, syntax=CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (Intel syntax)", None
    one_sample_vec_seq=[]
    opcode_oprand_seq=[]
    try:

        md = Cs(arch, mode)
        md.detail = True
        if syntax is not None:
            md.syntax = syntax

        for insn in md.disasm(code, 0x0):

            address, prefix, opcode, modrm, sib, disp, imme,imme_cont=get_asm_msg( insn)
            result_vec=msg_to_vector(normal,address, prefix, opcode, modrm, sib, disp, imme,imme_cont)
            one_sample_vec_seq.append(result_vec)
            opcode_oprand_seq.append("0x%x:%s %s" % (insn.address, insn.mnemonic, insn.op_str))
            # print("one_sample_vec_seq:" + str(one_sample_vec_seq))
            # print(len(one_sample_vec_seq))
        #返回vector列表，

        return one_sample_vec_seq,opcode_oprand_seq
    except CsError as e:
        print("ERROR: %s" % e)
        exit()
