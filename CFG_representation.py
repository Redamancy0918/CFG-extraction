import angr
import csv
import os
from tqdm import tqdm
from capstone import *
import binascii
from representation_method import malconv,n_gram_1,n_gram_2,n_gram_3,split_basicblock_byte,instruction_count,Asm2VecPlus,Asm2VecBase,Magic,Asm2VecBase1,\
    representation_method_func,Asm2VecBase_get_basicblock_seq_vec_list,Asm2VecPlus_get_basicblock_seq_vec_list,get_basicblock_seq_vec_list\
#     ,Asm2VecPlus_get_basicblock_seq_vec_list_8,\
# Asm2VecPlus_get_basicblock_seq_vec_list_16,Asm2VecPlus_get_basicblock_seq_vec_list_32,Asm2VecPlus_get_basicblock_seq_vec_list_64,Asm2VecPlus_get_basicblock_seq_vec_list_128,Asm2VecPlus_get_basicblock_seq_vec_list_256,init_vector_374_get_basicblock_seq_vec_list

import multiprocessing as mp
import ast
import json
csv.field_size_limit(1310720000)
def process_edge_row(row):

    File_name=row['File Name']
    try:
        CFG_Basicblock_Byte_Sequence = eval(row['Basicblock Byte Sequence'])
        Basicblock_Instructions_Count = eval(row['Basicblock Instructions Count'])
        offspring_counts=row['offspring_counts']
        instructions_in_vertex = row['instructions_in_vertex']
    except:
        CFG_Basicblock_Byte_Sequence = ['90']
        Basicblock_Instructions_Count = [1]
        offspring_counts={401000:1}
        instructions_in_vertex = {401000:1}
    return File_name,CFG_Basicblock_Byte_Sequence,Basicblock_Instructions_Count,offspring_counts,instructions_in_vertex

def read_cfg_from_csv_mutiple_thread(path=r"\\ZJNU-NSR\Malware\Microsoft\CFG",num_samples=None):
    CFG_Basicblock_Byte_Sequence_list=[]
    File_names_list=[]
    Basicblock_Instructions_Counts_list=[]
    offspring_counts_list=[]
    instructions_in_vertex_list=[]
    print("加载边信息...")
    with open(os.path.join(path, "edges.csv"), 'r') as edges_file:
        reader = list(csv.DictReader(edges_file))  # 读取所有行到内存

        # 创建进程池
        with mp.Pool(processes=8) as pool:
            # 使用 imap 处理每一行
            results = pool.imap(process_edge_row, reader, chunksize=10)

            try:

                for idx, (File_name,CFG_Basicblock_Byte_Sequence,Basicblock_Instructions_Count,offspring_counts,instructions_in_vertex) in enumerate(tqdm(results)):
                    File_names_list.append(File_name)
                    CFG_Basicblock_Byte_Sequence_list.append(CFG_Basicblock_Byte_Sequence)
                    Basicblock_Instructions_Counts_list.append(Basicblock_Instructions_Count)
                    offspring_counts_list.append(offspring_counts)
                    instructions_in_vertex_list.append(instructions_in_vertex)
                    if num_samples is not None and idx + 1 == num_samples:
                        break
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()
                raise

    return File_names_list,CFG_Basicblock_Byte_Sequence_list,Basicblock_Instructions_Counts_list,offspring_counts_list,instructions_in_vertex_list


def load_CFG_Basicblock_Byte_Sequence_list(folder, num_samples=None):
    File_names,CFG_Basicblock_Byte_Sequence_list,Basicblock_Instructions_Counts_list,offspring_counts_list,instructions_in_vertex_list= read_cfg_from_csv_mutiple_thread(path=folder,num_samples=num_samples)
    File_names, CFG_Basicblock_Byte_Sequence_list, Basicblock_Instructions_Counts_list, offspring_counts_list, instructions_in_vertex_list =File_names[:10000],CFG_Basicblock_Byte_Sequence_list[:10000],Basicblock_Instructions_Counts_list[:10000],offspring_counts_list,instructions_in_vertex_list[:10000]
    return File_names,CFG_Basicblock_Byte_Sequence_list,Basicblock_Instructions_Counts_list,offspring_counts_list,instructions_in_vertex_list





# 定义提取CFG信息的函数
def extract_cfg_info(p):
    cfg = p.analyses.CFGFast(show_progressbar=True,
                             normalize=False,
                             resolve_indirect_jumps=False,
                             force_smart_scan=False,
                             symbols=False,
                             data_references=False)
    # print(cfg)
    # 提取CFG边信息
    edges = [(edge[0].addr, edge[1].addr) for edge in cfg.graph.edges()]

    # print(edges)
    # edges = cfg.graph.edges()
    # print(edges)

    # 提取CFG中每个基本块的字节序列信息
    byte_sequences = []
    nodes_addr = []

    for node in cfg.graph.nodes():
        # print(node.addr)
        byte_info = p.loader.memory.load(node.addr, node.size)
        byte_sequences.append(byte_info.hex())
        nodes_addr.append(node.addr)
    # exit()
    return edges, nodes_addr,byte_sequences

def extract_cfg_info_magic(p):
    cfg = p.analyses.CFGFast(show_progressbar=True,
                             normalize=False,
                             resolve_indirect_jumps=False,
                             force_smart_scan=False,
                             symbols=False,
                             data_references=False)
    # 提取CFG边信息
    edges = [(edge[0].addr, edge[1].addr) for edge in cfg.graph.edges()]

    # 提取CFG中每个基本块的字节序列信息
    byte_sequences = []
    nodes_addr = []
    offspring_counts = {}  # 存储每个节点的子节点数量
    instructions_in_vertex = {}  # 存储每个节点的指令数量

    for node in cfg.graph.nodes():
        byte_info = p.loader.memory.load(node.addr, node.size)
        byte_sequences.append(byte_info.hex())
        nodes_addr.append(node.addr)

        # 计算每个节点的子节点（offspring）个数
        offspring_counts[node.addr] = len(list(cfg.graph.successors(node)))

        # 计算每个顶点中的指令数量
        block = p.factory.block(node.addr)
        instructions_in_vertex[node.addr] = len(block.capstone.insns)

    # 返回边信息、节点地址、字节序列信息、子节点数量信息和顶点中的指令数量信息
    return edges, nodes_addr, byte_sequences, offspring_counts, instructions_in_vertex




# 遍历文件夹并处理每个文件
def get_edges_msg(folder_path, shaixuan_list,output_csv_path):
    with open(output_csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['File Name','CFG Nodes', 'CFG Edges', 'Basicblock Byte Sequence','Basicblock Instructions Count','offspring_counts','instructions_in_vertex'])

        # 遍历文件夹中的所有文件
        # for filename in tqdm(os.listdir(folder_path)):
        count=0
        for filename in tqdm(shaixuan_list):
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path):
                try:
                    # 创建angr项目
                    p = angr.Project(file_path, auto_load_libs=False)
                    # 提取CFG信息
                    edges,nodes_addr,byte_sequences, offspring_counts, instructions_in_vertex = extract_cfg_info_magic(p)

                    instruction_counts=instruction_count(byte_sequences)
                    # 写入CSV文件
                    writer.writerow([filename, str(nodes_addr),str(edges), str(byte_sequences), str(instruction_counts).replace(" ", ""),str(offspring_counts).replace(" ", ""), str(instructions_in_vertex).replace(" ", "")])
                    count+=1
                    print(count)
                except Exception as e:
                    print(f"Error processing file {filename}: {e}")


def process_file(args):
    idx,folder_path, filename, output_csv_path = args
    file_path = os.path.join(folder_path, filename)
    # print(file_path)
    if os.path.isfile(file_path):
        try:
            # 创建angr项目
            p = angr.Project(file_path, auto_load_libs=False)
            # 提取CFG信息
            edges, nodes_addr, byte_sequences, offspring_counts, instructions_in_vertex = extract_cfg_info_magic(p)

            instruction_counts = instruction_count(byte_sequences)
            # 返回结果
            return [idx,filename, nodes_addr, edges, byte_sequences, instruction_counts, offspring_counts, instructions_in_vertex]
        except Exception as e:
            print(f"Error processing file {filename}: {e}")
            return [filename, None, None, None, None, None, None]

def get_edges_msg_mp(folder_path, shaixuan_list, output_csv_path):
    # 准备数据写入CSV
    with open(output_csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["idx",'File Name', 'CFG Nodes', 'CFG Edges', 'Basicblock Byte Sequence', 'Basicblock Instructions Count', 'offspring_counts', 'instructions_in_vertex'])

        # 创建线程池
        with mp.Pool(processes=4) as pool:
            try:
                tasks = [(idx,folder_path, shaixuan_list[idx], output_csv_path) for idx in range(len(shaixuan_list))]

                # 处理文件并获取结果
                for result in tqdm(pool.imap(process_file, tasks), total=len(tasks)):
                    print(result)
                    # 写入CSV文件
                    writer.writerow(result)
            except:
                # 关闭线程池
                pool.close()
                pool.join()






import os

def make_csv_add(mulu,representation_methods=["malconv","n_gram_1"]):

    csvfile_dict={}
    csvfile_writer_dict={}
    for representation_method in representation_methods:
        path=os.path.join(mulu,representation_method+".csv")

        csvfile = open(path, 'a', newline='')
        csvfile_writer = csv.writer(csvfile)
        # csvfile_writer.writerow(['File Name', 'vec'])

        csvfile_dict[representation_method]=csvfile
        csvfile_writer_dict[representation_method]=csvfile_writer

    return csvfile_dict,csvfile_writer_dict

def make_csv(mulu,representation_methods=["malconv","n_gram_1"]):

    csvfile_dict={}
    csvfile_writer_dict={}
    for representation_method in representation_methods:
        path=os.path.join(mulu,representation_method+".csv")

        csvfile = open(path, 'w', newline='')
        csvfile_writer = csv.writer(csvfile)
        csvfile_writer.writerow(["idx",'File Name', 'vec'])

        csvfile_dict[representation_method]=csvfile
        csvfile_writer_dict[representation_method]=csvfile_writer

    return csvfile_dict,csvfile_writer_dict

def close_csv(representation_methods,csvfile_dict):
    for representation_method in representation_methods:
        csvfile_dict[representation_method].close()
def featured_cfg1(folder_path,shaixuan_list,mulu,representation_methods=["malconv","n_gram_1","n_gram_2","n_gram_3"]):


    csvfile_dict,csvfile_writer_dict=make_csv(mulu,representation_methods)

    # 遍历文件夹中的所有文件
    for filename in tqdm(shaixuan_list):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
                # 创建angr项目
                p = angr.Project(file_path, auto_load_libs=False)
                # 提取CFG信息
                edges, nodes_addr, byte_sequences, offsprings, instructions_in_vertex = extract_cfg_info_magic(p)

                for representation_method in representation_methods:

                    if "Asm2VecPlus_8" == representation_method:
                        Asm2VecPlus_8_vec_list, Asm2VecPlus_16_vec_list, Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,\
                        Asm2VecPlus_128_vec_list, Asm2VecPlus_256_vec_list = Asm2VecPlus_get_basicblock_seq_vec_list(byte_sequences,representation_method=representation_method)
                        csvfile_writer_dict["Asm2VecPlus_8"].writerow([filename, Asm2VecPlus_8_vec_list])
                        csvfile_writer_dict["Asm2VecPlus_16"].writerow([filename, Asm2VecPlus_16_vec_list])
                        csvfile_writer_dict["Asm2VecPlus_32"].writerow([filename, Asm2VecPlus_32_vec_list])
                        csvfile_writer_dict["Asm2VecPlus_64"].writerow([filename, Asm2VecPlus_64_vec_list])
                        csvfile_writer_dict["Asm2VecPlus_128"].writerow([filename, Asm2VecPlus_128_vec_list])
                        csvfile_writer_dict["Asm2VecPlus_256"].writerow([filename, Asm2VecPlus_256_vec_list])
                        break
                    elif "Asm2VecBase_8" == representation_method:
                        Asm2VecBase_8_vec_list, Asm2VecBase_16_vec_list, Asm2VecBase_32_vec_list, \
                        Asm2VecBase_64_vec_list, Asm2VecBase_128_vec_list, Asm2VecBase_256_vec_list \
                            = Asm2VecBase_get_basicblock_seq_vec_list(byte_sequences,
                                                                  representation_method=representation_method)


                        csvfile_writer_dict["Asm2VecBase_8"].writerow([filename, Asm2VecBase_8_vec_list])
                        csvfile_writer_dict["Asm2VecBase_16"].writerow([filename, Asm2VecBase_16_vec_list])
                        csvfile_writer_dict["Asm2VecBase_32"].writerow([filename, Asm2VecBase_32_vec_list])
                        csvfile_writer_dict["Asm2VecBase_64"].writerow([filename, Asm2VecBase_64_vec_list])
                        csvfile_writer_dict["Asm2VecBase_128"].writerow([filename, Asm2VecBase_128_vec_list])
                        csvfile_writer_dict["Asm2VecBase_256"].writerow([filename, Asm2VecBase_256_vec_list])

                        break
                    elif  "Magic" == representation_method:
                        a = get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method,offspring=offsprings,instructions_in_vertex=instructions_in_vertex)
                        csvfile_writer_dict[representation_method].writerow([filename, str(a).replace(" ", "")])
                    else:
                        a=get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method)
                        csvfile_writer_dict[representation_method].writerow([filename, str(a).replace(" ","")])


    close_csv(representation_methods,csvfile_dict)



def featured_cfg(mulu,representation_methods=["malconv","n_gram_1","n_gram_2","n_gram_3"]):


    csvfile_dict,csvfile_writer_dict=make_csv(mulu,representation_methods)

    filenames,CFG_Basicblock_Byte_Sequence_list=load_CFG_Basicblock_Byte_Sequence_list(mulu)
    i=0
    for byte_sequences in tqdm(CFG_Basicblock_Byte_Sequence_list):
        filename=filenames[i]
        i=i+1
        for representation_method in representation_methods:

            if "Asm2VecPlus_8" == representation_method:
                Asm2VecPlus_8_vec_list, Asm2VecPlus_16_vec_list, Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,\
                Asm2VecPlus_128_vec_list, Asm2VecPlus_256_vec_list = Asm2VecPlus_get_basicblock_seq_vec_list(byte_sequences,representation_method=representation_method)
                csvfile_writer_dict["Asm2VecPlus_8"].writerow([filename, Asm2VecPlus_8_vec_list])
                csvfile_writer_dict["Asm2VecPlus_16"].writerow([filename, Asm2VecPlus_16_vec_list])
                csvfile_writer_dict["Asm2VecPlus_32"].writerow([filename, Asm2VecPlus_32_vec_list])
                csvfile_writer_dict["Asm2VecPlus_64"].writerow([filename, Asm2VecPlus_64_vec_list])
                csvfile_writer_dict["Asm2VecPlus_128"].writerow([filename, Asm2VecPlus_128_vec_list])
                csvfile_writer_dict["Asm2VecPlus_256"].writerow([filename, Asm2VecPlus_256_vec_list])
                break
            elif "Asm2VecBase_8" == representation_method:
                Asm2VecBase_8_vec_list, Asm2VecBase_16_vec_list, Asm2VecBase_32_vec_list, \
                Asm2VecBase_64_vec_list, Asm2VecBase_128_vec_list, Asm2VecBase_256_vec_list \
                            = Asm2VecBase_get_basicblock_seq_vec_list(byte_sequences,
                                                                  representation_method=representation_method)
                csvfile_writer_dict["Asm2VecBase_8"].writerow([filename, Asm2VecBase_8_vec_list])
                csvfile_writer_dict["Asm2VecBase_16"].writerow([filename, Asm2VecBase_16_vec_list])
                csvfile_writer_dict["Asm2VecBase_32"].writerow([filename, Asm2VecBase_32_vec_list])
                csvfile_writer_dict["Asm2VecBase_64"].writerow([filename, Asm2VecBase_64_vec_list])
                csvfile_writer_dict["Asm2VecBase_128"].writerow([filename, Asm2VecBase_128_vec_list])
                csvfile_writer_dict["Asm2VecBase_256"].writerow([filename, Asm2VecBase_256_vec_list])
                break
            elif  "Magic" == representation_method:
                a = get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method,offspring=offsprings,instructions_in_vertex=instructions_in_vertex)
                csvfile_writer_dict[representation_method].writerow([filename, str(a).replace(" ", "")])
            else:
                a=get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method)
                csvfile_writer_dict[representation_method].writerow([filename, str(a).replace(" ","")])


    close_csv(representation_methods,csvfile_dict)



def process_byte_sequence(args):
    idx,filename, byte_sequences,Basicblock_Instructions_Counts,offspring_counts,instructions_in_vertex,representation_methods = args
    results = {}
    for representation_method in representation_methods:
        if "Asm2VecPlus_8" == representation_method:
            Asm2VecPlus_8_vec_list, Asm2VecPlus_16_vec_list, Asm2VecPlus_32_vec_list, Asm2VecPlus_64_vec_list, \
            Asm2VecPlus_128_vec_list, Asm2VecPlus_256_vec_list = Asm2VecPlus_get_basicblock_seq_vec_list(byte_sequences,
                                                                                                         representation_method=representation_method)
            results["Asm2VecPlus_8"] = Asm2VecPlus_8_vec_list
            results["Asm2VecPlus_16"] = Asm2VecPlus_16_vec_list
            results["Asm2VecPlus_32"] = Asm2VecPlus_32_vec_list
            results["Asm2VecPlus_64"] = Asm2VecPlus_64_vec_list
            results["Asm2VecPlus_128"] = Asm2VecPlus_128_vec_list
            results["Asm2VecPlus_256"] = Asm2VecPlus_256_vec_list
            break
        elif "Asm2VecBase_8" == representation_method:
            Asm2VecBase_8_vec_list, Asm2VecBase_16_vec_list, Asm2VecBase_32_vec_list, \
            Asm2VecBase_64_vec_list, Asm2VecBase_128_vec_list, Asm2VecBase_256_vec_list \
                = Asm2VecBase_get_basicblock_seq_vec_list(byte_sequences,
                                                          representation_method=representation_method)
            results["Asm2VecBase_8"] = Asm2VecBase_8_vec_list
            results["Asm2VecBase_16"] = Asm2VecBase_16_vec_list
            results["Asm2VecBase_32"] = Asm2VecBase_32_vec_list
            results["Asm2VecBase_64"] = Asm2VecBase_64_vec_list
            results["Asm2VecBase_128"] = Asm2VecBase_128_vec_list
            results["Asm2VecBase_256"] = Asm2VecBase_256_vec_list
            break
        elif "Magic" == representation_method:

            a = get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method,offspring=offspring_counts, instructions_in_vertex=instructions_in_vertex)
            results[representation_method] = str(a).replace(" ","")

        else:
            a = get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method)
            results[representation_method] = str(a).replace(" ","")

    return idx,filename, results

def process_byte_sequence1(args):
    idx,filename, byte_sequences,Basicblock_Instructions_Counts,offspring_counts,instructions_in_vertex,representation_methods = args
    results = {}
    for representation_method in representation_methods:
        # if "Asm2VecPlus_8" == representation_method:
        #     a=Asm2VecPlus_get_basicblock_seq_vec_list_8(byte_sequences,
        #                                                   representation_method=representation_method)
        #
        #     results[representation_method] = str(a).replace(" ", "")
        # elif "Asm2VecPlus_16" == representation_method:
        #     a = Asm2VecPlus_get_basicblock_seq_vec_list_16(byte_sequences,
        #                                                  representation_method=representation_method)
        #
        #     results[representation_method] = str(a).replace(" ", "")
        # elif "Asm2VecPlus_32" == representation_method:
        #     a = Asm2VecPlus_get_basicblock_seq_vec_list_32(byte_sequences,
        #                                                  representation_method=representation_method)
        #
        #     results[representation_method] = str(a).replace(" ", "")
        # elif "Asm2VecPlus_64" == representation_method:
        #     a = Asm2VecPlus_get_basicblock_seq_vec_list_64(byte_sequences,
        #                                                  representation_method=representation_method)
        #
        #     results[representation_method] = str(a).replace(" ", "")
        # elif "Asm2VecPlus_128" == representation_method:
        #     a = Asm2VecPlus_get_basicblock_seq_vec_list_128(byte_sequences,
        #                                                  representation_method=representation_method)
        #
        #     results[representation_method] = str(a).replace(" ", "")
        # elif "Asm2VecPlus_256" == representation_method:
        #     a = Asm2VecPlus_get_basicblock_seq_vec_list_256(byte_sequences,
        #                                                  representation_method=representation_method)
        #
        #     results[representation_method] = str(a).replace(" ", "")
        if "Asm2VecBase_8" == representation_method:
            Asm2VecBase_8_vec_list, Asm2VecBase_16_vec_list, Asm2VecBase_32_vec_list, \
            Asm2VecBase_64_vec_list, Asm2VecBase_128_vec_list, Asm2VecBase_256_vec_list \
                = Asm2VecBase_get_basicblock_seq_vec_list(byte_sequences,
                                                          representation_method=representation_method)
            results["Asm2VecBase_8"] = Asm2VecBase_8_vec_list
            results["Asm2VecBase_16"] = Asm2VecBase_16_vec_list
            results["Asm2VecBase_32"] = Asm2VecBase_32_vec_list
            results["Asm2VecBase_64"] = Asm2VecBase_64_vec_list
            results["Asm2VecBase_128"] = Asm2VecBase_128_vec_list
            results["Asm2VecBase_256"] = Asm2VecBase_256_vec_list
            break
        elif "Magic" == representation_method:
            a = get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method,offspring=offspring_counts, instructions_in_vertex=instructions_in_vertex)
            results[representation_method] = str(a).replace(" ","")
        else:
            a = get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method)
            results[representation_method] = str(a).replace(" ","")
            # del a
        # elif "init_vector_374"==representation_method:
        #     a=init_vector_374_get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method)
        #     results[representation_method] = str(a).replace(" ", "")

    return idx,filename, results

def featured_cfg_mp(mulu,representation_methods=["malconv","n_gram_1","n_gram_2","n_gram_3"]):
    csvfile_dict,csvfile_writer_dict=make_csv(mulu,representation_methods)
    File_names,CFG_Basicblock_Byte_Sequence_list,Basicblock_Instructions_Counts_list,offspring_counts_list,instructions_in_vertex_list= load_CFG_Basicblock_Byte_Sequence_list(mulu)

    # 创建进程池
    tasks = [(i , File_names[i], byte_sequences, Basicblock_Instructions_Counts_list[i],offspring_counts_list[i],instructions_in_vertex_list[i], representation_methods) for i, byte_sequences in enumerate(CFG_Basicblock_Byte_Sequence_list)]

    with mp.Pool(processes=6) as pool:
        # 使用imap_unordered获取结果并更新进度条
        for idx,filename, result_dict in tqdm(pool.imap(process_byte_sequence1, tasks), total=len(tasks)):
            # 在主进程中写入文件
            for representation_method, result in result_dict.items():
                csvfile_writer_dict[representation_method].writerow([idx,filename, result])
    close_csv(representation_methods, csvfile_dict)


def get_sample_list_from_csv(csv_save_path="../data/malware_msg_last.csv"):
    file_list = []
    with open(csv_save_path, 'r', encoding='utf-8') as f:
        # 经下述操作后，reader成为了一个可以迭代行的文件
        reader = csv.reader(f)
        # 先拿出csv文件的首行（一般是基本名称说明的行），此时指针指向下一行
        header = next(reader)
        for row in reader:
            file_name = row[0]
            file_list.append(file_name)
    return file_list

if __name__ == '__main__':
    pass
    # Micosoft样本--------------------
    # 良性软件
    # folder_path = r'\\ZJNU-NSR\Benign\benign_last1'  # 替换为您的文件夹路径
    # output_csv_path = r"\\ZJNU-NSR\Malware\Microsoft\CFG_benign\edges.csv"
    # begnin_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"C:\Users\Administrator\Desktop\Asm2VecPlus修改稿\代码\CFG特征赋予\benign_msg_last.csv"))
    # for i in range(len(begnin_shaixuan_list)):
    #     begnin_shaixuan_list[i]=begnin_shaixuan_list[i].replace(".gexf","")
    # get_edges_msg_mp(folder_path,begnin_shaixuan_list,output_csv_path)
    # mulu=r"\\ZJNU-NSR\Malware\Microsoft\CFG_benign"


    # 恶意软件
    # folder_path = r'\\ZJNU-NSR\Malware\Microsoft\train_exe'  # 替换为您的文件夹路径
    # output_csv_path = r"\\ZJNU-NSR\Malware\Microsoft\CFG_malware\edges.csv"
    # malware_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"C:\Users\Administrator\Desktop\Asm2VecPlus修改稿\代码\CFG特征赋予\malware_msg_last.csv"))
    # get_edges_msg_mp(folder_path,malware_shaixuan_list,output_csv_path)
    # mulu=r"\\ZJNU-NSR\Malware\Microsoft\CFG_malware"




    # SOREL-20M样本----------------------
    # 良性软件
    # folder_path = r'\\ZJNU-NSR\Benign\benign_all'  # 替换为您的文件夹路径
    # output_csv_path = r"\\ZJNU-NSR\Malware\SOREL-20M\CFG_benign\edges.csv"
    # begnin_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"\\ZJNU-NSR\Malware\SOREL-20M\benign_msg - 副本.csv"))
    # get_edges_msg_mp(folder_path,begnin_shaixuan_list,output_csv_path)
    # mulu=r"\\ZJNU-NSR\Malware\SOREL-20M\CFG_benign"

    # 恶意软件
    # folder_path = r'\\ZJNU-NSR\Malware\SOREL-20M\armed'  # 替换为您的文件夹路径
    # output_csv_path = r"\\ZJNU-NSR\Malware\SOREL-20M\CFG_malware\edges.csv"
    # malware_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"\\ZJNU-NSR\Malware\SOREL-20M\CFG_malware\cleaned_file.csv"))
    # get_edges_msg_mp(folder_path,malware_shaixuan_list,output_csv_path)
    mulu=r"\\ZJNU-NSR\Malware\SOREL-20M\CFG_malware"
    # mulu=r"\\ZJNU-NSR\Malware\SOREL-20M\CFG_malware"
    # featured_cfg_mp(mulu, ["L_LSTM_MGNE_16"])
    featured_cfg_mp(mulu, ["L_LSTM_MGNE_8"])
    # featured_cfg_mp(mulu, ["Asm2VecBase_8","Asm2VecBase_16","Asm2VecBase_32","Asm2VecBase_64","Asm2VecBase_128","Asm2VecBase_256"])

    # BODMAS样本----------------------
    # 良性软件
    # folder_path = r'\\ZJNU-NSR\Benign\benign_all'  # 替换为您的文件夹路径
    # output_csv_path = r"\\ZJNU-NSR\Malware\SOREL-20M\CFG_benign\edges.csv"
    # begnin_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"\\ZJNU-NSR\Malware\SOREL-20M\benign_msg - 副本.csv"))
    # get_edges_msg_mp(folder_path,begnin_shaixuan_list,output_csv_path)
    mulu=r"\\ZJNU-NSR\Malware\SOREL-20M\CFG_benign"
    # featured_cfg_mp(mulu, ["L_LSTM_MGNE_16"])
    featured_cfg_mp(mulu, ["L_LSTM_MGNE_8"])
    # featured_cfg_mp(mulu, ["Asm2VecBase_8","Asm2VecBase_16","Asm2VecBase_32","Asm2VecBase_64","Asm2VecBase_128","Asm2VecBase_256"])
    # 恶意软件
    # folder_path = r'\\ZJNU-NSR\Malware\BODMAS\armed'  # 替换为您的文件夹路径
    # output_csv_path = r"\\ZJNU-NSR\Malware\BODMAS\CFG_malware\edges.csv"
    # malware_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"\\ZJNU-NSR\Malware\BODMAS\cleaned_file.csv"))
    # get_edges_msg(folder_path,malware_shaixuan_list,output_csv_path)
    mulu=r"\\ZJNU-NSR\Malware\BODMAS\CFG_malware"
    # featured_cfg_mp(mulu, ["L_LSTM_MGNE_16"])
    featured_cfg_mp(mulu, ["L_LSTM_MGNE_8"])
    # featured_cfg_mp(mulu, ["Asm2VecBase_8","Asm2VecBase_16","Asm2VecBase_32","Asm2VecBase_64","Asm2VecBase_128","Asm2VecBase_256"])


    # featured_cfg_mp(mulu, ["malconv","n_gram_1","n_gram_2","n_gram_3","Magic"])



    # featured_cfg_mp(mulu, ["init_vecotr_374","malconv","n_gram_1","n_gram_2","n_gram_3","Magic"])
    # featured_cfg_mp(mulu, ["Asm2VecBase_8","Asm2VecBase_16","Asm2VecBase_32","Asm2VecBase_64","Asm2VecBase_128","Asm2VecBase_256"])
    # featured_cfg_mp(mulu, ["LSTM_MGNE_8","LSTM_MGNE_16","LSTM_MGNE_32","LSTM_MGNE_64","LSTM_MGNE_128","LSTM_MGNE_256"])
    # featured_cfg_mp(mulu, ["LSTM_MGNE_8"])