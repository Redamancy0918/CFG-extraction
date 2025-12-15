import torch
from transformers import BertConfig, BertModel
from model import EmbeddingDecoder,load_model
import time

def get_instruction_embedding(bert_encoder, decoder, instruction_tensor):
    # Ensure that instruction_vector is a 2D tensor of shape (1, sequence_length)
    # instruction_tensor = torch.tensor([instruction_vector])  # shape will be (1, vector_size)
    # instruction_tensor=instruction_tensor.to('cuda:0')
    # print(instruction_tensor)
    # exit()
    # The BERT encoder expects a 3D tensor for inputs_embeds, so reshape as needed
    # We are assuming that vector_size is the correct hidden_size for the BERT model
    instruction_tensor = instruction_tensor.unsqueeze(0)  # Adds the batch_size dimension

    with torch.no_grad():
        # try:
        encoded_states = bert_encoder(inputs_embeds=instruction_tensor)[0]
        # except:
        #     print(instruction_tensor)

        embedding = decoder(encoded_states)


    return embedding.squeeze(0)


def main():
    # 示例汇编指令向量
    vector_size = 374
    embedding_size = 4
    sample_instruction_vector = [0.5] * vector_size

    # 模型文件路径
    encoder_path = 'model_save/bert_encoder_epoch_1.pt'
    decoder_path = 'model_save/decoder_epoch_1.pt'

    # 加载模型
    bert_encoder, decoder = load_model(encoder_path, decoder_path, vector_size, embedding_size)

    # 获取汇编指令的嵌入向量
    embedding = get_instruction_embedding(bert_encoder, decoder, sample_instruction_vector)
    print("汇编指令的嵌入向量:", embedding[0])

device = 'cuda' if torch.cuda.is_available() else 'cpu'
vector_size = 374

# 模型文件路径
encoder_path = './Asm2vecPlus/model_save/1000000_8_bert_encoder_epoch_50.pt'
decoder_path = './Asm2vecPlus/model_save/1000000_8_decoder_epoch_50.pt'
embedding_size = 8

# 加载模型
bert_encoder_8, decoder_8 = load_model(encoder_path, decoder_path, vector_size, embedding_size)
bert_encoder_8, decoder_8 =bert_encoder_8.to(device), decoder_8.to(device)
# 模型文件路径
encoder_path = './Asm2vecPlus/model_save/1000000_16_bert_encoder_epoch_50.pt'
decoder_path = './Asm2vecPlus/model_save/1000000_16_decoder_epoch_50.pt'
embedding_size = 16
# 加载模型
bert_encoder_16, decoder_16 = load_model(encoder_path, decoder_path, vector_size, embedding_size)
bert_encoder_16, decoder_16 =bert_encoder_16.to(device), decoder_16.to(device)
# 模型文件路径
encoder_path = './Asm2vecPlus/model_save/1000000_32_bert_encoder_epoch_50.pt'
decoder_path = './Asm2vecPlus/model_save/1000000_32_decoder_epoch_50.pt'
embedding_size = 32

# 加载模型
bert_encoder_32, decoder_32 = load_model(encoder_path, decoder_path, vector_size, embedding_size)
bert_encoder_32, decoder_32 =bert_encoder_16.to(device), decoder_32.to(device)
# 模型文件路径
encoder_path = './Asm2vecPlus/model_save/1000000_64_bert_encoder_epoch_50.pt'
decoder_path = './Asm2vecPlus/model_save/1000000_64_decoder_epoch_50.pt'
embedding_size = 64

# 加载模型
bert_encoder_64, decoder_64 = load_model(encoder_path, decoder_path, vector_size, embedding_size)
bert_encoder_64, decoder_64 =bert_encoder_16.to(device), decoder_64.to(device)
# 模型文件路径
encoder_path = './Asm2vecPlus/model_save/1000000_128_bert_encoder_epoch_50.pt'
decoder_path = './Asm2vecPlus/model_save/1000000_128_decoder_epoch_50.pt'
embedding_size = 128
# 加载模型
bert_encoder_128, decoder_128 = load_model(encoder_path, decoder_path, vector_size, embedding_size)
bert_encoder_128, decoder_128 =bert_encoder_128.to(device), decoder_128.to(device)

# 模型文件路径
encoder_path = './Asm2vecPlus/model_save/1000000_256_bert_encoder_epoch_20.pt'
decoder_path = './Asm2vecPlus/model_save/1000000_256_decoder_epoch_20.pt'
embedding_size = 256
# 加载模型
# bert_encoder_256, decoder_256 = load_model(encoder_path, decoder_path, vector_size, embedding_size)
# bert_encoder_256, decoder_256 =bert_encoder_256.to(device), decoder_256.to(device)






def Asm2VecPlus_8(sample_instruction_vector):
    return get_instruction_embedding(bert_encoder_8, decoder_8, sample_instruction_vector)



def Asm2VecPlus_16(sample_instruction_vector):
    return get_instruction_embedding(bert_encoder_16, decoder_16, sample_instruction_vector)



def Asm2VecPlus_32(sample_instruction_vector):
    return get_instruction_embedding(bert_encoder_32, decoder_32, sample_instruction_vector)



def Asm2VecPlus_64(sample_instruction_vector):
    return get_instruction_embedding(bert_encoder_64, decoder_64, sample_instruction_vector)



def Asm2VecPlus_128(sample_instruction_vector):
    return get_instruction_embedding(bert_encoder_128, decoder_128, sample_instruction_vector)


def Asm2VecPlus_256(sample_instruction_vector):
    return get_instruction_embedding(bert_encoder_256, decoder_256, sample_instruction_vector)

from tqdm import tqdm
import torch
if __name__ == "__main__":
    # 示例汇编指令向量
    vector_size = 374

    sample_instruction_vector = [0.5] * vector_size

    sample_instruction_vector= torch.tensor([sample_instruction_vector,sample_instruction_vector,sample_instruction_vector,sample_instruction_vector,sample_instruction_vector,sample_instruction_vector,sample_instruction_vector,sample_instruction_vector,sample_instruction_vector,sample_instruction_vector]).to('cuda:0')
    # 开始计时
    start_time = time.time()
    for i in tqdm(range(10000)):
        Asm2VecPlus_8(sample_instruction_vector)
        Asm2VecPlus_16(sample_instruction_vector)
        Asm2VecPlus_64(sample_instruction_vector)
        Asm2VecPlus_128(sample_instruction_vector)
        Asm2VecPlus_256(sample_instruction_vector)
    # 结束计时

    # print(Asm2VecPlus_16(sample_instruction_vector))
    # print(Asm2VecPlus_32(sample_instruction_vector))
    # print(Asm2VecPlus_64(sample_instruction_vector))
    # print(Asm2VecPlus_128(sample_instruction_vector))
    # print(Asm2VecPlus_256(sample_instruction_vector))

    end_time = time.time()
    total_time = end_time - start_time
    print(f"程序运行耗时 {total_time} 秒。")



