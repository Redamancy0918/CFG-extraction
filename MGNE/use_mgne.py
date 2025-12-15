import torch
from .model import MalwareDetectionModel_NodeSequence
from .asm2vec_plus_util import str_hex_to_bytes,get_asm_input_vector
import sys
sys.path.append(r"./Asm2vecPlus")
from Asm2vecPlus.init_vector_generation import get_seq_encoder1
from torch.nn.utils.rnn import pad_sequence
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


gnn_name="GCN"
input_dim=374
hidden_dim=8
gnn_out_feats=16
num_layers=2
LSTM_model_8 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
# BERT_model_8 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
LSTM_model_8.load_state_dict(torch.load('./MGNE/checkpoints/LSTM_8_GCN_init_vector_374_training_log_node_seq_start_checkpoints_100.pt'))
# BERT_model_8.load_state_dict(torch.load('./MGNE/374 GCN_init_vector_training_node_seq_start_checkpoints_50.pt'))
#
hidden_dim=16
LSTM_model_16 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
# BERT_model_16 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
LSTM_model_16.load_state_dict(torch.load('./MGNE/checkpoints/LSTM_16_GCN_init_vector_374_training_log_node_seq_start_checkpoints_100.pt'))
# BERT_model_16.load_state_dict(torch.load('./MGNE/374 GCN_init_vector_training_node_seq_start_checkpoints_50.pt'))
#
hidden_dim=32
LSTM_model_32 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
# BERT_model_32 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
LSTM_model_32.load_state_dict(torch.load('./MGNE/checkpoints/LSTM_32_GCN_init_vector_374_training_log_node_seq_start_checkpoints_100.pt'))
# BERT_model_32.load_state_dict(torch.load('./MGNE/374 GCN_init_vector_training_node_seq_start_checkpoints_50.pt'))
#
hidden_dim=64
LSTM_model_64 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
# BERT_model_64 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
LSTM_model_64.load_state_dict(torch.load('./MGNE/checkpoints/LSTM_64_GCN_init_vector_374_training_log_node_seq_start_checkpoints_100.pt'))
# BERT_model_64.load_state_dict(torch.load('./MGNE/374 GCN_init_vector_training_node_seq_start_checkpoints_50.pt'))
#
hidden_dim=128
LSTM_model_128 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
# BERT_model_128 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
LSTM_model_128.load_state_dict(torch.load('./MGNE/checkpoints/LSTM_128_GCN_init_vector_374_training_log_node_seq_start_checkpoints_100.pt'))
# BERT_model_128.load_state_dict(torch.load('./MGNE/374 GCN_init_vector_training_node_seq_start_checkpoints_50.pt'))
#
#
hidden_dim=256
LSTM_model_256 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
# BERT_model_256 = MalwareDetectionModel_NodeSequence(gnn_name, input_dim, hidden_dim, gnn_out_feats, num_layers).to(device)
LSTM_model_256.load_state_dict(torch.load('./MGNE/checkpoints/LSTM_256_GCN_init_vector_374_training_log_node_seq_start_checkpoints_100.pt'))
# BERT_model_256.load_state_dict(torch.load('./MGNE/374 GCN_init_vector_training_node_seq_start_checkpoints_50.pt'))
#
#
LSTM_model_8.eval()
LSTM_model_16.eval()
LSTM_model_32.eval()
LSTM_model_64.eval()
LSTM_model_128.eval()
LSTM_model_256.eval()
# BERT_model_8.eval()
# BERT_model_16.eval()
# BERT_model_32.eval()
# BERT_model_64.eval()
# BERT_model_128.eval()
# BERT_model_256.eval()

def node_embedding():
    test=model.node_feature_model()


def MGNE_node_embedding(hex_asm=["56a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3","909090909090909056a194382b56508b35cc912b56ffd6ff3584382b56ffd6a174382b5650ffd65ec3"],dim="MGNE_8"):
    features=[]
    for hex_asm_item in hex_asm:
        if hex_asm_item=='':
            hex_asm_item="90"
        initial_vector =get_seq_encoder1(hex_asm_item)
        features.append(initial_vector)

    batch_lengths = [len(sublist if sublist else [0] * 374) for sublist in features ]
    # features = [torch.tensor(each_node, dtype=torch.float32) for each_node in features]
    features = [torch.tensor(each_node if each_node else [0] * 374, dtype=torch.float32) for each_node in features]
    batched_features = pad_sequence(features, batch_first=True, padding_value=0)
    # try:
    #     batched_features = pad_sequence(features, batch_first=True, padding_value=0)
    # except:
    #     print("----------------------------------")
    #     print(features)
    #     print(batch_lengths)
    #     batch_lengths = [len(item) for sublist in features for item in sublist]
    #     print(batch_lengths)
    #     print("----------------------------------")
        # batched_features = torch.tensor([[[0]*374]],dtype=torch.float32)
        # batch_lengths=[1]
    if dim=="LSTM_MGNE_8":
        embedding_func_vec_list = LSTM_model_8.node_feature_model(torch.tensor(batched_features).to(device), batch_lengths,seq_model="LSTM")
    elif dim=="LSTM_MGNE_16":
        embedding_func_vec_list = LSTM_model_16.node_feature_model(torch.tensor(batched_features).to(device), batch_lengths,seq_model="LSTM")
    elif dim=="LSTM_MGNE_32":
        embedding_func_vec_list = LSTM_model_32.node_feature_model(torch.tensor(batched_features).to(device), batch_lengths,seq_model="LSTM")
    elif dim == "LSTM_MGNE_64":
        embedding_func_vec_list = LSTM_model_64.node_feature_model(torch.tensor(batched_features).to(device), batch_lengths,seq_model="LSTM")
    elif dim=="LSTM_MGNE_128":
        embedding_func_vec_list = LSTM_model_128.node_feature_model(torch.tensor(batched_features).to(device), batch_lengths,seq_model="LSTM")
    elif dim=="LSTM_MGNE_256":
        embedding_func_vec_list = LSTM_model_256.node_feature_model(torch.tensor(batched_features).to(device), batch_lengths,seq_model="LSTM")


    elif dim=="L_LSTM_MGNE_8":
        # x, batch_lengths, seq_model
        embedding_func_vec_list1 = LSTM_model_8.node_feature_model.embedding(torch.tensor(batched_features).to(device))
        embedding_func_vec_list=[]
        for i in range(len(embedding_func_vec_list1)):
            embedding_func_vec_list.append(torch.mean(embedding_func_vec_list1[i], dim=0).tolist())

    elif dim=="L_LSTM_MGNE_16":
        embedding_func_vec_list1 = LSTM_model_16.node_feature_model.embedding(torch.tensor(batched_features).to(device))
        embedding_func_vec_list=[]
        for i in range(len(embedding_func_vec_list1)):
            embedding_func_vec_list.append(torch.sum(embedding_func_vec_list1[i], dim=0).tolist())

    elif dim=="L_LSTM_MGNE_256":
        embedding_func_vec_list2 = LSTM_model_256.node_feature_model(torch.tensor(batched_features).to(device), batch_lengths,seq_model="LSTM")
        embedding_func_vec_list1 = LSTM_model_256.node_feature_model.embedding(torch.tensor(batched_features).to(device))
        embedding_func_vec_list=[]
        for i in range(len(embedding_func_vec_list1)):
            embedding_func_vec_list.append(torch.mean(embedding_func_vec_list2[i],torch.mean(embedding_func_vec_list1[i], dim=0)).tolist())

    # elif dim=="L_LSTM_MGNE_256":
    #     embedding_func_vec_list1 = LSTM_model_256.node_feature_model.embedding(torch.tensor(batched_features).to(device))
    #     embedding_func_vec_list=[]
    #     for i in range(len(embedding_func_vec_list1)):
    #         embedding_func_vec_list.append(torch.sum(embedding_func_vec_list1[i], dim=0).tolist())

    elif dim == "BERT_MGNE_8":
        embedding_func_vec_list =BERT_model_8.node_feature_model(torch.tensor(batched_features).to(device),batch_lengths, seq_model="BERT")
    elif dim == "BERT_MGNE_16":
        embedding_func_vec_list = BERT_model_16.node_feature_model(torch.tensor(batched_features).to(device),batch_lengths, seq_model="BERT")
    elif dim == "BERT_MGNE_32":
        embedding_func_vec_list = BERT_model_32.node_feature_model(torch.tensor(batched_features).to(device),batch_lengths, seq_model="BERT")
    elif dim == "BERT_MGNE_64":
        embedding_func_vec_list = BERT_model_64.node_feature_model(torch.tensor(batched_features).to(device),batch_lengths, seq_model="BERT")
    elif dim == "BERT_MGNE_128":
        embedding_func_vec_list = BERT_model_128.node_feature_model(torch.tensor(batched_features).to(device), batch_lengths, seq_model="BERT")
    elif dim == "BERT_MGNE_256":
        embedding_func_vec_list = BERT_model_256.node_feature_model(torch.tensor(batched_features).to(device),batch_lengths, seq_model="BERT")



    rounded_list = []
    if type(embedding_func_vec_list)!=list:
        embedding_func_vec_list=embedding_func_vec_list.tolist()
    # for sublist in embedding_func_vec_list.tolist():
    for sublist in embedding_func_vec_list:
        rounded_sublist = [round(item, 4) for item in sublist]
        rounded_list.append(rounded_sublist)

    # print(rounded_list)
    return rounded_list

if __name__ == '__main__':
    print(MGNE_node_embedding())