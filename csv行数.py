import pandas as pd

def count_csv_rows_pandas(filepath):
    df = pd.read_csv(filepath)
    return len(df)

print(count_csv_rows_pandas(r"\\ZJNU-NSR\Malware\Microsoft\CFG_benign\malconv.csv"))

print(count_csv_rows_pandas(r"\\ZJNU-NSR\Malware\Microsoft\CFG\edges2.csv"))
print(count_csv_rows_pandas(r"\\ZJNU-NSR\Malware\Microsoft\CFG\n_gram_1.csv"))
print(count_csv_rows_pandas(r"\\ZJNU-NSR\Malware\Microsoft\CFG\n_gram_2.csv"))
print(count_csv_rows_pandas(r"\\ZJNU-NSR\Malware\Microsoft\CFG\n_gram_3.csv"))
print(count_csv_rows_pandas(r"\\ZJNU-NSR\Malware\Microsoft\CFG\malconv.csv"))


# print(count_csv_rows_pandas(r"\\ZJNU-NSR\Malware\Microsoft\CFG\edges2.csv"))
# print(count_csv_rows_pandas(r"\\ZJNU-NSR\Malware\Microsoft\CFG\edges2.csv"))
# print(count_csv_rows_pandas(r"\\ZJNU-NSR\Malware\Microsoft\CFG\edges2.csv"))
# print(count_csv_rows_pandas(r"\\ZJNU-NSR\Malware\Microsoft\CFG\edges2.csv"))
