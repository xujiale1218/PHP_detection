import os
import pickle
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
import re
import warnings
warnings.filterwarnings("ignore")

# ================== 配置 ==================
MODEL_SAVE_PATH = "./model/vul_final_model.pkl"

DANGER_FUNC = {"eval","system","exec","shell_exec","passthru","popen",
               "include","require","mysqli_query","mysql_query","echo","print","assert"}
USER_INPUT = {"$_get","$_post","$_request","$_cookie","$_server","$_files"}

# ================== 特征提取 ==================
def extract_features(code):
    c = str(code).lower()
    f = []
    f.append(len(c))
    f.append(c.count(";"))
    f.append(c.count("$"))
    f.append(c.count("("))
    f.append(c.count("."))

    has_danger = 0
    for d in DANGER_FUNC:
        if d + "(" in c:
            has_danger = 1
            break
    f.append(has_danger)

    has_input = 0
    for u in USER_INPUT:
        if u in c:
            has_input = 1
            break
    f.append(has_input)
    f.append(1 if (has_danger and has_input) else 0)
    f.append(1 if re.search(r'\$\w+\(', c) else 0)
    f.append(1 if re.search(r'select.*from.*\$_', c, re.DOTALL) else 0)
    return np.array(f, dtype=np.float32)

# ================== 构建数据集 ==================
def build_dataset():
    vul = []
    safe = []

    # 漏洞样本
    patterns = [
        "eval($_GET['cmd']);",
        "system($_POST['cmd']);",
        "exec($_REQUEST['a']);",
        "include($_GET['file']);",
        "mysqli_query($link,'SELECT * FROM user WHERE id='.$_GET['id']);",
        "echo $_GET['name'];",
        "$a='system';$a($_GET['cmd']);",
    ]
    for p in patterns:
        vul.extend([{"code": p, "label": 1}] * 150)

    # 安全样本
    safe_patterns = [
        "$a=1;", "echo 'hello';", "function test(){}",
        "include 'header.php';", "echo htmlspecialchars($_GET['a']);"
    ]
    for p in safe_patterns:
        safe.extend([{"code": p, "label": 0}] * 100)

    return pd.DataFrame(vul + safe)

# ================== 训练 ==================
def train():
    df = build_dataset()
    X = np.array([extract_features(c) for c in df["code"]])
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, eval_metric="logloss")
    model.fit(X_train, y_train)

    os.makedirs("./model", exist_ok=True)
    pickle.dump(model, open(MODEL_SAVE_PATH, "wb"))
    print("模型训练完成！已保存到：" + MODEL_SAVE_PATH)

if __name__ == "__main__":
    train()