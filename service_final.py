import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
import pickle
import re
import os

app = FastAPI(title="PHP漏洞检测系统")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = "./model/vul_final_model.pkl"

if not os.path.exists(MODEL_PATH):
    print("模型文件不存在，请先训练模型！")
    exit()

model = pickle.load(open(MODEL_PATH, "rb"))

def extract_features(code):
    c = str(code).lower()
    f = [len(c), c.count(";"), c.count("$"), c.count("("), c.count(".")]
    danger_list = ["eval", "system", "exec", "shell_exec", "passthru", "popen", "assert", "include", "require", "mysqli_query", "mysql_query"]
    has_danger = 1 if any(d + "(" in c for d in danger_list) else 0
    has_input = 1 if any(u in c for u in ["$_get", "$_post", "$_request"]) else 0
    f.append(has_danger)
    f.append(has_input)
    f.append(1 if (has_danger and has_input) else 0)
    f.append(1 if re.search(r'\$\w+\(.+\)', c) else 0)
    f.append(1 if re.search(r'select.+\$', c, re.I) else 0)
    return np.array(f, dtype=np.float32)

def split_code(code):
    code = re.sub(r'//.*', '', code)
    code = re.sub(r'/\*[\s\S]*?\*/', '', code)
    return [s.strip() for s in code.split(";") if len(s.strip()) > 3]

def detect(stmt):
    try:
        feat = extract_features(stmt).reshape(1, -1)
        pred = model.predict(feat)[0]
        is_vul = bool(int(pred))
        prob = round(float(model.predict_proba(feat)[0][1]), 3)
        typ = "安全"
        lc = stmt.lower()
        raw = stmt

        # ==================== 安全规则（修复误判）=====================
        # 1. die / exit 输出固定字符串 → 安全
        if re.search(r'die\s*\(\s*["\'][^"$]*["\']\s*\)', raw) or re.search(r'exit\s*\(\s*["\'][^"$]*["\']\s*\)', raw):
            is_vul = False
            typ = "安全"
            return {"statement": raw, "is_vulnerable": is_vul, "confidence": prob, "vuln_type": typ}

        # 2. CSRF 防护验证 → 安全
        if "hash_equals" in lc and "csrf_token" in lc:
            is_vul = False
            typ = "安全"
            return {"statement": raw, "is_vulnerable": is_vul, "confidence": prob, "vuln_type": typ}

        # 3. 使用 htmlspecialchars 转义 → 安全
        if "htmlspecialchars" in lc:
            is_vul = False
            typ = "安全"
            return {"statement": raw, "is_vulnerable": is_vul, "confidence": prob, "vuln_type": typ}

        # 4. 纯赋值语句 → 安全
        if re.fullmatch(r'\$\w+\s*=\s*[^;()]*', raw.strip()):
            is_vul = False
            typ = "安全"
            return {"statement": raw, "is_vulnerable": is_vul, "confidence": prob, "vuln_type": typ}

        # ==================== 漏洞检测规则 ====================
        if re.search(r'^\s*\$\w+\s*\(', raw):
            is_vul = True
            typ = "命令执行"
        elif any(d in lc for d in ["system(", "exec(", "shell_exec(", "passthru(", "popen(", "assert("]) and re.search(r'\$\w+', raw):
            is_vul = True
            typ = "命令执行"
        elif any(d in lc for d in ["include(", "require(", "include_once(", "require_once("]) and re.search(r'\$\w+', raw):
            is_vul = True
            typ = "文件包含"
        elif any(d in lc for d in ["mysqli_query(", "mysql_query("]) and re.search(r'\$\w+', raw):
            is_vul = True
            typ = "SQL注入"
        elif any(d in lc for d in ["echo ", "print ", "printf("]) and re.search(r'\$\w+', raw):
            is_vul = True
            typ = "XSS"
        elif "eval(" in lc and re.search(r'(\$_|\$)', raw):
            is_vul = True
            typ = "命令执行"
        elif is_vul:
            if any(x in lc for x in ["eval(", "system(", "exec(", "shell_exec(", "passthru(", "popen(", "assert("]):
                typ = "命令执行"
            elif any(x in lc for x in ["include(", "require(", "include_once(", "require_once("]):
                typ = "文件包含"
            elif any(x in lc for x in ["mysqli_query(", "mysql_query("]) or "select" in lc:
                typ = "SQL注入"
            elif any(x in lc for x in ["echo ", "print ", "printf("]):
                typ = "XSS"
            else:
                typ = "命令执行"
        else:
            typ = "安全"

        return {"statement": raw, "is_vulnerable": is_vul, "confidence": prob, "vuln_type": typ}
    except Exception:
        return {"statement": stmt, "is_vulnerable": False, "confidence": 0.0, "vuln_type": "安全"}

@app.post("/api/analyze")
async def api_analyze(data: dict):
    code = data.get("code", "")
    stmts = split_code(code)
    results = [detect(s) for s in stmts]
    total = len(results)
    vulnerable = sum(1 for r in results if r["is_vulnerable"])
    safe = total - vulnerable
    return {
        "status": "success",
        "total_statements": total,
        "vulnerable_statements": vulnerable,
        "safe_statements": safe,
        "results": results
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)