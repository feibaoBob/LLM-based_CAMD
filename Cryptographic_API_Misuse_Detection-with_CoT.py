import os
import csv
import re
import time
import requests
import rule_source as ru
import argparse
from pathlib import Path
from tqdm import tqdm
import random


def find_java_files(folder_path: str) -> list:
    java_files = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".java"):
                java_files.append(Path(root) / file)
    return java_files


def find_py_files(folder_path: str) -> list:
    py_files = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".py"):
                py_files.append(Path(root) / file)
    return py_files


def load_security_rules(code_type: str = None) -> (dict, dict):
    """Load rule_groups from rule_source.py"""
    try:
        if code_type == 'java':
            return ru.rule_groups_java
        elif code_type == 'py':
            return ru.rule_groups
    except ImportError:
        raise RuntimeError("Cannot Load rule_groups!")


def read_code_file(file_path: str) -> str:
    try:
        path = Path(file_path)
        if not path.is_file():
            raise ValueError("Path is not files")
        if path.suffix not in ['.py', '.java']:
            raise ValueError("Only support .py and .java files")

        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        numbered_lines = [f"{i + 1}: {line}" for i, line in enumerate(lines)]
        content = ''.join(numbered_lines)

        return content

    except Exception as e:
        raise RuntimeError(f"Fail read files: {str(e)}")


def prepare_prompt(source_code: str, rule_groups: dict) -> str:
    rule_descriptions = []
    for i, rules in rule_groups.items():
        group_id, group_info = i, rules
        rule_desc = (f"Rule ID: {group_id}\n"
            f"Rule Name: {group_info.get('name', 'UNKNOW')} \n"
            f"Rule description: {group_info.get('Message', 'UNKNOW')} \n"
            "------"
        )
        rule_descriptions.append(rule_desc)
    rules_str = "\n".join(rule_descriptions)
    instruction = f"""
[Misuse Rule List]
{rules_str}

[Source Code]
{source_code}

[Detection Steps]
[1] Line-by-line analyze code:
Analyze the code line by line, ensuring correctly understanding of the function of each line and the variable and parameter passing between lines; Differentiating between 'module import code' and 'body code'.
[2] Must Exclude the unused module import code:
Confirm the import modules be used in body code; Must Exclude them if unused right now without speculate. If there is no body code, directly Skip to step [5].
[3] Locate body code lines related to [Misuse Rule List]:
Locate body code lines related to [Misuse Rule List], and determine the body code executed condition during runtime; Must Exclude them if unexecuted right now without speculate.
[4] Trace each used parameter related to [Misuse Rule List]:
Understanding the code through step [1], [2] and [3], Trace each used parameter related to [Misuse Rule List] origins (keys/salts/iterations/regex).
[5] Draw a judgment conclusion:
Based on the above analysis steps, draw a judgment conclusion of actual execution body code against the [Misuse Rule List]. If there is no body code, judge as no misuse.
[6] Output Detection Result:
Output the Detection Result of step [5] according to the requirements and format.

### Task Requirements
As a professional Python programmer, strictly execute the [Detection Steps] sequentially to analyze the [Source Code] for Cryptographic API Misuse Detection. 

### Detection Result Output Requirements:
1. Strictly executed all [Detection Steps] at first, Output the Detection Result later.
2. Separate misuse line numbers with commas ','.
3. If multiple rules are violated, merge into a single entry.
4. Separate field values with '|'; for the same rule, keep line numbers comma-separated.
5. Strictly maintain field order and format (retain titles before ':').

### Detection Result Output Format:
Line Numbers: (same-rule lines comma-separated, different rules separated by '|', e.g., 1,3|2,5. If the detection result is no misused, set it to None.)
Rule IDs: (multiple numbers separated by '|'. If the detection result is no misused, set it to -1.)
Rule Names: (multiple names separated by '|'. If the detection result is no misused, set it to UNKNOWN.)
Misused Modules: (multiple modules separated by '|'. If the detection result is no misused, set it to None.)
Misused path:
    """
    return instruction


def parse_analysis_result(text: str, file_path: str) -> dict:
    result = {
        "File Path": '',
        "Line Numbers": '',
        "Rule IDs": '',
        "Rule Names": '',
        "Misused Modules": ''
    }
    result["File Path"] = file_path
    patterns = [
        r'Line Numbers[：:]\s*([^.\n]+?)\s*\n',
        r'Rule IDs[：:]\s*([\d\s,\|\-]+)\n',
        r'Rule Names[：:]\s*([^.\n]+?)\s*\n',
        r'Misused Modules[：:]\s*([^.\n]+?)\s*\n'
    ]

    match1 = re.search(patterns[0], text)
    if match1:
        result['Line Numbers'] = match1.group(1)
    match2 = re.search(patterns[1], text)
    if match2:
        result['Rule IDs'] = match2.group(1)
    match3 = re.search(patterns[2], text)
    if match3:
        result['Rule Names'] = match3.group(1)
    match4 = re.search(patterns[3], text)
    if match4:
        result['Misused Modules'] = match4.group(1)

    return result


def analyze_with_llm(prompt: str, model_name: str, API_Key: str, timeout: int = 120):
    """
    Use LLMs by API
    Suggest LLMs：
    SiliconFlow：THUDM/GLM-4-32B-0414、moonshotai/Kimi-K2-Instruct
    OpenAI：GPT4.1、GPT4
    """

    endpoint = "https://api.siliconflow.cn/v1/chat/completions"  # siliconflow request adress
    # endpoint = "http://localhost:11434/api/generate"  # siliconflow request adress
    # endpoint = " https://api.apiyi.com/v1/chat/completions"  # OpenAI request adress
    # endpoint = "https://api.openai.com/v1/chat/completions"  # OpenAI request adress
    headers = {
        "Authorization": f"Bearer {API_Key}",  # Please fill in your own SiliconFlow API key.
        # "Authorization": f"Bearer {'Your—API-Key'}",  # Please fill in your own OpenAI API key.
        "Content-Type": "application/json"
    }
    payload = {
        "model": model_name,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0
    }

    max_retries = 5
    base_delay = 1
    retry_count = 0

    while retry_count <= max_retries:
        try:
            response = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=timeout
            )
            response.raise_for_status()
            result = response.json()['choices'][0]['message']

            content_str = result.get('content', '')
            if '```json' in content_str:
                json_part = content_str.split('```json')[1].split('```')[0].strip()
                cleaned_json = json_part.replace('"', '').replace('{', '').replace('}', '').replace('*', '').replace('#', '')
            else:
                cleaned_json = content_str.replace('"', '').replace('{', '').replace('}', '').replace('*', '').replace('#', '')

            final_output = cleaned_json
            return final_output

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                retry_count += 1
                retry_after = e.response.headers.get('Retry-After')
                if retry_after and retry_after.isdigit():
                    wait_time = int(retry_after)
                else:
                    wait_time = (2 ** retry_count) * base_delay + random.uniform(0, 0.5)
                print(f"⚠️ Triggle speed limit(429), {retry_count}/{max_retries} times retry，waiting {wait_time:.2f} seconds...")
                time.sleep(wait_time)
                if retry_count > max_retries:
                    raise RuntimeError(f"API error: retry invalid")
                print(f"⚠️ Triggle speed limit(429),  {retry_count}/{max_retries} times retry，waiting {wait_time:.2f} seconds...")
                time.sleep(wait_time)

            else:
                error_msg = f"HTTP error {e.response.status_code}"
                if e.response.status_code == 401:
                    error_msg += " | API Key invalid"
                raise RuntimeError(f"API error: {error_msg}")

        except Exception as e:
            raise RuntimeError(f"Fail use LLMs: {str(e)}")


def analyze_with_ollama(prompt: str, model_name: str, timeout: int = 200):
    """
    调用本地Ollama大模型（修复流式响应处理）
    """
    endpoint = "http://localhost:11434/api/generate"

    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0,
            "num_predict": 2000
        }
    }

    try:
        # 添加stream=True参数以处理流式响应
        response = requests.post(
            endpoint,
            json=payload,
            stream=False,
            timeout=timeout
        )
        data = response.json()
        content_str = data["response"].strip()
        if '```json' in content_str:
            # 提取JSON部分并移除标记
            json_part = content_str.split('```json')[1].split('```')[0].strip()

            # 去除所有双引号、大括号和逗号
            cleaned_json = json_part.replace('"', '').replace('{', '').replace('}', '').replace('*', '').replace('#', '')
        else:
            # 直接处理非JSON格式内容
            cleaned_json = content_str.replace('"', '').replace('{', '').replace('}', '').replace('*', '').replace('#', '')
        return cleaned_json

    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Ollama API调用失败: {str(e)}")
    except Exception as e:
        raise RuntimeError(f"处理响应时发生错误: {str(e)}")


def process_single_file(file_path: Path, rule_groups: dict, model_name: str, API_Key:str) -> dict:
# def process_single_file(file_path: Path, rule_groups: dict, model_name: str) -> dict:
    """process single files and return a dict result"""
    try:
        code_content = read_code_file(str(file_path))
        prompt = prepare_prompt(code_content, rule_groups)
        # raw_result = analyze_with_ollama(prompt, model_name)
        raw_result = analyze_with_llm(prompt, model_name, API_Key)
        result = parse_analysis_result(raw_result, str(file_path))
        result["Time_Taken/s"] = '0.01'
        return result
    except Exception as e:
        return {
        "File Path": 'miss',
        "Line Numbers": 'miss',
        "Rule IDs": 'miss',
        "Rule Names": 'miss',
        "Misused Modules": str(e),
        "Time_Taken/s": '0.01'
    }


def save_to_csv(results: list[dict], output_path: str):
    """save structure result to CSV"""
    fieldnames = ["File Path", "Line Numbers", "Rule IDs", "Rule Names", "Misused Modules", "Time_Taken/s"]

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def batch_analyze(folder_path: str, codetype: str, model_name: str, API_Key: str, i):
# def batch_analyze(folder_path: str, codetype: str, model_name: str, i):
    try:
        rule_groups = load_security_rules(codetype)
    except Exception as e:
        raise RuntimeError(f"fail load rule_groups: {str(e)}")

    if codetype == 'java':
        java_files = find_java_files(folder_path)
        if not java_files:
            raise ValueError("No Found .java files")
        code_files = java_files
    elif codetype == 'py':
        py_files = find_py_files(folder_path)
        if not py_files:
            raise ValueError("No Found .py files")
        code_files = py_files
    else:
        print("Please enter a valid folder path.")
    results = []
    progress_bar = tqdm(code_files, desc="analyze progress", unit="file")
    for file_path in progress_bar:
        start_time = time.time()
        progress_bar.set_postfix({"current file": file_path.name})
        try:
            file_results = process_single_file(
                file_path=file_path,
                rule_groups=rule_groups,
                model_name=model_name,
                API_Key=API_Key
            )
            elapsed = round(time.time() - start_time, 2)
            file_results["Time_Taken/s"] = f"{elapsed}"
        except Exception as e:
            elapsed = round(time.time() - start_time, 2)
            error_result = {
                    "File Path": 'miss',
                    "Line Numbers": 'miss',
                    "Rule IDs": 'miss',
                    "Rule Names": 'miss',
                    "Misused Modules": str(e),
                    "Time_Taken/s": f"{elapsed}"
                }
            file_results = error_result
        results.append(file_results)
    # Save result to CSV
    output_csv = Path(folder_path) / f"analysis_result_by_{model_name.replace('/', '_')}-CoT-{i}-3.csv"
    save_to_csv(results, str(output_csv))
    print(f"\n Analysis cycle {i} has been completed！Results save to：{output_csv} \n\n")


if __name__ == "__main__":
    model_name = 'moonshotai/Kimi-K2-Instruct'
    # model_name = 'deepseek-ai/DeepSeek-V3'
    API_Key = 'sk-juexxxx'  # Please fill in your own SiliconFlow API key.
    # file_path = './py_full_unsafe/rule_08_Global_1.py'
    # file_path = './py_full_unsafe/rule_09_Path-Sensitive_0.py'
    file_path = './pysafe_trapfile/Trap_Import_Path-Sensitive_md5_rule_11_trapfile_9.py'
    # file_path = './pysafe_trapfile/Trap_Import_Field-Sensitive_pyDes_rule_09_trapfile_5.py'

    rule_groups = load_security_rules('py')
    code_content = read_code_file(str(file_path))
    prompt = prepare_prompt(code_content, rule_groups)  # 传入rule_groups
    print(prompt)
    start_time = time.perf_counter()
    raw_result = analyze_with_llm(prompt, model_name, API_Key)
    print("*" * 10)
    print(raw_result)
    print(type(raw_result))

    fd = parse_analysis_result(raw_result, file_path)
    print(fd)

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time

    # 转换为分和秒
    minutes = int(elapsed_time // 60)
    seconds = elapsed_time % 60

    if minutes > 0:
        print(f"检测耗时: {minutes}分{seconds:.2f}秒")
    else:
        print(f"检测耗时: {seconds:.2f}秒")



