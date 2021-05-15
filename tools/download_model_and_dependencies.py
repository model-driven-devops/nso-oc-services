#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import os
import re

import requests


def get_downloaded_models(directory: str) -> list:
    return os.listdir(directory)


def download_model(url: str) -> str:
    result = requests.get(url)
    return result.text


def find_model_dependencies(file: str) -> list:
    text_list = file.split("\n")
    dependencies = list()
    for line in text_list:
        if "import" in line or "include" in line:
            line = line.strip()
            if not re.search("^//", line):
                if re.search(" \{.*\}", line):
                    line = re.sub(" \{.*\}", "", line)
                    line = line.replace("import ", "")
                    dependencies.append(f"{line}.yang")
                elif re.search("^include ", line):
                    line = re.sub("^include ", "", line)
                    line = line.replace(";", "")
                    dependencies.append(f"{line}.yang")
                    print(f"Sub-module {line}.yang")
    return dependencies


def main(root_model: str, repo_base_url: str, f_directory: str):
    todo = [root_model]
    finished = []
    models = get_downloaded_models(f_directory)
    finished.extend(models)
    if todo[-1] not in finished:
        flag = True
        while flag:
            if todo:
                model = todo[-1]
                if model not in finished:
                    model_file = download_model(f"{repo_base_url}/{model}")
                    with open(f"{f_directory}/{model}", "w") as m:
                        m.write(model_file)
                    model_dependencies = find_model_dependencies(model_file)
                    todo.remove(model)
                    finished.append(model)
                    for m in model_dependencies:
                        if m not in finished and m not in todo:
                            todo.append(m)
            else:
                flag = False


if __name__ == "__main__":
    """
    Example usage: 
    
    python download_model_and_dependencies.py \
    -u https://raw.githubusercontent.com/YangModels/yang/master/vendor/cisco/xe/1751 \
    -m openconfig-system.yang \
    -d ../models/system
    
    """

    parser = argparse.ArgumentParser(
        description='Identify and download specified model and all dependencies')
    parser.add_argument('--os_models_url', '-u',
                        action='store',
                        default='https://raw.githubusercontent.com/YangModels/yang/master/vendor/cisco/xe/1751',
                        help=('YangModels OS directory, e.g. https://raw.githubusercontent.com/YangModels/yang/master/vendor/cisco/xe/1751'))

    parser.add_argument('--model', '-m',
                        action='store',
                        default='openconfig-system.yang',
                        help=('Name of root model, e.g. openconfig-system.yang'))

    parser.add_argument('--download_directory', '-d',
                        action='store',
                        default='../models/system',
                        help=('Directory to receive downloaded models'))

    args = parser.parse_args()

    main(root_model=args.model, repo_base_url=args.os_models_url, f_directory=args.download_directory)

    files = get_downloaded_models(directory=args.download_directory)
    print(f"The following are needed for '{args.model}' and are located in the '{args.download_directory}' directory:")
    for i in files:
        print(f"-    {i}")
