import json
import sys
import os.path

"""
Creates a directory containing seed inputs from a json file.
Usage:
- pass the resulting corpus directory path as the first argument
- pass the json file path to make the corpus from as the second argument
"""
corpus_dir = sys.argv[1]
corpus_file_json = sys.argv[2]
if not os.path.exists(corpus_dir):
    os.makedirs(corpus_dir)

with open(corpus_file_json) as file:
    corpus = json.load(file)

for i, seed_file in enumerate(corpus):
    seed_file_name = "seed_file_" + str(i)
    bytes = seed_file['hex'].decode("hex")
    with open(os.path.join(corpus_dir, seed_file_name), 'wb') as f:
        f.write(bytes)
