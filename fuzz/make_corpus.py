"""Creates a directory containing seed inputs from a json file having
   the following structure:
   [
     {
       "hex": "a901a1182a182a02a3626964781a6d616b655f6261645f7...",
       "cbor": "{1: h'42', 2: {\"id\": \"make.example.com\", ...",
       "description": "make credential parameters"
     },
     ...
   ]

  Usage:
    - pass the resulting corpus directory path as the first argument
    - pass the json file path to make the corpus from as the second argument
  Example:
    python make_corpus.py ./corpus ./corpus_file.json
"""
import argparse
import json
import os.path


# Creates a corpus directory to the given path from the given json file.
def make_corpus(corpus_dir, corpus_json):
  if not os.path.exists(corpus_dir):
    os.makedirs(corpus_dir)
  elif not os.path.isdir(corpus_dir):
    raise NotADirectoryError

  if os.path.isfile(corpus_json) and \
    os.path.splitext(corpus_json)[-1] == ".json":
    with open(corpus_json, encoding="utf-8") as corpus_file:
      corpus = json.load(corpus_file)
  else:
    raise TypeError

  for i, seed_file in enumerate(corpus):
    seed_file_name = "seed_file_" + str(i)
    raw_hex = seed_file["hex"].decode("hex")
    with open(os.path.join(corpus_dir, seed_file_name), "wb") as f:
      f.write(raw_hex)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      "corpus_directory", help="the resulting corpus directory path")
  parser.add_argument(
      "corpus_json", help="the json file path to make the corpus from")
  args = parser.parse_args()
  try:
    make_corpus(args.corpus_directory, args.corpus_json)
  except NotADirectoryError:
    print(args.corpus_directory, " is not a directory.\n")
  except TypeError:
    print(args.corpus_json, " must be a json file.\n")


if __name__ == "__main__":
  main()
