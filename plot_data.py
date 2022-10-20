#!/usr/bin/env python3
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Lint as: python3
"""Hacky script to read RTT output from crypto_bench and plot it."""

import matplotlib.pyplot as plt
import numpy as np


def read_file(filename):
  with open(filename, "r", encoding="utf-8") as f:
    lines = f.readlines()
    return [float(l[:-2]) for l in lines]


def below_threshold(data, threshold=10.):
  a = np.array(data)
  return np.mean(a / 1000. < threshold)


def percentiles(data):
  s = sorted(data)
  l = len(s)
  for i in range(10):
    print(f"{i * 10}th percentile: {s[(i * l) // 10]}")


def show_plot(data, title):
  threshold_ratio = below_threshold(data)
  if threshold_ratio < 0.9999:
    max_range = min(max(data), 2 * 10. * 1000)
    hist_range = (0, max_range)
  else:
    hist_range = None
  plt.hist(data, bins=50, range=hist_range, label="Timing distribution")
  mean = np.mean(data)
  plt.axvline(x=mean, color="g", label="Mean")
  if threshold_ratio < 0.9999:
    plt.axvline(x=10. * 1000, color="r", label="CTAP threshold")

  plt.title(title)
  plt.legend()
  plt.savefig(title.replace(" ", "") + "_plot.png")
  plt.show()


def run(filename, title):
  data = read_file(filename)
  print(title, "below 10s:", below_threshold(data))
  print("Mean:", np.mean(data))
  percentiles(data)
  show_plot(data, title)


run("make_durations.txt", "MakeCredential")
run("get_durations.txt", "GetAssertion")
