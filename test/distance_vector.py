#!/usr/bin/env python3
import sys

class Graph:
    def __init__(self):
        self.adj_list = {}

    def add_edge(self, u, v, weight):
        self.adj_list.setdefault(u, {})
        self.adj_list.setdefault(v, {})
        self.adj_list[u][v] = weight
        self.adj_list[v][u] = weight

node_list = []
net = Graph()

# Read node names
line = sys.stdin.readline().strip()
while line != "START":
    node_list.append(line)
    net.adj_list[line] = {}
    line = sys.stdin.readline().strip()

# Read initial links
line = sys.stdin.readline().strip()
while line != "UPDATE":
    a, b, cost = line.split()
    net.add_edge(a, b, int(cost))
    line = sys.stdin.readline().strip()