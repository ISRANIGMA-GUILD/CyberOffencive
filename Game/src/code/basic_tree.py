from bigtree import dataframe_to_tree_by_relation
import pandas as pd


def main():
    relation_data = pd.DataFrame([
        ["a", None, 90],
        ["b", "a", 65],
        ["c", "a", None],
        ["d", "b", 40],
        ["e", "b", 35],
        ["f", "c", 38],
        ["g", "e", 10],
        ["h", "e", 6],
        ], columns=["child", "parent", "ip", "port"]
    )
    root = dataframe_to_tree_by_relation(relation_data)
    root.show(attr_list=["ip"])


if __name__ == '__main__':
    main()
