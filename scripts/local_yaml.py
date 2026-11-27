"""Safe YAML loading for committed transport and scenario fixtures."""

import yaml


class UniqueSafeLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        node = super().compose_node(parent, index)
        # These pair-list tags bypass construct_mapping, even as merge operands.
        if node is not None and node.tag in ("tag:yaml.org,2002:omap", "tag:yaml.org,2002:pairs"):
            self.construct_undefined(node)
        return node

    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError(f"non-string or duplicate YAML key: {key!r}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_yaml(data):
    return yaml.load(data, Loader=UniqueSafeLoader)
