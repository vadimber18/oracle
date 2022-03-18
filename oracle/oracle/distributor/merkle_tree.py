import collections
from typing import Dict, List, Tuple, Union

from eth_typing import ChecksumAddress
from eth_typing.encoding import HexStr
from eth_utils.crypto import keccak
from web3 import Web3

from .types import Claim, Claims, Rewards

w3 = Web3()


class Node:
    """MerkleTree Node."""

    __slots__ = ("value", "pair", "parent")

    def __init__(self, value, pair=None, parent=None):
        self.value = value
        self.pair = pair
        self.parent = parent

    def __repr__(self):
        return f"Node {self.value}"


class MerkleTree:
    def __init__(self, elements: List[bytes]):
        self.leaves: Dict[bytes, Node] = dict()
        self.root = None
        self.fill_leaves(elements)
        self.fill_tree()

    def fill_leaves(self, elements: List[bytes]):
        prev: Union[Node, None] = None
        for element in sorted(set(elements)):
            node = Node(element)
            self.leaves[element] = node
            if prev:
                prev.pair = node
                node.pair = prev
                prev = None
            else:
                prev = node

    def fill_tree(self):
        current_level: List[Node] = list(self.leaves.values())

        level_length = len(current_level)
        while level_length > 1:
            next_level: List[Node] = []
            index = 0
            while index < level_length:
                node = current_level[index]
                if node.pair:
                    parent = Node(MerkleTree.combine_hash(node.value, node.pair.value))
                    node.pair.parent = parent
                    # increase index cause we already covered two nodes
                    index += 1
                else:
                    parent = Node(node.value)
                node.parent = parent
                # if prev node has no pair - update it
                if next_level and not next_level[-1].pair:
                    next_level[-1].pair = parent
                    parent.pair = next_level[-1]
                next_level.append(parent)
                index += 1
            current_level = next_level
            level_length = len(current_level)
        self.root = current_level[0]

    def get_proof(self, element: bytes) -> List[bytes]:
        node: Node = self.leaves.get(element)
        if not node:
            raise ValueError("No such element in Merkle Tree")
        proof: List[bytes] = []
        while node:
            if node.pair:
                proof.append(node.pair.value)
            node = node.parent
        return proof

    def get_hex_proof(self, element: bytes) -> List[HexStr]:
        return [w3.toHex(p) for p in self.get_proof(element)]

    @property
    def hex_root(self) -> HexStr:
        return w3.toHex(self.root.value)

    @staticmethod
    def combine_hash(first: bytes, second: bytes = None) -> bytes:
        if first and second:
            return keccak(primitive=b"".join(sorted([first, second])))
        return first or second


def get_merkle_node(
    index: int,
    tokens: List[ChecksumAddress],
    account: ChecksumAddress,
    values: List[int],
) -> bytes:
    """Generates node for merkle tree."""
    encoded_data: bytes = w3.codec.encode_abi(
        ["uint256", "address[]", "address", "uint256[]"],
        [index, tokens, account, values],
    )
    return w3.keccak(primitive=encoded_data)


def calculate_merkle_root(rewards: Rewards) -> Tuple[HexStr, Claims]:
    """Calculates merkle root and claims for the rewards."""
    merkle_elements: List[bytes] = []
    accounts: List[ChecksumAddress] = sorted(rewards)
    claims: Claims = dict()
    for index, account in enumerate(accounts):
        tokens: List[ChecksumAddress] = sorted(rewards[account].keys())
        claim: Claim = collections.OrderedDict(
            index=index, tokens=tokens, values=[rewards[account][t] for t in tokens]
        )
        claims[account] = claim

        merkle_element: bytes = get_merkle_node(
            index=index,
            account=account,
            tokens=tokens,
            values=[int(val) for val in claim["values"]],
        )
        merkle_elements.append(merkle_element)

    merkle_tree = MerkleTree(merkle_elements)

    # collect proofs
    for index, account in enumerate(accounts):
        proof: List[HexStr] = merkle_tree.get_hex_proof(merkle_elements[index])
        claims[account]["proof"] = proof

    # calculate merkle root
    merkle_root: HexStr = merkle_tree.hex_root

    return merkle_root, claims
