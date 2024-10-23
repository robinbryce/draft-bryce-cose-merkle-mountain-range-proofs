from typing import List, Tuple
import hashlib


def add_leaf_hash(db, f: bytes) -> int:
    """Adds the leaf hash value f to the MMR.

    Interior nodes are appended by this algorithm as necessary to for a complete mmr.

    Args:
        db: an interface providing the required append and get methods.
            - append must return the index for the next item to be added, and make the
              value added available to subsequent get calls in the same invocation.
            - get must return the requested value or raise an exception.
        v (bytes): the leaf hash value entry to add
    Returns:
        (int): the mmr index where the the next leaf would placed on a subsequent call to addleafhash.
    """

    g = 0
    i = db.append(f)

    while index_height(i) > g:
        left = db.get(i - (2 << g))
        right = db.get(i - 1)

        i = db.append(hash_pospair64(i + 1, left, right))
        g += 1

    return i


def inclusion_proof_path(i, c):
    """Returns the list of node indices proving inclusion of i

    Args:
        i (int): The index of the node to whose inclusion path is required.
        c (int): The index of the last node of any complete MMR that contains i.

    Note that where i < c0; c0 < c1; the following hold

        path_c0 = inclusion_proof_path(i, c0)
        path_c1 = inclusion_proof_path(parent(path[c][-1]), c1)
        path = inclusion_proof_path(i, c1) == path_c0 + path_c1

    Returns
        The inclusion path of i with respect to c

    """

    # set the path to the empty list
    path = []

    # Set `g` to `index_height(i)`
    g = index_height(i)

    # Repeat until #termination_condition evaluates true
    while True:

        # Set `siblingoffset` to 2^(g+1)
        siblingoffset = (2 << g)

        # If `index_height(i+1)` is greater than `g`
        if index_height(i+1) > g:

            # Set isibling to `i - siblingoffset + 1`. because i is the right
            # sibling, its witness is the left which is offset behind.
            isibling = i - siblingoffset + 1

            # Set `i` to `i+1`. the parent of a right sibling is always
            # stored immediately after.
            i += 1
        else:

            # Set isibling to `i + siblingoffset - 1`. because i is the left
            # sibling, its witness is the right and is offset ahead.
            isibling = i + siblingoffset - 1

            # Set `i` to `i+siblingoffset`. the parent of a left sibling is
            # stored at 1 position ahead of the right sibling.
            i += siblingoffset

        # If `isibling` is greater than `ix`, return the collected path. this is
        # the #termination_condition
        if isibling > c:
            return path

        # Append isibling to the proof.
        path.append(isibling)
        # Increment the height index `g`.
        g += 1


def included_root(
    i: int, nodehash: bytes, proof: List[bytes]
) -> bytes:
    """Apply the proof to nodehash to produce the implied root

    For a valid cose receipt of inclusion, using the returned root as the
    detached payload will result in a receipt message whose signature can be
    verified.

    Args:
        i (int): the mmr index where `nodehash` is located.
        nodehash (bytes): the value whose inclusion is being proven.
        proof (List[bytes]): the siblings required to produce `root` from `nodehash`.

    Returns:
        the root hash produced for `nodehash` using `path`
    """

    # set `root` to the value whose inclusion is to be proven
    root = nodehash

    # set g to the zero based height of i.
    g = index_height(i)

    # for each sibling in the proof
    for sibling in proof:
        # if the height of the entry immediately after i is greater than g, then
        # i is a right child.
        if index_height(i + 1) > g:
            # advance i to the parent. As i is a right child, the parent is at `i+1`
            i = i + 1
            # Set `root` to `H(i+1 || sibling || root)`
            root = hash_pospair64(i + 1, sibling, root)
        else:
            # Advance i to the parent. As i is a left child, the parent is at `i + (2^(g+1))`
            i = i + (2 << g)
            # Set `root` to `H(i+1 || root || sibling)`
            root = hash_pospair64(i + 1, root, sibling)

        # Set g to the height index above the current
        g = g + 1

    # Return the hash produced. If the path length was zero, the original nodehash is returned
    return root



def consistency_proof_paths(ifrom : int, ito: int) -> List[List[int]]:
    """Returns the proof paths showing consistency between the MMR's identified by ifrom and ito.

    The proof is an inclusion path for each peak in MMR(ifrom) in MMR(ito)

    """
    apeaks = peaks(ifrom)

    proof = []

    for ipeak in apeaks:
        proof.append(inclusion_proof_path(ipeak, ito))

    return proof


def consistent_roots(
    ifrom: int,
    accumulatorfrom: List[bytes],
    proofs: List[List[bytes]],
) -> List[bytes]:
    """Apply the inclusion paths for each origin accumulator peak

    The returned list will be a descending height ordered list of elements from
    the accumulator for the consistent future state. It may be *exactly* the
    future accumulator or it may be a prefix of it.

    For a valid COSE Receipt of consistency, using the returned array as the
    detached payload will result in a receipt message whose signature can be
    verified.
    """

    # It is an error if the lengths of frompeaks, paths and accumulatorfrom are not all equal.
    frompeaks = peaks(ifrom)
    if (len(frompeaks) != len(accumulatorfrom)):
        raise ValueError()
    if (len(frompeaks) != len(proofs)):
        raise ValueError()

    roots = []
    for i in range(len(accumulatorfrom)):
        root = included_root(frompeaks[i], accumulatorfrom[i], proofs[i])
        if roots and roots[-1] == root:
            continue
        roots.append(root)

    return roots


# ------------------------------------------------------------------------------
# Essential supporting algorithms
# ------------------------------------------------------------------------------

def index_height(i: int) -> int:
    """Returns the 0 based height of the mmr entry indexed by i"""
    # convert the index to a position to take advantage of the bit patterns afforded
    pos = i + 1
    while not all_ones(pos):
        pos = pos - (most_sig_bit(pos) - 1)

    return pos.bit_length() - 1


def peaks(i: int) -> List[int]:
    """Returns the peak indices for MMR(i) in highest to lowest order 

    Assumes MMR(i) is complete, implementations can check for this condition by
    testing the height of i+1
    """

    peak = 0
    peaks = []
    s = i+1
    while s != 0:
        
        # find the highest peak size in the current MMR(s)
        highest_size = (1 << log2floor(s+1)) - 1
        peak = peak + highest_size
        peaks.append(peak-1)
        s -= highest_size

    return peaks


def hash_pospair64(pos: int, a: bytes, b: bytes) -> bytes:
    """
    Compute the hash of  pos || a || b

    Args:
        pos (int): the 1-based position of an mmr node. If a, b are left and
            right children, pos should be the parent position.
        a (bytes): the first value to include in the hash
        b (bytes): the second value to include in the hash

    Returns:
        The value for the node identified by pos
    """
    h = hashlib.sha256()
    h.update(pos.to_bytes(8, byteorder="big", signed=False))
    h.update(a)
    h.update(b)
    return h.digest()

# 
# Binary primitives for the essential algorithms
#
 
def most_sig_bit(pos) -> int:
    """Returns the mask for the the most significant bit in pos"""
    return 1 << (pos.bit_length() - 1)


def all_ones(pos) -> bool:
    """Returns true if all bits, starting with the most significant, are 1"""
    imsb = pos.bit_length() - 1
    mask = (1 << (imsb + 1)) - 1
    return pos == mask

def log2floor(x):
    """Returns the floor of log base 2 (x)"""
    return x.bit_length() - 1

# ------------------------------------------------------------------------------
# Complimentary supporting algorithms, commonly useful when working with MMR data
# ------------------------------------------------------------------------------
def verify_inclusion_path(
    i: int, nodehash: bytes, proof: List[bytes], root: bytes
) -> Tuple[bool, int]:
    """
    Args:
        i (int): The mmr index where `nodehash` is located.
        nodehash (bytes): The value whose inclusion is being proven.
        proof (List[bytes]): The siblings required to produce `root` from `nodehash`.
        root (bytes): The peak from the accumulator which includes node `i`.

    Returns:
        A tuple  (bool, int), where the bool is True if `root` was produced and
        the int is the count of path elements required to do so.
    """
    # 1. If the proof length is zero and the leaf is equal the root, succeed
    if len(proof) == 0 and nodehash == root:
        return (True, 0)

    # 1. Set `g` to `IndexHeight(i)`
    g = index_height(i)

    # 1. Set elementHash to the value whose inclusion is to be proven
    elementhash = nodehash

    # 1. For each pathItem with index iProof in proof
    for iproof, pathitem in enumerate(proof):
        # 1. if `IndexHeight(i+1)` is greater than `g`
        if index_height(i + 1) > g:
            # 1. Set `i` to `i + 1`
            i = i + 1
            # 1. Set `elementHash` = `H(i+1 || pathItem || elementHash)`
            elementhash = hash_pospair64(i + 1, pathitem, elementhash)
        else:
            # 1. Set `i` to `i + (2^(g+1))`
            i = i + (2 << g)
            # 1. Set `elementHash` to `H(i+1 || elementHash || pathItem)`
            elementhash = hash_pospair64(i + 1, elementhash, pathitem)

        # 1. Compare root to `elementHash`.
        if elementhash == root:
            # If root is equal, we have shown that index items from proof have
            # proven inclusion of the value at the initial value for `i`.  Return
            # index to the caller and indicate success.
            return (True, iproof + 1)
        # 1. Increment `g`
        g = g + 1

    # 1. We have consumed the proof without producing the root, fail the verification.
    return (False, len(proof))

def verify_consistent_roots(
        ifrom: int,
        accumulatorfrom: List[bytes],
        accumulatorto: List[bytes],
        fromproofs: List[List[bytes]]) -> bool:
    """Verifies that the proofs from a previous accumulator's peaks are consistent

    Intended for use when verifying consistency directly against replicated
    sections of the log.
    """

    # If all proven nodes match an accumulator peak for MMR(to) then
    # MMR(from) is consistent with MMR(ia). Because both the peaks and
    # the accumulator peaks are listed in descending order of height
    #this can be accomplished with a linear scan.
    proven = consistent_roots(ifrom, accumulatorfrom, fromproofs)

    ito = 0
    for root in proven:

        if accumulatorto[ito] == root:
            continue

        # If the root does not match the current peak then it must match the
        # next one down.

        ito += 1

        if ito >= len(accumulatorto):
            return False

        if accumulatorto[ito] != root:
            return False

    # All proven peaks have been matched against the future accumulator. The log
    # committed by the future accumulator is consistent with the previously
    # committed log state.
    return True


def inclusion_proof(db, i, ix) -> List[bytes]:
    """Return a proof showing the node i is included in mmr(ix)"""
    return [db.get(i) for i in inclusion_proof_path(i, ix)]


def consistency_proof(db, ifrom: int ,ito: int) -> List[List[bytes]]:
    """Return a proof showing MMR(ito) is consistent with MMR(ifrom)"""

    return [[db.get(i) for i in path] for path in consistency_proof_paths(ifrom, ito)]


def peak_depths(i: int) -> List[int]:
    """Returns the peak depths indices for MMR(i) in highest to lowest order 

    The inclusion proof length of any element before i will match the element in
    this list corresponding to the proven accumulator peak. For interior nodes,
    the height of the node must be added to the proof length.

    Assumes MMR(i) is complete, implementations can check for this condition by
    testing the height of i+1
    """

    depths = []
    s = i+1
    while s != 0:
        # find the highest peak size in the current MMR(s)
        highest_size = (1 << ((s + 1).bit_length() - 1)) - 1
        depths.append((highest_size).bit_length() -1)
        s -= highest_size

    return depths


def leaf_count(i: int) -> int:
    """Returns the count of leaf elements in MMR(i)

    The bits of the count also form a mask, where a single bit is set for each
    "peak" present in the accumulator. The bit position is the height of the
    binary tree committing the elements to the corresponding accumulator entry.

    The (sparse) accumulator entry is also derived from the height as acc[len(acc) - bitpos]

    Where acc is the list of accumulator peak indices in descending order of
    height and bitpos is any bit set in the leaf count.

    """
    s = i + 1

    peaksize = (1 << s.bit_length()) - 1
    peakmap = 0
    while peaksize > 0:
        peakmap <<= 1
        if s >= peaksize:
            s -= peaksize
            peakmap |= 1
        peaksize >>= 1

    return peakmap


def mmr_index(e: int) -> int:
    """Returns the node index for the leaf `e`

    Args:
        e - the leaf index, where the leaves are numbered consecutively, ignoring interior nodes
    Returns:
        The mmr index `i` for the element `e`
    """
    sum = 0
    while e > 0:
        h = e.bit_length()
        sum += (1 << h) - 1
        half = 1 << (h - 1)
        e -= half
    return sum


def proves_peak(e:int, d: int) -> bool:
    """Returns true if the path length of d for leaf e proves an accumulator peak

    This is a constant time operation

    Args:
        d: the length of the proposed proof of inclusion for leaf e
    """

    # if the 2^d is an even multiple of e, then the proof is for an accumulator peak
    # also, all such peaks have no left parent

    return (e // (1 << d)) & 1 == 0


def proves_index_peak(i: int, d: int) -> Tuple[int, bool]:
    """Returns the index proven by a path length of d through i and a boolean indicating if it is an accumulator peak

    This operation is log 2 i
     
    Args:
        d: the height of i + the length of the proof
    """

    e = leaf_count(complete_mmr(i)) - 1

    elast, is_peak = proves_leaf_peak(e, d)

    # the last leaf mmr index after e, which is proven by the path length d
    ilast = mmr_index(elast)

    # adding d obtains the mmr peak index, and if is_peak is 1, its also an
    # accumulator peak for at least one MMR state.
    return (ilast + d, is_peak)


def proves_leaf_peak(e: int, d: int) -> Tuple[int, bool]:
    """Determine peak of a perfect tree of height d, containing e, is an accumulator peak

    This operation is constant time.

    mmr_index(elast) + d is the mmr index of the corresponding node.
     
    Args:
        d: the height of i + the length of the proof

    Returns:
        [elast, 1 or 0]
        - elast is the last element after e which is also proven by path length d
        - 1 if the peak is an accumulator peak, 0 otherwise
    """

    # divisor is the count of perfect trees of height d in the smallest complete
    # mmr peak containing leaf_index(i) - 1
    # regardless of the height of the perfect tree, the odd ones are the accumulator peaks.
    dtrees = (e // (1 << d))

    # the first leaf index of the perfect tree, containing i, with height d
    efirst = dtrees * (1 << d)
    # the mmr index of the last leaf of the perfect tree, containing i, with height d
    elast = efirst + (1 << d) - 1

    return (elast, dtrees & 1 == 0)



def parent(i: int) -> int:
    """Return the mmr index for the parent of `i`"""
    g = index_height(i)
    # It is the sibling of the witness that is being proven at
    # each step, so that is what the extension of the proof must be based on.
    if index_height(i + 1) > g:
        return i + 1

    return i + (2 << g)


def complete_mmr(i) -> int:
    """Returns the first complete mmr index which contains i

    A complete mmr index is defined as the first left sibling node above or equal to i.
    """

    h0 = index_height(i)
    h1 = index_height(i + 1)
    while h0 < h1:
        i += 1
        h0 = h1
        h1 = index_height(i + 1)

    return i

def max_height_index(i: int) -> int:
    """Returns the height of the maximum accumulator peak height for MMR(i+1)

    This is also the maximum length of the inclusion proof for any node  
    """


# ------------------------------------------------------------------------------
# Complimentary algorithms for working with accumulators
# ------------------------------------------------------------------------------

def accumulator_root(i: int, ix: int) -> int:
    """Returns the mmr index of the peak root containing `i` in MMR(ix)

    Args:
        ix: Identifies the accumulator state in which to find the root of `i`
        i: The mmr index for which we want to find the root mmr index

    """
    s = ix + 1

    peaksize = (1 << s.bit_length()) - 1
    r = 0
    while peaksize > 0:
        # If the next peak size exceeds the size identifying the accumulator, it
        # is not included in the accumulator.
        if r + peaksize > s:
            peaksize >>= 1
            continue

        # The first peak that surpasses i, without exceeding s, is the root for i
        if r + peaksize > i:
            return r + peaksize - 1

        r += peaksize

        peaksize >>= 1

    return r


def accumulator_index(e: int, g: int) -> int:
    """Return the packed accumulator index for the inclusion proof of e
     
    In the MMR whose proof for e is height `g` long

    Where e = leaf_count(i) - 1

    Args:
        e (int): the leaf count
        g (int): the height index of the smallest complete mmr peak containing e
    Returns:
        The index into the accumulator
    """
    return (e & ~((1 << g) - 1)).bit_count() - 1


def next_witness(ix: int, d: int) -> int:
    """Returns the count of elements that, when added to MMR(sw), will extend the proof for ix
    Args:
        ix: the mmr node index of the node whose proof has length d in mmr size sw
        sw: mmr size when the witness of length d was produced.
        d: len(proof)
    """

    g = index_height(ix)

    ec = 1 << (d + g)
    te = leaf_count(ix) % ec
    return ec - te

def leaf_index_next_witness(e: int, g: int) -> int:
    """Returns the leaf index which will cause an update to the witness for e which has length g"""
    e += 1
    return  e + (1 << g) - (e % (1 << g))


def leaf_witness_update_due(tx: int, d: int) -> int:
    """Returns the count of elements that, when added to MMR(sw), will extend the proof for tx
    Args:
        tx:
        d: length of the proof obtained for tx against accumulator MMR(sw)

    Returns:
        The count of elements that must be added to the mmr of size sw to
        extend the inclusion proof for tx
    """

    ec = 1 << d
    te = tx % ec
    return ec - te


def roots(iw, ix):
    """Returns the unique accumulator roots that commit the inclusion of iw

    in all mmr states before ix
    """

    roots = []

    i = iw
    g = index_height(i)

    while True:

        if index_height(i+1) > g:
            i += 1
        else:

            i += (2 << g)

            while index_height(i+1) > g:
                i += 1
                g += 1

            if i >= ix:
                return roots
            roots.append(i)
        if i >= ix:
            return roots
       
        g += 1


def root_counts(iw, ix):
    return ((ix).bit_length() - 1) - ((iw).bit_length() - 1)


# ------------------------------------------------------------------------------
# Various bit primitives that typically have efficient implementations for 64 bit integers
# ------------------------------------------------------------------------------


# generally useful bit primitives for the tests and for producing the kat tables
def trailing_zeros(v: int) -> int:
    """
    returns the count of 0 bits after the least significant set bit
    returns -1 if v is 0
    """
    # https://stackoverflow.com/a/63552117/13846602
    return (v & -v).bit_length() - 1
