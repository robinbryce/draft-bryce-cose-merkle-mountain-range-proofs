---
title: "Merkle Mountain Range for Immediately Verifiable and Replicable Commitments"
abbrev: MMRIVER
cat: exp
docname: draft-bryce-cose-merkle-mountain-range-proofs-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "CBOR Object Signing and Encryption"
keyword:
 - Internet-Draft
# venue:
#   group: cose
#   type: Working Group
#   mail: WG@example.com
#   arch: https://example.com/WG
#   github: USER/REPO
#   latest: https://example.com/LATEST
#
author:
 -
    fullname: Robin Bryce
    organization: DataTrails
    # we can't change email once an I-D is accepted, and we have changed company emails twice now.
    # also, this is the email that I contribute using on github.
    email: robinbryce@gmail.com

normative:

informative:


--- abstract

This specification describes a protocol for the COSE encoding of verifiable commitments to data,
providing immediate verifiability and immediate, safe, replicability of these commitments.
Using this scheme, any replicated copies are permanently verifiable and are permanently consistent with the complete data set.
The specification allows for historic commitments and the original data, if desired,
to be pruned without impacting the verifiability of subsequent data or any replicated copies.
Verifiers and auditors may be off line indefinitely, and yet, once back online,
be guaranteed they can prove integrity and consistency, or otherwise,
against any future state they encounter.

--- middle

# Introduction

The term "Merkle Mountain Range" is due to [PeterTodd] and has wide acceptance as the identifier for the approach to managing Merkle trees described by this specification.
This is typically abbreviated as MMR.
The MMR can also be seen as the node visitation order obtained by the post-order traversal of any binary tree.

This specification defines algorithms for leaf addition, proofs of inclusion and consistency,
and the related necessary primitives in order to make the advantages of this approach to Merkle trees available in an interoperable manner.

Proving and verifying is defined in terms of the cryptographic, asynchronous, accumulator described by [ReyzinYakoubov]

It further defines the COSE encoding of those proofs.

The format of the underlying storage is outside the scope of this document, however some minimal requirements are established for interfacing with it.

There are distinct advantages for maintainers of verifiable data and for parties relying on the verifiability of that data when using this approach:

- Updates to the persistent tree data are co-ordination free. Competing writers
  can safely use [Optimistic Concurrency Control](https://en.wikipedia.org/wiki/Optimistic_concurrency_control)
- Tree data does not change once written.
  This makes additions immediately available for replication and caching with mechanisms such as [HTTP_ETag](https://en.wikipedia.org/wiki/HTTP_ETag)
- Proofs of inclusion for a specific element are permanently consistent with all future states of the tree.
  And, a tree state which fails this property is provably inconsistent.
- A proof of inclusion can be verified against any historic accumulator,
  provided the element being verified was included in the tree at the time the accumulator was obtained.
- For a previously saved inclusion proof,
  there are at most log 2 (n) future accumulator states required to show its validity against any future tree.
  Where n is the count of additions made after the entry was added.
- Trees can be pruned without breaking these properties of inclusion and consistency.
- The accumulator states naturally emerge from the tree and are also permanently consistent with future states of the tree.
- Any tree state which fails to satisfy these properties is provably inconsistent.
- For both proofs of inclusion and proofs of consistency,
  the authentication paths are strict prefixes of all future authentication paths for those same items.

The above advantages mostly follow from:

- A post order traversal of a binary tree results in a naturally linear storage organization. As observed  in [CrosbySecondaryStorage].
- An asynchronous cryptographic accumulator naturally emerges when maintaining a tree in this way.
  [ReyzinYakoubov] defines the properties of these, which are particularly relevant here, as "Low update frequency" and "Old-Accumulator Compatibility".
- As the post order traversal index is permanently identifying for any elements siblings and parents,
  the authentication path element indices is known and permanent.
  It can be easily computed without needing to materialize the tree in whole or in part.

Further work in [BNT] defines additional advantages for contexts in which "stream" processing of verifiable data is desirable.
Post-order, Pre-order and in-order tree traversal are defined by [KnuthTBT]

# Conventions and Definitions

{::boilerplate bcp14-tagged}

- `i` shall be the index of a node in the MMR
- `pos` shall be `i+1`
- `e` shall be the zero based index of leaf entry in the MMR
- `f` shall be a leaf value, which is `H(x)`
- `h` shall be the 1 based tree height
- `g` shall be the 0 based height, `h-1`
- `v` shall be any node, including a leaf node value, which will be the result of `H(x)`.
- `S` shall be any valid MMR size, and is uniquely identifying for an MMR state
- `A` shall be the the accumulator for any valid MMR size `S`
- `R` shall be the the sparse accumulator, of [ReyzinYakoubov], for any valid MMR size `S`
- `H(x)` shall be the SHA-256 digest of any value x
- `||` shall mean concatenation of raw byte representations of the referenced values.

# Accumulator Structure

In this section we describe and define the asynchronous cryptographic accumulator naturally available in an MMR,
and which is crucial to to a number of the benefits of this approach.

An MMR is a flat base binary tree, where complete sub-trees are maintained in series.
Only the last sub tree may be incomplete.
The roots of each complete sub-tree are described as peaks.

Given only the preceding peaks, and the leaf nodes of the last sub tree,
it is always possible to complete the last sub tree.

For every even numbered node addition, this process will always "burry" at least one preceding peak,
by absorbing the newly complete peak under its predecessor.
This process proceeds until there are no more "completable" predecessors,
needing only the previous peak at each step.

The set of peaks for an MMR of any size is a naturally forming cryptographic accumulator (see [ReyzinYakoubov]).
And this uniquely and succinctly commits the complete history of the MMR.

The notable distinction from more traditional "mono" roots approach to merkle tree proofs is that, as the tree grows,
elements in the accumulator change with low frequency. While a mono root is unique for each individual addition.
This frequency is defined as $$\log_2(n)$$ in the number of subsequent leaf additions after the element in question.

It is important to note that while the accumulator state evolves, all nodes in the tree are write once.
The accumulator simply comprises the nodes at the "peaks" for the current MMR state.
All paths for proofs of inclusion lead to an accumulator peak, rather than a single "mono" root.

Therefore many proofs of inclusion are committed by single attestations to an accumulator state.

Because of this, the inclusion path for any element is strictly append only,
in addition to the data structure itself being append only.
Consistency proofs *are* the inclusion proofs for the old-accumulator peaks against the accumulator for the future tree state consistency is being shown for.
An accumulator is at most tree height long, which is also the maximum length of any single proof of inclusion + 1.

For illustration, consider `MMR(8)` which is a complete MMR with two peaks at node indices 6 and 7.

       6
     2   5
    0 1 3 4 7

The node indices match their location in storage.
When constructing the tree, addition of nodes is strictly append only.

MMR's are identified uniquely by their size. Above we have `MMR(8)`, because there are 8 nodes.

An incomplete MMR may still be identified. Here we have `MMR(9)`.

       6
     2   5
    0 1 3 4 7 8

An MMR is said to be "complete" when all possible ancestors have been "filled in".
The value for node 9 is `H(7 || 8)`, and adding that node completes the previous MMR.

       6
     2   5   9
    0 1 3 4 7 8

The accumulator, described by [ReyzinYakoubov] is the set of peaks, with "gaps" reserved for the missing peaks.
MMR(8), where a gap is indicated by _ would be:

    [6, _, 7]

The packed form would be:

    [6, 7]

The accumulator, packed or padded, lists the peaks strictly descending order of height.
Given this fact, straight forward primitives for selecting the desired peak can be derived from both packed and un-packed form.
The algorithms in this document work with the packed form exclusively.

Given any index `i` in the tree, the accumulator for the previous `D[0:i)` nodes
satisfies the sibling dependencies of the inclusion paths of all subsequent `D[i:n]` nodes.

And the accumulator is itself, only dependent, for proof of inclusion or consistency, on nodes in `D[i:n]`

The progression of the packed accumulator for MMR sizes 1, 3, 4, 7, 8 is then:

`MMR(1): [0]`

`MMR(3): [2]`

`MMR(4): [2, 3]`

`MMR(7): [6]`

`MMR(8): [6, 7]`

`MMR(10): [6, 9]`

The verification path for node `1` in `MMR(3)` is `[0]`, because `H(0, 1)` is the value at `2`.

The path for node `1` in `MMR(4)` remains un changed.

The path for node `1` in `MMR(7)` becomes `[0, 5]`, because `H(0, 1)` is the value at `2`, and `H(H(0, 1), 5)` is the value at `6`.

The path for node `1` in `MMR(8)` and `MMR(10)` remains unchanged.

It can be seen that the older the tree item is,
the less frequently its verification path will be extended to reach a new accumulator entry.

An algorithm to add a single leaf to an MMR is given in [AddLeafHash](#addleafhash)

An algorithm to produce the verifying path for any node `i` is given in [InclusionProofPath](#inclusionproofpath)

In general, given the height `g` of the accumulator peak currently authenticating a node `i`,
the verification path for `i` will not change until the count of tree leaves reaches $$2^{g+1}$$.

An algorithm defining the packed accumulator for any MMR size `S` is given by [Peaks](#peaks)

An algorithm which sets a bit for each present accumulator peaks in an MMR of size `S` is given by [PeaksBitmap](#peaksbitmap),
the produced value is also the count of leaves present in that MMR. This algorithm is independent of whether the accumulator is maintained in packed or padded form.

Lastly, many primitives for working with MMR's rely on a property of the *position* tree form of an MMR.

The position tree for the complete MMR with size 8 MMR(8) is

       7
     3   6
    1 2 4 5 8

Expressing this in binary notation reveals the property that MMR's make extensive use of:

        111
     11     110
    1 10 100  101 1000

The left most node at any height is always "all ones".

# Inclusion Proof

TODO: CDDL

# Receipt of Inclusion

TODO: CDDL

# Consistency Proof

TODO: CDDL

# Receipt of Consistency

# Implementation defined storage methods

The following methods are assumed to be available to the implementation. Very minimal requirements are specified.

Informally, the storage must be array like and have no gaps.

## Get

Reads the value from the MMR at the supplied index.

Used by any algorithm which needs access to node values.

The read MUST be consistent with any other calls to Append or Get within the same algorithm invocation.

Get MAY fail for transient reasons.

## Append


Appends new node to storage and returns the index that will be occupied by the node provided to the next call to append.

The implementation MUST guarantee that the results of Append are immediately available to Get calls in the same invocation of the algorithm OR fail.

Append MUST return the node `i` identifying the node location which comes next.

There MUST be a 1 to 1 correspondence between the MMR node index and the storage location of the node's value.

The implementation MUST guarantee that the storage organization is linear and non-sparse.

Implementations MAY rely on the verifiable properties of the tree,
or optimistic concurrency control, to afford detection of accidental or competing overwrites.

Used only by [AddLeafHash](#addleafhash)

The implementation MAY defer commitment to underlying persistent storage.

Append MAY fail for transient reasons.

# Node values

Interior nodes in the tree SHALL prefix the value provided to `H(x)` with `pos`.

The value `v` for any interior node MUST be `H(pos || Get(LEFT_CHILD) || Get(RIGHT_CHILD))`

This naturally affords the pre-image resistance typically obtained with specific leaf/interior node prefixes.
Nonce schemes to account for duplicate leaves are also un-necessary as a result,
but MAY be included by the application for other reasons.

The algorithm for leaf addition is provided the result of `H(x)` directly.
The application MUST define how it produces `x` such that parties reliant on the system for verification can recreate `H(x)`.

# Addition, Inclusion and Consistency Proof Algorithms

All numbers are unsigned 64 bit integers. The maximum height of a single tree is 64.

Were a tree to accept a new addition once every 10 milliseconds, it would take roughly 4.6 million milenia to over flow.

Should a system exist that can extend a tree fast enough for this to be a limitation,
the same advantages that make MMR's convenient to work with also accrue to combinations of trees.

The algorithms are offered in both a python like informal pseudo code, and structured english.

## AddLeafHash

`AddLeafHash(f)`

Note: it is assumed that the algorithm terminates and returns on any transient error.

Given,

`f` the leaf value resulting from `H(x)` for the caller defined leaf value `x`

The caller MUST account for 2nd pre-image attacks on the tree.

The caller SHOULD take into account the defined [Node values](#node-values) scheme when satisfying this requirement.

Because the interior nodes commit the position of their children, including the case where the child is a leaf,
no special steps are required of the application or implementation to account for duplicate values of `x`.

The process in words is

1. Set `i` to the result of invoking `Append(f)`
1. Set `g` to 0, the height of the leaf item f
1. If `IndexHeight(i)` is greater than `g` (#looptarget)
    1. Set `iLeft` to `i - (2 << g)`
    1. Set `iRight` to `i - 1`
    1. Set `v` to `H(i + 1 || Get(iLeft) || Get(iRight))`
    1. Set `i` to the result of invoking `Append(v)`
    1. Set `g` to `g + 1`
    1. Goto #looptarget
1. Return `i` to the caller

The process expressed in python is

    def addleafhash(db, f: bytes) -> int:

        g = 0
        i = db.append(f)

        while index_height(i) > g:

            ileft = i - (2 << g)
            iright = i - 1

            i = db.append(hash_pospair64(i+1, db.get(ileft), db.get(iright)))
            g += 1

        return i

## InclusionProofPath

`InclusionProofPath(S, i)` is used to produce the verification paths for inclusion proofs and consistency proofs.

When a path is produced for the purposes of verification, the path elements MUST be resolved to the referenced node values.
Whether this is accomplished in-line, as the algorithm proceeds, or later as a second pass, is an implementation choice.

For a pruned tree, the post order index of the element is either present directly or is present in the accumulator.
Managing the availability of the accumulator is the callers responsibility.

Given

- `S` identifies the MMR state.
- `i` is the index the `nodeHash` is to be shown at

In the described algorithm,
pathElement is either the the post-order index `i` for the node or the value obtained from storage for that index.

1. Set the path to the empty list
1. Set `g` to `IndexHeight(i)`
1. Repeat until #termination_condition evaluates true
    1. Set iLocalPeak to `i`
    1. if `IndexHeight(i+1)` is greater than `g`
        1. Set `iSibling` to `iLocalPeak - SiblingOffset(g)`
        1. Set `i` to `i+1`
    1. Otherwise,
        1. Set `iSibling` to `iLocalPeak + SiblingOffset(g)`
        1. Set `i` to `i` + `2 << g`
    1. If `iSibling` is greater or equal to `S` (#termination_condition)
       Return the current path to the caller, terminating the algorithm.
    1. Append the current pathElement to the proof.
    1. Increment the index height `g`

* `SiblingOffset` is defined as `(2 << g) - 1`
* `IndexHeight` is defined in [IndexHeight](#indexheight)

Note that at the #termination_condition it MAY be convenient for implementations to return the index of the local peak `iLocalPeak` and its height `g` to the caller.

For reference in the supplementary worked examples, the decision points are annotated (1), (2)

    def inclusion_proof_path(s, i) -> List[int]:
        """Returns the list of node indices proving inclusion of i"""

        path = []
        g = index_height(i)

        while True:

            isibling = None # lexical scopes

            ilocalpeak = i
            if index_height(i+1) > g: # (1)
                isibling = ilocalpeak - ((2 << g) -1)
                i = i + 1
            else:
                isibling = ilocalpeak + ((2 << g) -1)
                i = i + (2 << g)

            if isibling >= s: # (2)
                return path
            path.append(isibling)
            g = g + 1

# Inclusion and Consistency Verification Algorithms

## VerifyInclusionPath

Verifies an accumulator peak root can be reached from the leaf using the path

Given

- `S` identifies the MMR state.
- `i` is the index the `nodeHash` is to be shown at
- `nodeHash` the value whose inclusion is to be shown
- `proof` is the inclusion path node values, verifying inclusion of `nodeHash` at `i` in the `MMR(S)`
- `root` is the root of the sub tree occupied by `i`, and is a member of the accumulator for `MMR(S)`

`VerifyInclusionPath` is defined as

1. If the proof length is zero and the leaf is equal the root, succeed
1. Set `g` to `IndexHeight(i)`
1. Set elementHash to the value whose inclusion is to be proven
1. For each pathItem with index iProof in proof
    1. if `IndexHeight(i+1)` is greater than `g`
        1. Set `i` to `i + 1`
        1. Set `elementHash` = `H(i+1 || pathItem || elementHash)`
    1. Otherwise:
        1. Set `i` to `i + (2 << g)`
        1. Set `elementHash` to `H(i+1 || elementHash || pathItem)`
    1. Compare root to `elementHash`.
       If root is equal,
       we have shown that index items from proof have proven inclusion
       of the value at the initial value for `i`.
       Return index to the caller and indicate success.
    1. Increment `g`
1. We have consumed the proof without producing the root, fail the verification.

Verification MUST require that the path is fully consumed during verification.
The algorithm above defers that final requirement to the caller.

Where the caller is verifying a single proof of inclusion, they MUST check the returned consumed length equals the length of the poof provided.

Consistency proofs concatenate inclusion proofs for each accumulator peak in the origin mmr state.

Where the caller is verifying a series of concatenated proofs of inclusion, such as for consistency proofs,
the caller MUST ensure the entire concatenated series of proofs is fully consumed.

In the case of concatenated inclusion proof verification,
the sub range of the aggregate proof must be advanced by the returned consumed length on each call.

For "old accumulator compatibility", the application MUST establish the prefix length of the proof needed to produce the `root` value in the old accumulator. This prefix length MUST then be used when deciding if the provided proof has been fully consumed by verification.


The process expressed in python is

    def verify_inclusion_path(
        s: int, i: int, nodehash: bytes,
        proof: List[bytes], root: bytes) -> Tuple[bool, int]:

        if len(proof) == 0 and nodehash == root:
            return (True, 0)

        g = index_height(i)

        elementhash = nodehash

        for iproof, pathitem in enumerate(proof):
            if index_height(i + 1) > g:
                i = i + 1
                elementhash = hash_pospair64(i+1, pathitem, elementhash)
            else:
                i = i + (2 << g)
                elementhash = hash_pospair64(i+1, elementhash, pathitem)

            if elementhash == root:
                return (True, iproof + 1)
            g = g + 1

        return (False, len(proof))

## ConsistencyProof

Creates a proof of consistency between the identified MMR's.

The returned path is the concatenation of the inclusion proofs
authenticating the peaks of MMR(a) in MMR(b)

The process expressed in python is

    def consistency_proof(asize: int, bsize: int) -> List[int]:
        apeaks = peaks(asize)

        proof = []

        for apos in apeaks:
            proof.extend(inclusion_proof_path(bsize, apos-1))

        return proof

## VerifyConsistencyProof

The process expressed in python is

    def verify_consistency(
            asize: int, bsize: int,
            aaccumulator: List[bytes], baccumulator: List[bytes],
            path: List[bytes]) -> bool:

        apeakpositions = peaks(asize)
        bpeakpositions = peaks(bsize)

        if len(aaccumulator) != len(apeakpositions):
            return False

        if len(baccumulator) != len(bpeakpositions):
            return False

        ipeaka = ipeakb = 0

        apos = apeakpositions[ipeaka]

        ok = False
        while ipeaka < len(aaccumulator):
            bpeak = bpeakpositions[ipeakb]
            while apos  <= bpeak:
                (ok, used) = verify_inclusion_path(
                    bsize, aaccumulator[ipeaka], apos-1,
                    path, baccumulator[ipeakb])
                if not (ok or used > len(path)):
                    return False
                path = path[used:]
                ipeaka += 1
                if ipeaka == len(aaccumulator):
                    break
                apos = apeakpositions[ipeaka]
            ipeakb += 1

        return ok and len(path) == 0

# Algorithms for working with the accumulator

## IndexHeight

`IndexHeight(i)` returns the zero based height `g` of the node index `i`

    def index_height(i) -> int:
        pos = i + 1
        while not all_ones(pos):
          pos = pos - most_sig_bit(pos) + 1

        return pos.bit_length() - 1

## Peaks

`Peaks(S)` returns the peak positions for `MMR(S)` (Note: these are just the corresponding storage indices + 1)

Returns the peak indices for MMR(s)

Assumes MMR(s) is complete, implementations can check for this condition by testing the height of s+1

    def peaks(s) -> List[int]:

        peak = 0
        peaks = []
        while s != 0:
            # find the highest peak size in the current MMR(s)
            highest_size = (1 <<((s +1).bit_length()-1)) - 1
            peak = peak + highest_size
            peaks.append(peak)
            s -= highest_size

        return peaks

## SparsePeakIndex

`SparsePeakIndex(R, g)` returns the sparse accumulator index in `R` identified by its height `g`

When working with a sparse accumulator, and the height of the desired peak is known,
the accumulator index is given by `length(R) - g - 1`

## PeakIndex

`PeakIndex(e, g)` returns the packed accumulator index in `A` identified by its height `g`

`e` is the leaf count, which is often to hand. Otherwise it is the result of `PeaksBitmap(s)`

`g`, the height index of the accumulator peak containing `e` in MMR(s), is also often to hand.

Otherwise it is the count of zero bits in `e` after the least significant bit set.

1. Set `mask` to the result of left shifting 1 by `g`.
2. Set `mask` to `mask - 1`.
3. Set `mask` to its binary compliment.
4. Set `mask` to the logical and of `e` and `mask`
5. Return the count of bits set in `mask`

Expressed as python

    def peak_index(e:int, g:int) -> int:
        return (e & ~((1 << g)-1)).bit_count() - 1

## PeaksBitmap

`PeaksBitmap(s)` Returns a mask with a bit set for each peak,
interpreted as an integer this is also the count of leaves in `MMR(s)`,

Expressed in python

    def peaks_bitmap(s: int) -> int:
        if s == 0:
            return 0

        peaksize = (1 << s.bit_length()) - 1
        peakmap = 0
        while peaksize > 0:
            peakmap <<= 1
            if s >= peaksize:
                s -= peaksize
                peakmap |= 1
            peaksize >>= 1

        return peakmap

# General Algorithms & Primitives

## A Note On Hardware Sympathy

For flat base trees, many operations are formally $$\log_2(n)$$

However, precisely because of the binary nature of the tree, most benefit from single-cycle assembly level optimizations, assuming a counter limit of $$2^{64}$$ Which as discussed above, is a _lot_ of tree.

Finding the position of the first non-zero bit or counting the number of bits that are set are both primitives necessary for some of the algorithms.
[CLZ](https://developer.arm.com/documentation/dui0802/b/A32-and-T32-Instructions/CLZ) has single-cycle implementations on most architectures. Similarly, `POPCNT` exists.
AMD defined some useful [binary manipulation](https://en.wikipedia.org/wiki/X86_Bit_manipulation_instruction_set) extensions.

Sympathetic instructions, or compact look up table implementations exist for other fundamental operations too.
Most languages have sensible standard wrappers.
While these operations are not strictly O(1) complexity, this has little impact in practice.

## PeakIndex

Index of the peak accumulator for the peak with the provided height. Note that
this works with the compact accumulator directly.

`OnesCount(peakBits & ^((1<<heightIndex)-1)) - 1`


## TopPeak

Smallest, left most (all ones) peak, containing or **equal to** pos

This is essentially a ^2 *floor* function for the accumulation of bits

`1<<(BitLength(pos+1)-1) - 1`

An illustrative example of some outputs

    TopPeak(1) = TopPeak(2) = 1
    TopPeak(2) = TopPeak(3) = TopPeak(4) = TopPeak(5) = TopPeak(6) = 3
    TopPeak(7) = 7

    2       7
          /   \
    1    3     6    10
        / \  /  \   / \
    0  1   2 4   5 8   9 11

## TopHeight

The height index `g` of the largest perfect peak contained in, or exactly, pos
This is essentially a ^2 *floor* function for the accumulation of bits:

An illustrative example of some outputs

    TopHeight(1) = TopHeight(2) = 0
    TopHeight(2) = TopHeight(3) = TopHeight(4) = TopHeigth(5)
        = TopHeight(6) = 1
    TopHeight(7) = 2

    2       7
          /   \
    1    3     6    10
        / \  /  \   / \
    0  1   2 4   5 8   9 11

 `BitLength(pos+1)-1`

## SiblingOffset

`(2 << g) - 1`

## MostSigBit

Returns the mask for the the most significant bit in pos

`1 << (BitLength(pos) - 1)`

Expressed in python

    def most_sig_bit(pos) -> int:
        return 1 << (pos.bit_length() - 1)

We assume the following primitives for working with bits as they commonly have library or hardware support.

## BitLength

The minimum number of bits to represent pos. b011 would be 2, b010 would be 2, and b001 would be 1.

In python,

    def bit_length(pos):
        return pos.bit_length()

## AllOnes

Tests if all bits, from the most significant that is set, are 1, b0111 would be true, b0101 would be false.

In python,

    def all_ones(pos) -> bool:
        msb = most_sig_bit(pos)
        mask = (1 << (msb + 1)) - 1
        return pos == mask

## OnesCount

Count of set bits. For example `OnesCount(b101)` is 2

## TrailingZeros

The count of nodes above and to the left of `pos`

In python,

    (v & -v).bit_length() - 1

# Security Considerations

TODO Security


# IANA Considerations

## Additions to Existing Registries

Editors note: we will require an addition to the CoMETER spec once it is accepted.

## New Registries

Editors note: We can start with SHA-256. Two of the referenced implementations use BLAKE2b-256,
We would like to add support for SHA3-256 (and possibly SHA3-512)

--- back

# Implementation Status

Note to RFC Editor: Please remove this section as well as references to BCP205 before AUTH48.

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in BCP205.
The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.
Please note that the listing of any individual implementation here does not imply endorsement by the IETF.
Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors.
This is not intended as, and must not be construed to be, a catalog of available implementations or their features.
Readers are advised to note that other implementations may exist.

According to BCP205,
"this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature.
It is up to the individual working groups to use this information as they see fit".

## Implementers

### DataTrails

An open-source implementation was initiated and is maintained by Data Trails Inc. - DataTrails.

Uses SHA-256 as the hash alg

#### Implementation Name

An application demonstrating the concepts is available at [https://app.datatrails.ai/](https://app.datatrails.ai/).

#### Implementation URL

An open-source implementation is available at:

- https://github.com/datatrails/go-datatrails-merklelog

#### Maturity

Used in production. SEMVER unstable (no backwards compat declared yet)

### Peter Todd

Almost compatible, where here the leaf hash is not defined, in Peter Todd's formal description, all nodes, including the leaves include the position in the hash. In this specification, leaf hashes are added 'as is'. Interior nodes commit to the size of the balanced tree rooted at the node.

#### Implementation URL

- https://github.com/proofchains/python-proofmarshal/blob/master/proofmarshal/mmr.py

#### Maturity

Reference implementation, but the "original".

### Robin Bryce

#### Implementation URL

A minimal reference implementation of this draft. Used to generate the test vectors in this draft, is available at:

- https://github.com/robinbryce/merkle-mountain-range-proofs/blob/main/algorithms.py


#### Maturity

Reference only

### Mimblewimble ?

Is specifically committing to positions as we describe, but is committing zero based indices, and uses BLAKE2B as the HASH-ALG. Accounting for those differences, their commitment trees would be compatible with this draft.

#### Implementation URL

An implementation is available here:

- https://github.com/mimblewimble/grin/blob/master/doc/mmr.md (Grin is a rust implementation of the mimblewimble protocol)
- https://github.com/BeamMW/beam/blob/master/core/merkle.cpp (Beam is a C++ implementation of the mimblewimble protocol)

### ZCash ?

Uses an incompatible scheme for committing the sub trees, and additionally specifies how the leaf hash is produced.

- https://zips.z.cash/zip-0221

#### Implementation URL


TODO: check if they are to positions as we describe, if so their commitment trees should be compatible with this draft.


The code's level of maturity is considered to be "prototype".

### Tari-Project

Incompatible, does not include commitment of position in the interior node hash

#### Implementation URL

- https://github.com/tari-project/tari/blob/development/base_layer/mmr/src/merkle_mountain_range.rs


# Algorithm Test Vectors

In this section we provide known answer outputs for the various algorithms for the `MMR(39)`

## MMR(39)

The node index tree for `MMR(39)` is

    g

    4                         30


    3              14                       29
                  / \
                 /   \
                /     \
               /       \
              /         \
    2        6           13            21             28                37
           /   \        /   \        /    \
    1     2     5      9     12     17     20     24       27       33      36
         / \   / \    / \   /  \   /  \   /  \
    0   0   1 3   4  7   8 10  11 15  16 18  19 22  23   25   26  31  32   34  35   38

    .   0   1 2   3  4   5  6   7  8   9 10  11 12  13   14   15  16  17   18  19   20 e

The vertical axis is `g`, the one based height of the tree.

The horizontal axis is `e`, the leaf indices corresponding to the `g=0` nodes in the tree

## MMR(39) leaf values (excluding interior nodes)

We define `H(v)` for test vector leaf values `f` as the SHA-256 hash of the the big endian representation of `e`.

|  e |                          leaf values                           |
|---:|----------------------------------------------------------------|
|  0 |af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc|
|  1 |cd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50|
|  2 |d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975|
|  3 |8005f02d43fa06e7d0585fb64c961d57e318b27a145c857bcd3a6bdb413ff7fc|
|  4 |a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
|  5 |4c0e071832d527694adea57b50dd7b2164c2a47c02940dcf26fa07c44d6d222a|
|  6 |8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7|
|  7 |0b5000b73a53f0916c93c68f4b9b6ba8af5a10978634ae4f2237e1f3fbe324fa|
|  8 |e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|  9 |998e907bfbb34f71c66b6dc6c40fe98ca6d2d5a29755bc5a04824c36082a61d1|
| 10 |5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d|
| 11 |1b8d0103e3a8d9ce8bda3bff71225be4b5bb18830466ae94f517321b7ecc6f94|
| 12 |7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
| 13 |aed2b8245fdc8acc45eda51abc7d07e612c25f05cadd1579f3474f0bf1f6bdc6|
| 14 |561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213|
| 15 |1209fe3bc3497e47376dfbd9df0600a17c63384c85f859671956d8289e5a0be8|
| 16 |1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 17 |707d56f1f282aee234577e650bea2e7b18bb6131a499582be18876aba99d4b60|
| 18 |4d75f61869104baa4ccff5be73311be9bdd6cc31779301dfc699479403c8a786|
| 19 |0764c726a72f8e1d245f332a1d022fffdada0c4cb2a016886e4b33b66cb9a53f|
| 20 |e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785|

## MMR(39) node values (including leaves)

 | i  |                          node values                           |
 |:---|----------------------------------------------------------------|
 | 0|af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc|
 | 1|cd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50|
 | 2|ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8|
 | 3|d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975|
 | 4|8005f02d43fa06e7d0585fb64c961d57e318b27a145c857bcd3a6bdb413ff7fc|
 | 5|9a18d3bc0a7d505ef45f985992270914cc02b44c91ccabba448c546a4b70f0f0|
 | 6|827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88|
 | 7|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
 | 8|4c0e071832d527694adea57b50dd7b2164c2a47c02940dcf26fa07c44d6d222a|
 | 9|b8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d|
 |10|8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7|
 |11|0b5000b73a53f0916c93c68f4b9b6ba8af5a10978634ae4f2237e1f3fbe324fa|
 |12|6f3360ad3e99ab4ba39f2cbaf13da56ead8c9e697b03b901532ced50f7030fea|
 |13|508326f17c5f2769338cb00105faba3bf7862ca1e5c9f63ba2287e1f3cf2807a|
 |14|78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112|
 |15|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
 |16|998e907bfbb34f71c66b6dc6c40fe98ca6d2d5a29755bc5a04824c36082a61d1|
 |17|f4a0db79de0fee128fbe95ecf3509646203909dc447ae911aa29416bf6fcba21|
 |18|5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d|
 |19|1b8d0103e3a8d9ce8bda3bff71225be4b5bb18830466ae94f517321b7ecc6f94|
 |20|0a4d7e66c92de549b765d9e2191027ff2a4ea8a7bd3eb04b0ed8ee063bad1f70|
 |21|61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710|
 |22|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
 |23|aed2b8245fdc8acc45eda51abc7d07e612c25f05cadd1579f3474f0bf1f6bdc6|
 |24|dd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae|
 |25|561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213|
 |26|1209fe3bc3497e47376dfbd9df0600a17c63384c85f859671956d8289e5a0be8|
 |27|6b4a3bd095c63d1dffae1ac03eb8264fdce7d51d2ac26ad0ebf9847f5b9be230|
 |28|4459f4d6c764dbaa6ebad24b0a3df644d84c3527c961c64aab2e39c58e027eb1|
 |29|77651b3eec6774e62545ae04900c39a32841e2b4bac80e2ba93755115252aae1|
 |30|d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7|
 |31|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
 |32|707d56f1f282aee234577e650bea2e7b18bb6131a499582be18876aba99d4b60|
 |33|0c9f36783b5929d43c97fe4b170d12137e6950ef1b3a8bd254b15bbacbfdee7f|
 |34|4d75f61869104baa4ccff5be73311be9bdd6cc31779301dfc699479403c8a786|
 |35|0764c726a72f8e1d245f332a1d022fffdada0c4cb2a016886e4b33b66cb9a53f|
 |36|c861552e9e17c41447d375c37928f9fa5d387d1e8470678107781c20a97ebc8f|
 |37|6a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa|
 |38|e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785|

## Peak (accumulator) positions and values for all MMR's to MMR(39)

(Peaks)[#peaks] will produce the following position lists.

| S |        accumulator peaks |
|----|--------------------------------|
|   1| 1
|   3| 3
|   4| 3, 4
|   7| 7
|   8| 7, 8
|  10| 7, 10
|  11| 7, 10, 11
|  15| 15
|  16| 15, 16
|  18| 15, 18
|  19| 15, 18, 19
|  22| 15, 22
|  23| 15, 22, 23
|  25| 15, 22, 25
|  26| 15, 22, 25, 26
|  31| 31
|  32| 31, 32
|  34| 31, 34
|  35| 31, 34, 35
|  38| 31, 38
|  39| 31, 38, 39


When the positions are converted to indices they will retrieve the following values from the MMR

|S-1|        accumulator peaks |
|--|--------------------------------|
| 0|af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc
| 2|ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8
| 3|ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8, d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975
| 6|827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88
| 7|827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88, a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2
| 9|827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88, b8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d
|10|827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88, b8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d, 8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7
|14|78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112
|15|78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112, e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504
|17|78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112, f4a0db79de0fee128fbe95ecf3509646203909dc447ae911aa29416bf6fcba21
|18|78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112, f4a0db79de0fee128fbe95ecf3509646203909dc447ae911aa29416bf6fcba21, 5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d
|21|78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112, 61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710
|22|78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112, 61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710, 7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c
|24|78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112, 61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710, dd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae
|25|78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112, 61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710, dd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae, 561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213
|30|d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7
|31|d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7, 1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b
|33|d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7, 0c9f36783b5929d43c97fe4b170d12137e6950ef1b3a8bd254b15bbacbfdee7f
|34|d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7, 0c9f36783b5929d43c97fe4b170d12137e6950ef1b3a8bd254b15bbacbfdee7f, 4d75f61869104baa4ccff5be73311be9bdd6cc31779301dfc699479403c8a786
|37|d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7, 6a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa
|38|d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7, 6a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa, e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785

## node height, leaf count and peak mask

These tables cover the outputs of `IndexHeight` and `PeakBitmap`.
`g=IndexHeight`, `e` & `m` are the decimal and binary representations of `PeakBitmap`

`m` is the bit map of peaks, and also the binary representation of `e`

|i|0    |1    |2    |3    |4    |5    |6    |7    |8    |9    |
|-|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|
|g|0    |0    |1    |0    |0    |1    |2    |0    |0    |1    |
|e|1    |1    |2    |3    |3    |3    |4    |5    |5    |6    |
|m|1    |1    |10   |11   |11   |11   |100  |101  |101  |110  |

|i|10   |11   |12   |13   |14   |15   |16   |17   |18   |19   |20   |21   |
|-|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|
|g|0    |0    |1    |2    |3    |0    |0    |1    |0    |0    |1    |2    |
|e|7    |7    |7    |7    |8    |9    |9    |10   |11   |11   |11   |12   |
|m|111  |111  |111  |111  |1000 |1001 |1001 |1010 |1011 |1011 |1011 |1100 |


|i|22   |23   |24   |25   |26   |27   |28   |29   |30   |31   |32   |33   |
|-|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|
|g|0    |0    |1    |0    |0    |1    |2    |3    |4    |0    |0    |1    |
|e|13   |13   |14   |15   |15   |15   |15   |15   |16   |17   |17   |18   |
|m|1101 |1101 |1110 |1111 |1111 |1111 |1111 |1111 |10000|10001|10001|10010|

|i|34   |35   |36   |37   |38   |
|-|-----|-----|-----|-----|-----|
|g|0    |0    |1    |2    |0    |
|e|19   |19   |19   |20   |21   |
|m|10011|10011|10011|10100|10101|

## Inclusion proof paths and the associated accumulator states

- The inclusion path column defines the outputs of [InclusionProofPath](#inclusionproofpath))
- The accumlator column shows the output of [Peaks][#peaks], but adjusted index the storage.
- The accumulator root index shows the output of [PeakIndex](#peakindex)
- The root column shows the value in the storage corresponding to the index in accumulator selected by the accumulator_root_index. Eg `storage[]

This table illustrates the low, and predictably reducing, rate with which the authentication root changes for any single entry in the MMR.
Each time the root for a leaf changes, the validity period doubles.

This table also ilustrates that the authentication path for any single entry only ever grows.
It is therefore guaranteed to be a prefix of any future path for the same entry.

| i  | MMR  |inclusion path|accumulator|accumulator root index|
|:---|----:|------------------|------------------|----|
| 0|MMR(1) |                  |0                 |0   |
| 0|MMR(3) |1                 |2                 |0   |
| 0|MMR(7) |1, 5              |6                 |0   |
| 0|MMR(10)|1, 5              |6, 9              |0   |
| 0|MMR(15)|1, 5, 13          |14                |0   |
| 0|MMR(18)|1, 5, 13          |14, 17            |0   |
| 0|MMR(22)|1, 5, 13          |14, 21            |0   |
| 0|MMR(25)|1, 5, 13          |14, 21, 24        |0   |
| 0|MMR(31)|1, 5, 13, 29      |30                |0   |
| 0|MMR(34)|1, 5, 13, 29      |30, 33            |0   |
| 0|MMR(38)|1, 5, 13, 29      |30, 37            |0   |
| 1|MMR(3) |0                 |2                 |0   |
| 1|MMR(7) |0, 5              |6                 |0   |
| 1|MMR(10)|0, 5              |6, 9              |0   |
| 1|MMR(15)|0, 5, 13          |14                |0   |
| 1|MMR(18)|0, 5, 13          |14, 17            |0   |
| 1|MMR(22)|0, 5, 13          |14, 21            |0   |
| 1|MMR(25)|0, 5, 13          |14, 21, 24        |0   |
| 1|MMR(31)|0, 5, 13, 29      |30                |0   |
| 1|MMR(34)|0, 5, 13, 29      |30, 33            |0   |
| 1|MMR(38)|0, 5, 13, 29      |30, 37            |0   |
| 2|MMR(3) |                  |2                 |0   |
| 2|MMR(7) |5                 |6                 |0   |
| 2|MMR(10)|5                 |6, 9              |0   |
| 2|MMR(15)|5, 13             |14                |0   |
| 2|MMR(18)|5, 13             |14, 17            |0   |
| 2|MMR(22)|5, 13             |14, 21            |0   |
| 2|MMR(25)|5, 13             |14, 21, 24        |0   |
| 2|MMR(31)|5, 13, 29         |30                |0   |
| 2|MMR(34)|5, 13, 29         |30, 33            |0   |
| 2|MMR(38)|5, 13, 29         |30, 37            |0   |
| 3|MMR(4) |                  |2, 3              |1   |
| 3|MMR(7) |4, 2              |6                 |0   |
| 3|MMR(10)|4, 2              |6, 9              |0   |
| 3|MMR(15)|4, 2, 13          |14                |0   |
| 3|MMR(18)|4, 2, 13          |14, 17            |0   |
| 3|MMR(22)|4, 2, 13          |14, 21            |0   |
| 3|MMR(25)|4, 2, 13          |14, 21, 24        |0   |
| 3|MMR(31)|4, 2, 13, 29      |30                |0   |
| 3|MMR(34)|4, 2, 13, 29      |30, 33            |0   |
| 3|MMR(38)|4, 2, 13, 29      |30, 37            |0   |
| 4|MMR(7) |3, 2              |6                 |0   |
| 4|MMR(10)|3, 2              |6, 9              |0   |
| 4|MMR(15)|3, 2, 13          |14                |0   |
| 4|MMR(18)|3, 2, 13          |14, 17            |0   |
| 4|MMR(22)|3, 2, 13          |14, 21            |0   |
| 4|MMR(25)|3, 2, 13          |14, 21, 24        |0   |
| 4|MMR(31)|3, 2, 13, 29      |30                |0   |
| 4|MMR(34)|3, 2, 13, 29      |30, 33            |0   |
| 4|MMR(38)|3, 2, 13, 29      |30, 37            |0   |
| 5|MMR(7) |2                 |6                 |0   |
| 5|MMR(10)|2                 |6, 9              |0   |
| 5|MMR(15)|2, 13             |14                |0   |
| 5|MMR(18)|2, 13             |14, 17            |0   |
| 5|MMR(22)|2, 13             |14, 21            |0   |
| 5|MMR(25)|2, 13             |14, 21, 24        |0   |
| 5|MMR(31)|2, 13, 29         |30                |0   |
| 5|MMR(34)|2, 13, 29         |30, 33            |0   |
| 5|MMR(38)|2, 13, 29         |30, 37            |0   |
| 6|MMR(7) |                  |6                 |0   |
| 6|MMR(10)|                  |6, 9              |0   |
| 6|MMR(15)|13                |14                |0   |
| 6|MMR(18)|13                |14, 17            |0   |
| 6|MMR(22)|13                |14, 21            |0   |
| 6|MMR(25)|13                |14, 21, 24        |0   |
| 6|MMR(31)|13, 29            |30                |0   |
| 6|MMR(34)|13, 29            |30, 33            |0   |
| 6|MMR(38)|13, 29            |30, 37            |0   |
| 7|MMR(8) |                  |6, 7              |1   |
| 7|MMR(10)|8                 |6, 9              |1   |
| 7|MMR(15)|8, 12, 6          |14                |0   |
| 7|MMR(18)|8, 12, 6          |14, 17            |0   |
| 7|MMR(22)|8, 12, 6          |14, 21            |0   |
| 7|MMR(25)|8, 12, 6          |14, 21, 24        |0   |
| 7|MMR(31)|8, 12, 6, 29      |30                |0   |
| 7|MMR(34)|8, 12, 6, 29      |30, 33            |0   |
| 7|MMR(38)|8, 12, 6, 29      |30, 37            |0   |
| 8|MMR(10)|7                 |6, 9              |1   |
| 8|MMR(15)|7, 12, 6          |14                |0   |
| 8|MMR(18)|7, 12, 6          |14, 17            |0   |
| 8|MMR(22)|7, 12, 6          |14, 21            |0   |
| 8|MMR(25)|7, 12, 6          |14, 21, 24        |0   |
| 8|MMR(31)|7, 12, 6, 29      |30                |0   |
| 8|MMR(34)|7, 12, 6, 29      |30, 33            |0   |
| 8|MMR(38)|7, 12, 6, 29      |30, 37            |0   |
| 9|MMR(10)|                  |6, 9              |1   |
| 9|MMR(15)|12, 6             |14                |0   |
| 9|MMR(18)|12, 6             |14, 17            |0   |
| 9|MMR(22)|12, 6             |14, 21            |0   |
| 9|MMR(25)|12, 6             |14, 21, 24        |0   |
| 9|MMR(31)|12, 6, 29         |30                |0   |
| 9|MMR(34)|12, 6, 29         |30, 33            |0   |
| 9|MMR(38)|12, 6, 29         |30, 37            |0   |
|10|MMR(11)|                  |6, 9, 10          |2   |
|10|MMR(15)|11, 9, 6          |14                |0   |
|10|MMR(18)|11, 9, 6          |14, 17            |0   |
|10|MMR(22)|11, 9, 6          |14, 21            |0   |
|10|MMR(25)|11, 9, 6          |14, 21, 24        |0   |
|10|MMR(31)|11, 9, 6, 29      |30                |0   |
|10|MMR(34)|11, 9, 6, 29      |30, 33            |0   |
|10|MMR(38)|11, 9, 6, 29      |30, 37            |0   |
|11|MMR(15)|10, 9, 6          |14                |0   |
|11|MMR(18)|10, 9, 6          |14, 17            |0   |
|11|MMR(22)|10, 9, 6          |14, 21            |0   |
|11|MMR(25)|10, 9, 6          |14, 21, 24        |0   |
|11|MMR(31)|10, 9, 6, 29      |30                |0   |
|11|MMR(34)|10, 9, 6, 29      |30, 33            |0   |
|11|MMR(38)|10, 9, 6, 29      |30, 37            |0   |
|12|MMR(15)|9, 6              |14                |0   |
|12|MMR(18)|9, 6              |14, 17            |0   |
|12|MMR(22)|9, 6              |14, 21            |0   |
|12|MMR(25)|9, 6              |14, 21, 24        |0   |
|12|MMR(31)|9, 6, 29          |30                |0   |
|12|MMR(34)|9, 6, 29          |30, 33            |0   |
|12|MMR(38)|9, 6, 29          |30, 37            |0   |
|13|MMR(15)|6                 |14                |0   |
|13|MMR(18)|6                 |14, 17            |0   |
|13|MMR(22)|6                 |14, 21            |0   |
|13|MMR(25)|6                 |14, 21, 24        |0   |
|13|MMR(31)|6, 29             |30                |0   |
|13|MMR(34)|6, 29             |30, 33            |0   |
|13|MMR(38)|6, 29             |30, 37            |0   |
|14|MMR(15)|                  |14                |0   |
|14|MMR(18)|                  |14, 17            |0   |
|14|MMR(22)|                  |14, 21            |0   |
|14|MMR(25)|                  |14, 21, 24        |0   |
|14|MMR(31)|29                |30                |0   |
|14|MMR(34)|29                |30, 33            |0   |
|14|MMR(38)|29                |30, 37            |0   |
|15|MMR(16)|                  |14, 15            |1   |
|15|MMR(18)|16                |14, 17            |1   |
|15|MMR(22)|16, 20            |14, 21            |1   |
|15|MMR(25)|16, 20            |14, 21, 24        |1   |
|15|MMR(31)|16, 20, 28, 14    |30                |0   |
|15|MMR(34)|16, 20, 28, 14    |30, 33            |0   |
|15|MMR(38)|16, 20, 28, 14    |30, 37            |0   |
|16|MMR(18)|15                |14, 17            |1   |
|16|MMR(22)|15, 20            |14, 21            |1   |
|16|MMR(25)|15, 20            |14, 21, 24        |1   |
|16|MMR(31)|15, 20, 28, 14    |30                |0   |
|16|MMR(34)|15, 20, 28, 14    |30, 33            |0   |
|16|MMR(38)|15, 20, 28, 14    |30, 37            |0   |
|17|MMR(18)|                  |14, 17            |1   |
|17|MMR(22)|20                |14, 21            |1   |
|17|MMR(25)|20                |14, 21, 24        |1   |
|17|MMR(31)|20, 28, 14        |30                |0   |
|17|MMR(34)|20, 28, 14        |30, 33            |0   |
|17|MMR(38)|20, 28, 14        |30, 37            |0   |
|18|MMR(19)|                  |14, 17, 18        |2   |
|18|MMR(22)|19, 17            |14, 21            |1   |
|18|MMR(25)|19, 17            |14, 21, 24        |1   |
|18|MMR(31)|19, 17, 28, 14    |30                |0   |
|18|MMR(34)|19, 17, 28, 14    |30, 33            |0   |
|18|MMR(38)|19, 17, 28, 14    |30, 37            |0   |
|19|MMR(22)|18, 17            |14, 21            |1   |
|19|MMR(25)|18, 17            |14, 21, 24        |1   |
|19|MMR(31)|18, 17, 28, 14    |30                |0   |
|19|MMR(34)|18, 17, 28, 14    |30, 33            |0   |
|19|MMR(38)|18, 17, 28, 14    |30, 37            |0   |
|20|MMR(22)|17                |14, 21            |1   |
|20|MMR(25)|17                |14, 21, 24        |1   |
|20|MMR(31)|17, 28, 14        |30                |0   |
|20|MMR(34)|17, 28, 14        |30, 33            |0   |
|20|MMR(38)|17, 28, 14        |30, 37            |0   |
|21|MMR(22)|                  |14, 21            |1   |
|21|MMR(25)|                  |14, 21, 24        |1   |
|21|MMR(31)|28, 14            |30                |0   |
|21|MMR(34)|28, 14            |30, 33            |0   |
|21|MMR(38)|28, 14            |30, 37            |0   |
|22|MMR(23)|                  |14, 21, 22        |2   |
|22|MMR(25)|23                |14, 21, 24        |2   |
|22|MMR(31)|23, 27, 21, 14    |30                |0   |
|22|MMR(34)|23, 27, 21, 14    |30, 33            |0   |
|22|MMR(38)|23, 27, 21, 14    |30, 37            |0   |
|23|MMR(25)|22                |14, 21, 24        |2   |
|23|MMR(31)|22, 27, 21, 14    |30                |0   |
|23|MMR(34)|22, 27, 21, 14    |30, 33            |0   |
|23|MMR(38)|22, 27, 21, 14    |30, 37            |0   |
|24|MMR(25)|                  |14, 21, 24        |2   |
|24|MMR(31)|27, 21, 14        |30                |0   |
|24|MMR(34)|27, 21, 14        |30, 33            |0   |
|24|MMR(38)|27, 21, 14        |30, 37            |0   |
|25|MMR(26)|                  |14, 21, 24, 25    |3   |
|25|MMR(31)|26, 24, 21, 14    |30                |0   |
|25|MMR(34)|26, 24, 21, 14    |30, 33            |0   |
|25|MMR(38)|26, 24, 21, 14    |30, 37            |0   |
|26|MMR(31)|25, 24, 21, 14    |30                |0   |
|26|MMR(34)|25, 24, 21, 14    |30, 33            |0   |
|26|MMR(38)|25, 24, 21, 14    |30, 37            |0   |
|27|MMR(31)|24, 21, 14        |30                |0   |
|27|MMR(34)|24, 21, 14        |30, 33            |0   |
|27|MMR(38)|24, 21, 14        |30, 37            |0   |
|28|MMR(31)|21, 14            |30                |0   |
|28|MMR(34)|21, 14            |30, 33            |0   |
|28|MMR(38)|21, 14            |30, 37            |0   |
|29|MMR(31)|14                |30                |0   |
|29|MMR(34)|14                |30, 33            |0   |
|29|MMR(38)|14                |30, 37            |0   |
|30|MMR(31)|                  |30                |0   |
|30|MMR(34)|                  |30, 33            |0   |
|30|MMR(38)|                  |30, 37            |0   |
|31|MMR(32)|                  |30, 31            |1   |
|31|MMR(34)|32                |30, 33            |1   |
|31|MMR(38)|32, 36            |30, 37            |1   |
|32|MMR(34)|31                |30, 33            |1   |
|32|MMR(38)|31, 36            |30, 37            |1   |
|33|MMR(34)|                  |30, 33            |1   |
|33|MMR(38)|36                |30, 37            |1   |
|34|MMR(35)|                  |30, 33, 34        |2   |
|34|MMR(38)|35, 33            |30, 37            |1   |
|35|MMR(38)|34, 33            |30, 37            |1   |
|36|MMR(38)|33                |30, 37            |1   |
|37|MMR(38)|                  |30, 37            |1   |

## Accumulator peak hashes

| i  |accumulator peak(root)|
|:---|---:|
| 0|cd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50|
| 0|d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975|
| 0|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 0|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 0|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 0|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 0|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 0|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 0|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 0|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 0|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 1|d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975|
| 1|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 1|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 1|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 1|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 1|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 1|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 1|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 1|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 1|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 2|d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975|
| 2|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 2|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 2|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 2|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 2|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 2|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 2|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 2|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 2|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 3|8005f02d43fa06e7d0585fb64c961d57e318b27a145c857bcd3a6bdb413ff7fc|
| 3|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 3|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 3|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 3|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 3|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 3|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 3|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 3|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 3|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 4|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 4|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 4|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 4|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 4|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 4|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 4|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 4|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 4|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 5|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 5|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 5|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 5|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 5|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 5|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 5|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 5|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 5|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 6|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 6|a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2|
| 6|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 6|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 6|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 6|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 6|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 6|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 6|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 7|4c0e071832d527694adea57b50dd7b2164c2a47c02940dcf26fa07c44d6d222a|
| 7|8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7|
| 7|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 7|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 7|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 7|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 7|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 7|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 7|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 8|8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7|
| 8|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 8|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 8|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 8|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 8|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 8|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 8|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 9|8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7|
| 9|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 9|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 9|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 9|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
| 9|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 9|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
| 9|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|10|0b5000b73a53f0916c93c68f4b9b6ba8af5a10978634ae4f2237e1f3fbe324fa|
|10|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|10|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|10|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|10|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|10|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|10|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|10|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|11|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|11|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|11|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|11|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|11|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|11|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|11|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|12|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|12|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|12|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|12|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|12|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|12|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|12|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|13|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|13|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|13|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|13|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|13|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|13|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|13|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|14|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|14|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|14|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|14|e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504|
|14|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|14|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|14|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|15|998e907bfbb34f71c66b6dc6c40fe98ca6d2d5a29755bc5a04824c36082a61d1|
|15|5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d|
|15|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|15|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|15|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|15|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|15|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|16|5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d|
|16|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|16|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|16|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|16|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|16|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|17|5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d|
|17|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|17|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|17|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|17|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|17|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|18|1b8d0103e3a8d9ce8bda3bff71225be4b5bb18830466ae94f517321b7ecc6f94|
|18|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|18|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|18|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|18|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|18|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|19|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|19|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|19|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|19|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|19|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|20|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|20|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|20|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|20|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|20|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|21|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|21|7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c|
|21|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|21|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|21|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|22|aed2b8245fdc8acc45eda51abc7d07e612c25f05cadd1579f3474f0bf1f6bdc6|
|22|561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213|
|22|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|22|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|22|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|23|561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213|
|23|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|23|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|23|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|24|561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213|
|24|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|24|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|24|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|25|1209fe3bc3497e47376dfbd9df0600a17c63384c85f859671956d8289e5a0be8|
|25|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|25|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|25|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|26|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|26|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|26|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|27|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|27|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|27|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|28|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|28|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|28|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|29|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|29|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|29|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|30|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|30|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|30|1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b|
|31|707d56f1f282aee234577e650bea2e7b18bb6131a499582be18876aba99d4b60|
|31|4d75f61869104baa4ccff5be73311be9bdd6cc31779301dfc699479403c8a786|
|31|e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785|
|32|4d75f61869104baa4ccff5be73311be9bdd6cc31779301dfc699479403c8a786|
|32|e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785|
|33|4d75f61869104baa4ccff5be73311be9bdd6cc31779301dfc699479403c8a786|
|33|e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785|
|34|0764c726a72f8e1d245f332a1d022fffdada0c4cb2a016886e4b33b66cb9a53f|
|34|e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785|
|35|e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785|
|36|e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785|
|37|e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785|

# References

## Normative References

* [RFC9162]: https://datatracker.ietf.org/doc/html/rfc9162
  [RFC9162]
* [RFC9162_VerInc]:https://datatracker.ietf.org/doc/html/rfc9162#name-verifying-an-inclusion-proo
  [RFC9162_VerInc] 2.1.3.1 Generating an Inclusion Proof
* [RFC9162_VerCon]: https://datatracker.ietf.org/doc/html/rfc9162#name-verifying-consistency-betwe
  [RFC9162_VerCon] 2.1.4.2 Verifying Consistency between Two Tree Heads


## Informative References

* [PeterTodd]: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2016-May/012715.html
  [PeterTodd]
* [CrosbyWallach]: https://static.usenix.org/event/sec09/tech/full_papers/crosby.pdf
  [CrosbyWallach]
* [CrosbySecondaryStorage]: https://static.usenix.org/event/sec09/tech/full_papers/crosby.pdf
  [CrosbySecondaryStorage] 3.3 Storing the log on secondary storage
* [PostOrderTlog]: https://research.swtch.com/tlog#appendix_a
  [PostOrderTlog]
* [KnuthTBT]: https://www-cs-faculty.stanford.edu/~knuth/taocp.html
  [KnuthTBT] 2.3.1 Traversing Binary Trees
* [BNT]: https://eprint.iacr.org/2021/038.pdf
  [BNT]
* [ReyzinYakoubov]: https://eprint.iacr.org/2015/718.pdf
  [ReyzinYakoubov]
* [ProjectSilica]: https://www.tomshardware.com/news/microsoft-repositions-7tb-project-silica-glass-media-as-a-cloud-storage-solution
  [ProjectSilica]

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
