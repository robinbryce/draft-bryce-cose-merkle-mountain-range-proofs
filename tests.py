"""
See the notational conventions in the accompanying draft text for definition of short hand variables.
"""
import unittest

from typing import List

from algorithms import inclusion_proof_path, included_root
from algorithms import consistency_proof_paths, consistent_roots
from algorithms import consistent_roots
from algorithms import verify_consistent_roots
from algorithms import verify_inclusion_path
from algorithms import mmr_index
from algorithms import index_height
from algorithms import proves_peak, proves_index_peak
from algorithms import accumulator_index
from algorithms import peaks
from algorithms import peak_depths
from algorithms import leaf_count
from algorithms import parent
from algorithms import complete_mmr

from tableprint import complete_mmr_sizes, complete_mmr_indices
from tableprint import leaf_peak_witnesses, leaf_index_peak_witnesses
from tableprint import peaks_table
from tableprint import index_values_table
from tableprint import inclusion_paths_table

from db import KatDB, FlatDB


class TestIndexOperations(unittest.TestCase):
    """
    Tests for the various algorithms that work on mmr indexes and leaf indexes,
    with out reference to a materialized tree.
    """

    def test_index_heights(self):
        """The heights calculated for each mmr index are correct"""

        expect = [
            0, 0, 1, 0, 0, 1, 2, 0, 0, 1, 0, 0, 1, 2, 3, 0, 0, 1, 0, 0,
            1, 2, 0, 0, 1, 0, 0, 1, 2, 3, 4, 0, 0, 1, 0, 0, 1, 2, 0 ]

        heights = index_values_table(mmrsize=39)[0]

        for i in range(39):
            self.assertEqual(heights[i], expect[i])

    def test_index_leaf_counts(self):
        """The leaf counts calculated for each mmr index are correct"""

        expect = [ 1, 1, 2, 3, 3, 3, 4, 5, 5, 6, 7, 7, 7, 7, 8, 9, 9, 10, 11,
                  11, 11, 12, 13, 13, 14, 15, 15, 15, 15, 15, 16, 17, 17, 18, 19, 19, 19, 20, 21 ]

        leaf_counts = index_values_table(mmrsize=39)[1]

        for i in range(39):
            self.assertEqual(leaf_counts[i], expect[i])

    def test_proves_peak(self):
        """Test the path lengths which prove an accumulator peak are distinguished
        
        from those that prove an interior"""
        for e in range(len(leaf_peak_witnesses)):
            for d in range(len(leaf_peak_witnesses[e])):
                expect = leaf_peak_witnesses[e][d] == 1
                self.assertEqual(proves_peak(e, d), expect)

    def test_proves_index_peak(self):
        """Test the path lengths which prove an accumulator peak are distinguished
        
        from those that prove an interior, and that the peak index for the path is obtained"""
        for e in range(len(leaf_index_peak_witnesses)):
            for d in range(len(leaf_index_peak_witnesses[e])):

                i = mmr_index(e)
                (expect_index, expect_is_peak) = leaf_index_peak_witnesses[e][d]
                expect_is_peak = expect_is_peak == 1
                (index, is_peak) = proves_index_peak(i, d)
                self.assertEqual(index, expect_index)
                self.assertEqual(is_peak, expect_is_peak)


class TestAddLeafHash(unittest.TestCase):

    def test_add(self):
        """The dynamically created db matches the canonical known answer db"""
        db = FlatDB()
        db.init_canonical39()

        katdb = KatDB()
        katdb.init_canonical39()
        for i in range(len(db.store)):
            self.assertEqual(db.store[i], katdb.store[i])

    def test_addleafhash(self):
        """Adding the 21 canonical leaf values produces the canonical db"""
        katdb = KatDB()
        katdb.init_canonical39()
        db = FlatDB()
        db.init_size(39)

        for i in range(39):
            self.assertEqual(
                db.store[i],
                katdb.store[i],
                "node %d != %s (%s)" % (i, katdb.store[i], db.store[i]),
            )

    def test_addleafhash_accumulators(self):
        """Adding the 21 canonical leaf values produces the expected accumulators for each  mmr size"""

        expect = [
            [0, "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc"],
            [2, "ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8"],
            [
                3,
                "ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8",
                "d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975",
            ],
            [6, "827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88"],
            [
                7,
                "827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88",
                "a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2",
            ],
            [
                9,
                "827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88",
                "b8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d",
            ],
            [
                10,
                "827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88",
                "b8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d",
                "8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7",
            ],
            [14, "78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112"],
            [
                15,
                "78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
                "e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504",
            ],
            [
                17,
                "78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
                "f4a0db79de0fee128fbe95ecf3509646203909dc447ae911aa29416bf6fcba21",
            ],
            [
                18,
                "78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
                "f4a0db79de0fee128fbe95ecf3509646203909dc447ae911aa29416bf6fcba21",
                "5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d",
            ],
            [
                21,
                "78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
                "61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710",
            ],
            [
                22,
                "78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
                "61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710",
                "7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c",
            ],
            [
                24,
                "78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
                "61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710",
                "dd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae",
            ],
            [
                25,
                "78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
                "61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710",
                "dd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae",
                "561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213",
            ],
            [30, "d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7"],
            [
                31,
                "d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
                "1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b",
            ],
            [
                33,
                "d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
                "0c9f36783b5929d43c97fe4b170d12137e6950ef1b3a8bd254b15bbacbfdee7f",
            ],
            [
                34,
                "d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
                "0c9f36783b5929d43c97fe4b170d12137e6950ef1b3a8bd254b15bbacbfdee7f",
                "4d75f61869104baa4ccff5be73311be9bdd6cc31779301dfc699479403c8a786",
            ],
            [
                37,
                "d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
                "6a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa",
            ],
            [
                38,
                "d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
                "6a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa",
                "e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785",
            ],
        ]
        db = FlatDB()
        db.init_size(39)

        peak_indices_table = peaks_table()
        peak_values_table = peaks_table(db)

        for i in range(len(complete_mmr_sizes)):
            peak_indices = peak_indices_table[i]
            peak_values = peak_values_table[i]
            expect_complete_mmr, expect_values = (expect[i][0], expect[i][1:])
            for j, p in enumerate(peak_indices):
                self.assertEqual(complete_mmr_sizes[i]-1, expect_complete_mmr)
                self.assertEqual(db.store[p].hex(), peak_values[j])
                self.assertEqual(db.store[p].hex(), expect_values[j])


class TestVerifyInclusion(unittest.TestCase):

    def test_check_inclusion_proof_validity(self):
        """Test that the proposed proof for a leaf can be tested for memership in an accumulator"""

        # Many accumulators may contain the peak committing the leaf

        db = KatDB()
        db.init_canonical39()

        for e in range(21):
            # A proof for leaf 0 in MMR(39) is 4 elements long
            i = mmr_index(e)
            path_lengths = []
            for g in range(5):
                # is i + g a complete mmr ? if so, g is a valid proof length

                h0 = index_height(i)
                h1 = index_height(i + 1)
                if h0 == h1:
                    path_lengths.append(g)
            print(f"{i}: {path_lengths}.join(',')")


    def test_verify_inclusion(self):
        """Every node can be verified against an accumulator peak for every subsequent complete MMR size"""
        # Hand populate the db
        db = KatDB()
        db.init_canonical39()

        # Show that inclusion_proof_path verifies for all complete mmr's which include i
        for i in range(39):
            ix = complete_mmr(i)
            ei = leaf_count(i)
            while ix < 39:
                # typically, the size, accumulator and paths will be givens.
                accumulator = [db.get(ip) for ip in peaks(ix)]
                path = [db.get(isibling) for isibling in inclusion_proof_path(i, ix)]

                e = leaf_count(ix)

                # for leaf nodes, the peak height is len(proof) - 1,
                # for interiors, we need to take into account the height of the node.
                g = len(path) + index_height(i)

                # the next time a merge equals or excedes g
                # valid accumulator paths of length g will only ever have a new peak equal g, others will be greater


                r0 = ei // (1 << g)
                r1 = (ei+(1<<g)) // (1 << g)
                m0 = ei % (1 << g)
                m1 = (ei+(1<<g)) % (1 << g)

                enext = ei + (1 << g) - (ei % (1 << g))

                if i == 1 and g ==2:
                    # print('1')
                    pass

                if (i == 7 or i == 8 or i == 10 or i == 11): # and g >=2:
                    print(f"xx: {i} {ix} {g} {enext - 1} {mmr_index(enext - 1)}")
                iacc = accumulator_index(e, g)

                ok, pathconsumed = False, 0

                (ok, pathconsumed) = verify_inclusion_path(
                    i, db.get(i), path, accumulator[iacc]
                )
                self.assertTrue(ok)
                self.assertEqual(pathconsumed, len(path))

                ix = complete_mmr(ix + 1)


    def test_verify_inclusion_all_mmrs(self):
        """Every inclusion proof for every node proves the expected peak root"""
        db = KatDB()
        db.init_canonical39()

        table = inclusion_paths_table(39)
        for (i, e, s, pathindices, ai, accumulator) in table:
            root = db.get(accumulator[ai])
            node = db.get(i)
            path = [db.get(ip) for ip in pathindices]
            (ok, pathlen) = verify_inclusion_path(i, node, path, root)
            self.assertTrue(ok)
            self.assertEqual(pathlen, len(path))


    def test_verify_included_root_all_mmrs(self):
        """Every inclusion proof for every node proves the expected peak root"""
        db = KatDB()
        db.init_canonical39()

        table = inclusion_paths_table(39)
        for (i, e, s, pathindices, ai, accumulator) in table:
            root = db.get(accumulator[ai])
            node = db.get(i)
            path = [db.get(ip) for ip in pathindices]
            proven = included_root(i, node, path)
            self.assertEqual(root, proven)


class TestVerifyConsistency(unittest.TestCase):

    def test_verify_consistent_roots(self):
        """Consistency proofs of arbitrary MMR ranges verify"""
        # Hand populate the db
        db = KatDB()
        db.init_canonical39()

        for (i, ito) in enumerate(complete_mmr_indices):

            for ifrom in complete_mmr_indices[:i]:

                iproofs = consistency_proof_paths(ifrom, ito) 

                proofs = [[db.get(ii) for ii in path] for path in iproofs]

                accumulatorfrom = [db.get(ii) for ii in peaks(ifrom)]
                toaccumulator = [db.get(ii) for ii in peaks(ito)]

                ok = verify_consistent_roots(ifrom, accumulatorfrom, toaccumulator, proofs)
                self.assertTrue(ok)


    def test_consistent_roots(self):
        """Consistency proofs of arbitrary MMR ranges verify"""
        # Hand populate the db
        db = KatDB()
        db.init_canonical39()

        for (i, ito) in enumerate(complete_mmr_indices):

            for ifrom in complete_mmr_indices[:i]:

                proofs = [[db.get(i) for i in path] for path in consistency_proof_paths(ifrom, ito)]

                accumulatorfrom = [db.get(i) for i in peaks(ifrom)]
                topeakindices = peaks(ito)
                toaccumulator = [db.get(i) for i in topeakindices]

                # If all proven nodes match an accumulator peak for MMR(ito) then
                # MMR(ifrom) is consistent with MMR(ito). Because both the peaks and
                # the accumulator peaks are listed in descending order of height
                # we can do this with a linear scan.
                proven = consistent_roots(ifrom, accumulatorfrom, proofs)
                numvalid = 0
                iacc = 0
                for root in proven:
                    if toaccumulator[iacc] == root:
                        numvalid += 1
                        continue
                    iacc += 1
                    if iacc >= len(toaccumulator):
                        break
                    if toaccumulator[iacc] != root:
                        break
                    numvalid += 1

                self.assertEqual(numvalid, len(proven))


    def test_consistent_root_proof_depths(self):
        """Consistency proof lengths can be used to select the proven accumulator entry"""

        # Hand populate the db
        db = KatDB()
        db.init_canonical39()

        for (i, ito) in enumerate(complete_mmr_indices):

            for ifrom in complete_mmr_indices[:i]:

                proofs = [[db.get(i)for i in path] for path in consistency_proof_paths(ifrom, ito)]

                peakindicesfrom = peaks(ifrom)
                accumulatorfrom = [db.get(i) for i in peakindicesfrom]
                toaccumulator = [db.get(i) for i in peaks(ito)]

                accumulatordepths = dict((d, i) for (i, d) in enumerate(peak_depths(ito)))

                # The proofs start at the from accumulator peaks. The height of
                # the future peak that commits them is the height of the old
                # peak plus the length of the inclusion proof against the future
                # accumulator.  And that height indexes the sparse accumulator.
                # The accumulatordepths map is a lookup from sparse to packed
                # accumulator indices.

                proven = consistent_roots(ifrom, accumulatorfrom, proofs)
                for (iproof, root) in enumerate(proven):

                    d = len(proofs[iproof]) + index_height(peakindicesfrom[iproof])
                    self.assertTrue(d in accumulatordepths)
                    self.assertEqual(toaccumulator[accumulatordepths[d]], root)

class TestWitnessUpdate(unittest.TestCase):

    def test_witness_update(self):
        """Each witness is a prefix of all future witnesses for the same node"""

        db = KatDB()
        db.init_canonical39()

        mmrsize = 39

        for iw in range(mmrsize):

            wits = []
            ito = complete_mmr(iw+1)

            while ito < mmrsize:

                w = inclusion_proof_path(iw, ito)
                if not wits:
                    wits.append(w)
                    continue

                self.assertGreaterEqual(len(w), len(wits[-1]))
                # The old witness is a strict subset of the new witness
                self.assertEqual(wits[-1], w[: len(wits[-1])])

                # check that the previous witness is updated by the inclusion
                # proof for its previous accumulator root. The previous
                # accumulator root for any proof is the parent of the last
                # witness in the path.

                ioldroot = len(wits[-1]) and parent(wits[-1][-1]) or iw

                wupdated = wits[-1] + inclusion_proof_path(ioldroot, ito)

                self.assertEqual(wupdated, w)

                wits.append(w)

                ito = complete_mmr(ito+1)


if __name__ == "__main__":
    unittest.main()
