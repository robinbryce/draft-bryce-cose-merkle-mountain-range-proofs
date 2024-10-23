Considering https://research.swtch.com/tlog

from 'We still need to be able to write an efficient proof that the log of size N with tree hash T is a prefix of the log of size N'


2-d tree

```
 4                            x1
 3              y1  0                x0
                         y0
 2          0               1                2
 1      0       1       2       3       4        5
 0    0   1   2   3   4   5   6   7   8   9   10  11  12
```

`T = y1`, the MTH for leaf count 7
`T' = x1`, the MTH for leaf count 13

`T7	= H(h(2, 0), H(h(1, 2), h(0, 6)))`

```
T13 = H(h(3, 0), H(h(2, 2), h(0, 12)))
    = H(H(h(2, 0), h(2, 1)), H(h(2, 2), h(0, 12)))
    = H(H(h(2, 0), H(h(1, 2), h(1, 3))), H(h(2, 2), h(0, 12)))
    = H(H(h(2, 0), H(h(1, 2), H(h(0, 6), h(0, 7)))), H(h(2, 2), h(0, 12)))
```

1-d BNT/MMR

```
    4                         30


    3              14                       29
                  / \
                 /   \
                /     \
               /       \
              /         \
    2        6           13            21             28
           /   \        /   \        /    \
    1     2     5      9     12     17     20     24       27
         / \   / \    / \   /  \   /  \   /  \
    0   0   1 3   4  7   8 10  11 15  16 18  19 22  23   25   26

    .   0   1 2   3  4   5  6   7  8   9 10  11 12  13   14   15 e
```


```
level 0

(0, 0), (0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (0, 6), (0, 7), (0, 8), (0, 9), (0, 10), (0, 11), (0, 12),
    0 ,     1 ,     3 ,     4 ,     7 ,     8 ,    10 ,    11 ,    15 ,    16 ,     18 ,     19 ,     22,

level 1
     (1, 0),       (1, 1),         (1, 2),         (1, 3),         (1, 4),          (1, 5),
         2 ,           5 ,             9 ,            12 ,            17 ,            20,

level 2
            (2, 0),                       (2, 1),                          (2, 2),
                6 ,                          13 ,                             21,

level 3
                         (3, 0),
                            14 ,
```


`T7	= H(h(2, 0), H(h(1, 2), h(0, 6))) = H(h(6), H(h(9), h(10)))`

```
T13 = H(h(3, 0), H(h(2, 2), h(0, 12)))
     > H(h(14), H(h(21), h(22)))
     = H(H(h(2, 0), h(2, 1)), H(h(2, 2), h(0, 12)))
     > H(H(h(6),      h(13)), H(h(21),   h(22)))
     = H(H(h(2, 0), H(h(1, 2), h(1, 3))), H(h(2, 2), h(0, 12)))
     > H(H(h(6), H(h(9), h(12))), H(h(21), h(22)))
     = H(H(h(2, 0), H(h(1, 2), H(h(0, 6), h(0, 7)))), H(h(2, 2), h(0, 12)))
     > H(H(h(6), H(h(9), H(h(10), h(11)))), H(h(21), h(22)))
```

```
    4                         30


    3             [14]                      29
                  / \
                 /   \
                /     \
               /       \
              /         \
    2       (6)          (13)         [21]            28
           /   \        /   \        /    \
    1     2     5     (9)   (12)    17     20     24       27
         / \   / \    / \   /  \   /  \   /  \
    0   0   1 3   4  7   8 (10)(11)15  16 18  19[22]  23   25   26

    .   0   1 2   3  4   5  6   7  8   9 10  11 12  13   14   15 e
```

The only divergence is how the peaks are combined, and that is somewhat arbitrary.

Attesting peak lists directly, as an array of hashes in
hieght decending order, seems to offer worth while benefits to witness holders
which are described in this work:
https://eprint.iacr.org/2015/718.pdf

For inclusion proofs, the relevant signed peak is computable from the path length.