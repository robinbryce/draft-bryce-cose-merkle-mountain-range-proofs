This is a call for the adoption of this draft:

https://datatrails.github.io/draft-bryce-cose-merkle-mountain-range-proofs/

The primary goal of this draft is to meet the extension point registration requirements defined in the [Cose-Merkle-Tree-Proofs](https://www.ietf.org/archive/id/draft-ietf-cose-merkle-tree-proofs-05.html#name-registration-requirements) I-D
for verifiable logs based on the flat-based Merkle tree scheme, popularly known as a "Merkle Mountain Range" (MMR).

Why do we need something other than the binary Merkle tree construction of RFC 6962, as updated by RFC 9162?

In short, because the weight of various trade offs are not uniform accross different transparency use-cases.

Certificate Transparency logs are global in scale and serve to verify elements of global significance.
The incentives to ensure CT logs are well-operated and "checked" are enormous.

For transparency systems involving application data or general transparency, the value of the data assured is much more subjective, depending on individual publishers and consumers.
In heterogeneous situations, such as digital supply chains, the incentives to check and audit are much less clear.

Yet, transparency logs are trustworthy only when they are independently checked and monitored.

I believe that by specifying a verifiable data structure that minimizes the costs and complexities of replicating, auditing, and verifying, the adoption of transparency techniques can be encouraged.
This is especially so in "just in case" situations where the value often becomes evident when it’s already too late.

In the draft, I've highlighted the properties of MMRs that, in my view, have led to their wide adoption in systems that benefit from a highly replicable, prunable, and permanently stable VDS.

The implementation section includes references (though not exhaustive) to several production implementations, with broad similarities between them.
Trigger warning: most of these are "blockchains," but that seems to be fertile ground for testing many useful techniques, and there is certainly a strong incentive to attack them (double meaning intended).

Independent of blockchains, the draft leans heavily on work by Leonid Reyzin and Sophia Yakoubov, particularly their paper on "Efficient Asynchronous Accumulators for Distributed PKI" -- https://eprint.iacr.org/2015/718.pdf.

Their work provides a formal model that applies to the emergent benefits of MMRs, which is particularly important for the formulation of proofs of inclusion and consistency specified in the draft.

I should note that while I’ve made Leonid and Sophia aware of this draft, and they confirmed that the basic link between MMRs and their work makes sense, they have not reviewed the draft or otherwise endorsed it.

On a more personal note, this draft is the one I wish had been available when I first became convinced that MMRs were a great fit for more application-centric, "eye of the beholder-valued" transparency use cases.
It is also the result of poring over various implementations and considering which, if any, differences mattered.

Here are 6 properties that I think particularly help lower the barrier to ensuring trustworthy transparency systems:

1. Immediate replication after element addition is safe; the log data does not change after addition.

While regular checkpoints and consistency proofs can be requested for any Merkle-based log, being able to instantly replicate the VDS data puts the verifier in control of the frequency and granularity of verification.
Since each replicated (and attested) log is as reliable as the original, this can also significantly improve scalability.

2. "Old," no longer interesting, log data can be discarded.

Historic sections of the log can be removed easily.
Verification of newer data relies only on the "peaks" from the historic data, which are trivially available in any consistency proof or from the (easily) replicated log data.

3. Individual receipts are not strictly necessary.

With classic binary trees, each addition produces a unique Merkle Tree Head, requiring a unique signature from the transparency service.
MMRs, however, use the peaks of adjacent perfect binary trees.
While these peaks are merged as the tree evolves, they never move in storage and serve as a permanent commitment to all elements included before them.
Proof paths terminate at peaks, and while the peaks may be "buried" when they merge, the proof path for any single element simply grows longer.

This means a single signature over the peaks of the MMR attests to the full history of events added before those peaks.
Any proof path that reproduces one of these peaks is covered by the same signature.

This property is particularly useful where relying parties are forced to retain receipts for everything they add, and they are the dominant contributor to the log.
In cases where the application is an intermediary, it may not be able to determine whether individual entries in the transparency service are significant, and so it must retain receipts for everything.
An attested replica of the verifiable log can be significantly less cumbersome than maintaining individual receipts.

4. Appending to the log can be coordination-free.

Adding to the log is strictly append-only, and the data organization is linear.
This means that the HTTP_ETag style of optimistic concurrency, commonly supported by cloud vendor object stores, is sufficient to handle competing writers.

5. Old proofs remain consistent with all future proofs.

In many cases, it’s important to know that an element is both included and continues to be included at the same position.
This property (related to the "old accumulator compatibility" in the paper mentioned above) allows a relying party to be offline indefinitely.
Upon returning, they can request a new proof of inclusion for the same element to confirm that it remains in the same position.
If the old proof data is not a strict prefix of the new proof data, the log has been inconsistently updated, and the element has moved.

With MMRs, this is particularly convenient and requires no specialized actions to achieve this.

6. Elements can be verified without revealing the item of interest.

When bounded replication is simple, the verifier can maintain a local window on the log, eliminating the need to contact the log operator for every verification. Because the verifiable log is highly replicable, elements can be verified without disclosing the item of interest to the log operator. The linear, addition-ordered nature of the log allows the verifier to maintain a local "window" on the replicated log, discarding sections as they are no longer needed.

These points are not exhaustive, but hopefully they are enough to spark interest in discussing the merits of this draft.
Given that this is an "author's first draft," there is undoubtedly room for improvement in terms of form, content, and syntax. I’m very open to feedback and contributions on that front.

In the meantime, do you think there’s enough here to justify the time and attention needed to take it forward?

Best Regards,
Robin Bryce
