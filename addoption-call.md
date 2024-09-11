This is a call for the adoption of this draft

https://datatrails.github.io/draft-bryce-cose-merkle-mountain-range-proofs/

The primary goal of this draft is to meet the requirements of extension point registration defined in this I-D

https://www.ietf.org/archive/id/draft-ietf-cose-merkle-tree-proofs-05.html#name-registration-requirements

for verifiable logs based on the flat base merkle tree scheme known popularly as a "Merkle Mountain Range".

Why do we need anything other than the binary merkle tree construction of RFC 6962 and updated by RFC 9162 ?

In short, because the weight of various trade offs are not uniform accross different transparency use-cases.

Certificate Transparency logs are global in scale and serve to verify elements of global significance.
The incentives to ensure CT logs are well operated and "checked" are enourmous.

For systems of transparency for application data, general transparency, the value of the data assured is much more in the eye of the individual publisher/consumer's.
In heterogenous situatations, such as digital supply chains, the incentives to check and audit are much less clear.

And yet, transparency logs are assured to be trustworthy only by being independently checked and monitored.

I beleive that by specifying a verifiable data structure which minimises the costs and complexities of replicating, auditing, and verifying, the adoption of transparency teqhniques is encouraged.
This is especially so in the "just incase" situation where the value is often evident when it is already too late.

In the draft, I've highlighted the properties of MMR's which, in my view, has lead to their wide adoption in systems that benefit from a highly replicable, prunable and permanently stable VDS.
The implementations section has (non exhaustive) references for a number of production implementations. There are broad similarities between those.
Trigger warning, admitedly they are mostly "blockchains", but that seems to me to be a fertile proving ground for many useful techniques and certainly there is significant incentive to attack them (double meanings intended).

Indpendent of blockchains, the draft leans heavily on work by Leonid Reyzin and Sophia Yakoubov and their paper on "Efficient Asynchronous Accumulators
for Distributed PKI" -- https://eprint.iacr.org/2015/718.pdf

This work provides a formal model which is applicable to the emergent benefits of MMR's, and is particularly important to the formulation for proofs of inclusion and consistency specified in the draft.

I should note that while I've made Loenid and Sophia aware of this draft, and they confirmed the basic link between MMR's and their work makes sense, they have not reviewed the draft or otherwise endorsed it.

On a personal note, this draft is the one I wish was available when I became convinced that MMR's were a great fit for more application centric, "eye of the beholder valued", transparency use cases.
In part, it is also the result of poring over those implementations and deciding which, if any, differences in those implementations mattered.

In the hope that it widens the audience, and interest, in discussing the merits of this draft, here are 5 properties which I feel actively lower the barier for ensuring trustworthy  transparency systems:

1. Immediate replication after element addition is safe, the log data will not change after addition.

While regular checkpoints and consistency proofs can be requested for any merkle based log,
being able to instantly replicate the VDS data puts the verifier in complete control over the frequency and granularity of verification.
As each replicated (and attested) log is as good as the original, this can also significanly improve scalability of verification.


2. "Old", no longer interesting, log data can be discarded

Historic sections of the log can be removed easily.
Verification of newer data relies only on the "peaks" from the historic data, and those are trivialy available in any consistency proof or from the (easily) replicated log data.

3. Individual receipts are not strictly necessary.

With classic binary trees, every addition produces a unique Merkle Tree Head, and so every receipt requires a unique signature from the transparency service.
With MMR's there are the peaks of adjacent perfect binary trees.
While those get "merged" as the tree evolves, they never move in storage, and they are a permanent commitment to all elements included before them.
Proof paths terminate at peaks. While peaks get "burried" when they merge, the proof path for any single element simply gets longer.

This means a single signature over the "peaks" of the MMR attests to the full history of events added before those peaks.
Any proof path that reproduces one of those peaks is covered by the same signature.

This property is particularly significant where relying parties are, in effect, forced to retain receipts for everything they add, *and* they are the dominant contributor to the log.

With a single, globaly significant, log individual relying parties are a tiny proportion of the log.
For application transparency logs the common case is the opposite: all, or at least most, entries are typically valuable for the relying party, the publisher or both.
In cases where the application is an intermediary it can not typically tell whether indivdual entries on the transparency service are interesting, and so it needs to retain receipts for everything.

At which point an attested replica of the verifable log becomes significantly less cumbersome than maintaining copies of individual receipts.

4. Appending to the log can be co-ordination free

Adding to the log is strictly append only and the data organisation is linear.
This means that the [HTTP_ETag](https://en.wikipedia.org/wiki/HTTP_ETag) style of optimistic concurrence, commonly supported by cloud vendor object stores, is sufficient to deal with competing writers.

5. Old proofs are consistent with all future proofs

In many cases it is important to know both that an element is included *and* that it continues to be included at the same position.
This property (which is related to the "old accumulator compatibility in the paper above) allows a relying party to be off line indefinitely.
Later, comming back online, they can prove the log continues to include the element at the same position as previously shown by requesting a new proof of inclusion for the same element.
If the old proof data is not a strict prefix of the new proof data, the log has been inconsistently updated and the element has moved.

There are many ways this can be shown for various VDS's. With MMR's it is particularly convenient and requires no actions specialised to that goal.

6. Elements can be verified without revealing the item of interest.

When bounded replication is simple to accomplish, the verfier can maintain a local window on the log that makes it un-necessary to contact it for every verification.
Because the verifiable log is highly replicable, elements can be verified without revealing the item of interest to the log operator.
The linear, addition ordered, nature of the log means a verifier can simply maintain a local "window" on the replicated log, discarding sections that are no longer needed.

For certain, especialy as this is an "authors first draft", there is a journey to be made for this draft in in form, contenent and syntax.
I'm very happy to take direction and contributions to that effect.

But in the mean time, do people feel there enough here to justify the time and attention that would be needed to take it forward ?

Best Regards,

Robin Bryce





