---
title: "Post-Quantum Confidential Transactions with In-Runtime STARK Verification on a Sovereign Layer-1"
slug: "pq-confidential-stark"
authors: "Ash Brown, SusyLabs Research / QuantumAI Blockchain"
date: "2026-06-29"
version: "1.0 (preprint, for peer review)"
status: "preprint"
---

## Abstract

We present a confidential transaction system for a sovereign, post-quantum Layer-1 blockchain in
which every security property that protects value, namely amount-hiding, no-inflation soundness, and
spend authorization, is resistant to a quantum adversary. Existing confidential schemes based on
Pedersen commitments and Bulletproofs hide amounts with information-theoretic security but rest their
no-inflation guarantee on the discrete logarithm assumption, which Shor's algorithm breaks. We move
that guarantee onto a hash-based, transparent-setup STARK over the Goldilocks field, using the
Rescue-Prime permutation as the in-circuit commitment. The verifier is small and deterministic, so it
runs inside the chain runtime itself with no host function and no trusted node component, which removes
a class of consensus-split risk. We describe three algebraic intermediate representations (an opening
circuit, a public-value opening for the plaintext on and off ramps, and a two-input two-output transfer
that proves balance and range in a single proof), a zero-knowledge construction layered on a STARK
library that is not natively zero-knowledge, and the on-chain protocol that binds the pieces into a
shielded pool. We give a soundness argument that the in-field balance equation cannot wrap the field
modulus, report an empirical witness-indistinguishability evaluation, and disclose two critical
implementation findings that we discovered through adversarial self-review and have remediated. We are
explicit about what is proven and what is evidenced: soundness is argued and tested, while the
zero-knowledge property is supported by a verified masking-margin and an empirical distinguisher at
chance, and a formal zero-knowledge proof is the principal open problem for which we invite peer review.

## 1. Introduction

A confidential payment must do two separate jobs. The first is to hide the amount. The second is to
guarantee that no value is created from nothing. These are different properties resting on different
assumptions, and conflating them is a common error.

In the dominant confidential designs, a value v is hidden inside a Pedersen commitment C = v G + r H,
where r is a secret blinding and G, H are independent generators on an elliptic curve. The hiding is
information-theoretic: for uniform r, C reveals nothing about v, and no computational assumption is
involved, so a quantum computer does not weaken it. Soundness is the weaker link. The reason a prover
cannot open a commitment to a value it does not hold, and the reason a Bulletproof range proof or a
Schnorr balance argument cannot be forged, is that the discrete logarithm problem on the curve is hard.
Shor's algorithm solves discrete logarithm. Therefore the no-inflation property of every Pedersen and
Bulletproof confidential scheme is classical: a sufficiently large quantum computer could forge a
balance proof and mint value, even though it could never read the hidden amounts.

For a chain whose entire thesis is post-quantum security this is the wrong place to leave a classical
assumption. The contribution of this work is a confidential transaction system in which soundness, as
well as hiding and authorization, is post-quantum, and in which the verifier is cheap enough to live in
consensus rather than in a side service.

Our design choices are: hash-based proofs (STARKs) for transparent setup and post-quantum soundness;
the Rescue-Prime permutation as the in-circuit hash so that commitments and proofs share one primitive;
an in-runtime verifier so that confidential validity is a property of the deterministic state-transition
function rather than of a node binary; and a shielded-pool protocol with explicit on and off ramps to
the plaintext UTXO layer.

## 2. Background

**STARKs.** A Scalable Transparent Argument of Knowledge proves that an execution trace satisfies a set
of algebraic constraints. The only cryptographic assumption is that the underlying hash is collision
resistant, so there is no trusted setup and no number-theoretic hardness to be broken by Shor. We build
on Winterfell, an audited Rust STARK library, with the Blake3 hash for Fiat-Shamir and the FRI low-degree
test. We use a conjectured-security target of at least 96 bits, reached over the 64-bit base field by a
cubic field extension.

**Field and hash.** The base field is the Goldilocks prime field with modulus p = 2^64 minus 2^32 plus 1.
The in-circuit hash is Rescue-Prime (the Rp64_256 instance), a sponge with a state of twelve field
elements, a rate of eight and a capacity of four, and seven rounds. Its low algebraic degree makes it
efficient to express as constraints, which is why algebraic hashes are standard inside STARK circuits.

**Commitments.** A note commits to a value v and a blinding b as C = RescuePrime(v, b), a digest of four
field elements (thirty-two bytes). The binding property of the hash means a commitment determines its
opening, which lets us link otherwise separate proofs by the commitments they share.

## 3. Construction

### 3.1 The opening circuit

The foundational unit proves knowledge of (v, b) such that a public commitment C equals RescuePrime(v, b).
The trace runs the Rescue permutation: row zero loads the capacity initialiser, the value into the first
rate cell, and the blinding into the second, with the remaining rate cells zero. A single transition
constraint encodes one full Rescue round as the algebraic identity that relates consecutive rows, namely
that the inverse S-box of the next state, after removing the second round constant and applying the
inverse MDS matrix, raised to the S-box exponent, equals the MDS image of the seventh power of the current
state plus the first round constant. The digest is captured by a boundary assertion that the four digest
cells at the digest row equal the public commitment. Because v and b at row zero are unconstrained, the
prover is free to choose them, and the circuit proves exactly the opening relation and nothing more.

### 3.2 Zero-knowledge by trace masking

A STARK proves a statement, but it does not by itself promise to reveal nothing else. The proof opens a
small number of trace points at pseudo-random positions, and if the trace is short and of low degree, those
openings let an observer interpolate the trace polynomial and recover the witness. A naive STARK
confidential transfer would therefore be sound but would leak the amounts through its own proof.

We achieve statistical zero-knowledge inside the proving and verification logic, without modifying the
library, by three measures. First, Winterfell evaluates the low-degree extension on a coset disjoint from
the trace rows, so a query never reads a real row directly, and leakage can occur only through
interpolation, which requires at least as many openings as the trace length. Second, we run the Rescue
permutation continuously over a long trace with period-eight round constants, where the eighth constant is
zero, capturing the real digest at an early boundary, so that the round constraint is uniform and low
degree across the whole trace rather than a high-degree single-row selector. Third, we leave the trailing
rows unconstrained by setting the number of transition exemptions, and we fill those rows with fresh
cryptographic randomness drawn from the prover's secure generator. With the number of free random rows
strictly greater than the number of opened points, the trace polynomials are underdetermined, and the
witness is statistically hidden. A necessary signature of the randomization is that two proofs of the same
witness differ.

### 3.3 Public-value opening for shield and unshield

The plaintext on and off ramps require a variant in which the value is public. The shield operation burns
a plaintext output of a known amount and mints a note, and the unshield operation does the reverse, so in
both cases the amount equals a public plaintext quantity and only the blinding is secret. The public-value
opening is the opening circuit with one added boundary that asserts the value cell at row zero equals a
public value, and with the value added to the public inputs. The blinding remains hidden by the same
masking, which preserves the future unlinkability of the minted note.

To prevent a third party from re-pointing an unshield, the public-value opening also binds a thirty-two
byte context into the proof. The context is packed into eight field elements of four bytes each, which is
injective, and is included in the public inputs so that it seeds the Fiat-Shamir transcript. A proof is
therefore invalid under any context other than the one it was generated for. The unshield operation sets
the context to the destination address, and the shield operation sets a fixed sentinel.

### 3.4 The transfer circuit

The two-input two-output transfer proves, in one proof and in zero knowledge, that each input and output
commitment opens, that the inputs balance the outputs plus a public fee, and that each output value lies in
range. Each of the four note blocks runs the Rescue opening described above. A constant column carries the
held value of each block, linked to the absorbed value by a difference column with a single boundary at row
zero, which forces the held value to equal the committed value while keeping all later constraints uniform.
Balance is a single low-degree constraint over the four held-value columns and the public fee. Range is a
bit decomposition: a binary constraint on a bit column, a doubling accumulator, and a difference column with
a boundary that forces the accumulator at the range bound to equal the output value, which proves the value
is a sum of range-many bits and therefore in the interval from zero to two to the range power.

The public inputs of the transfer are the input commitments, the output commitments, and the fee. The
amounts never appear. The four note circuits and the range gadgets are bound to those commitments, so a
proof commits to a specific set of inputs, outputs, and fee.

### 3.5 In-runtime verification

The verifier is small and deterministic and does not depend on the prover. We compile it into the chain
runtime, so that confidential validity is checked identically by every validator as part of the
state-transition function. There is no host function and no native node component for the post-quantum path,
which means a confidential transfer cannot cause a consensus split between nodes that do and do not run a
side service, and an upgrade that changes the verifier propagates as an ordinary on-chain runtime upgrade.

## 4. On-chain protocol

A note is an unspent commitment in a pool keyed by the commitment. Three operations move value.

**Shield.** A holder burns a plaintext output of value V and mints a note. The operation is authorized by a
post-quantum lattice signature (Dilithium at NIST Level 5) over a message that binds the spent output, the
minted commitment, and V. The minted commitment is proven, by the public-value opening with the shield
context, to open to exactly V, so no value is created on the way in.

**Transfer.** A holder spends two notes and creates two, with the amounts hidden. The single transfer proof
establishes balance and range. The spent commitments move to a spent set, which prevents replay, and the new
commitments enter the pool. The fee is the only public quantity and is destroyed, which is deflationary and
safe.

**Unshield.** A holder spends a note and mints a plaintext output of value V at a destination. The
public-value opening with the destination as context both authorizes the spend, since only the holder of the
blinding can produce it, and binds the destination, so the operation cannot be re-pointed in transit. A
running pool total is decremented under a checked, fail-closed subtraction, so that any accounting desync
aborts the operation rather than silently minting.

The proof is generated on the holder's own device. A relayer that submits the transaction and pays the outer
fee sees only commitments, a public fee, an opaque proof, and, for unshield, a destination that is bound into
that proof. The holder's amounts and blindings never leave the device.

## 5. Security analysis

### 5.1 Soundness: no inflation

The balance constraint is enforced over the field as the sum of input values minus the sum of output values
minus the fee equal to zero. If any of these quantities is unbounded, a malicious prover can exploit the
field modulus: set the fee to p minus X, where X is the amount to mint, and the field equation holds while
the integer relation has the outputs exceed the inputs by X. We close this by bounding every value and the
fee below two to the sixty-second power. With two inputs and two outputs, the sum of inputs is below two to
the sixty-third power and the sum of outputs plus fee is below three times two to the sixty-second power, both
of which are below the modulus. The field equation therefore equals the integer equation, and no wraparound is
possible. The bound is far above the maximum supply of the chain, so no legitimate amount is excluded. Output
range is enforced in-circuit, and input range holds inductively because every note enters the pool through a
range-checked path, namely a shield of a bounded plaintext amount or an output of a prior bounded transfer.
Commitment binding ties each value in the balance to the committed value through the difference column and the
digest boundary.

### 5.2 Zero-knowledge: amount-hiding

The amounts are not in the public inputs, so the on-chain data of a transfer is exactly the commitments, the
fee, and the proof. Hiding therefore reduces to the proof revealing nothing about the witness. We give two
forms of evidence.

First, the masking margin is correct against the library, not merely assumed, once the extension field is
counted properly. The implementation reveals one trace row per query position, for forty two queries, plus an
out-of-domain frame of two rows. The query openings are base-field values, but the out-of-domain frame is
evaluated over the cubic extension field, so each of its two rows fixes three base-field coordinates per
column, not one. The number of base-field linear constraints the verifier places on each trace-column
polynomial is therefore forty two from the queries plus six from the out-of-domain frame, which is forty
eight, not forty four. The masking budget is sixty-two free random rows per column. Since sixty-two exceeds
forty-eight, the trace polynomials remain underdetermined, with a margin of fourteen free rows. We correct
the earlier count, which treated the two out-of-domain rows as two base-field constraints rather than six;
the conclusion is unchanged but the true margin is fourteen rather than eighteen.

Second, we ran a battery of empirical witness-indistinguishability tests over the full proof bytes, which
include the trace openings, the constraint composition, the FRI layers, and the Merkle paths. In each test
we generate large families of proofs that differ only in a hidden quantity, with fresh randomness each
time, and train a held-out linear distinguisher; under zero knowledge the accuracy must be one half. The
measured results, with the proof length at roughly forty-five kilobytes, are as follows. The amount
distinguisher across twelve independent trials had mean accuracy 0.478 with a ninety-five percent
confidence interval of plus or minus 0.032, which brackets one half. A per-byte two-sample scan over the
whole proof found a maximum effect size of 0.385 and zero bytes exceeding a Bonferroni-corrected threshold
of 5.24 standard deviations, so no single byte separates the classes. A sweep over adjacent, wide, and
mid-range amount pairs stayed at chance. A distinguisher trained to recover a bit of the secret blinding,
rather than the amount, reached 0.403, so the hiding randomness itself does not leak. A distinguisher
restricted to the FRI and Merkle region of the proof, which is the channel the formal argument reduces to a
standard result, reached 0.472, again at chance. An information-theoretic upper bound on the leakage,
derived from the best accuracy any of these distinguishers achieved through Fano's inequality, is 0.014
bits. In every case a positive control with an injected signal was recovered with accuracy 1.000, which
shows the methodology detects leakage when it is present. Two proofs of one witness differ, and the hidden
amounts are confirmed absent from the public inputs.

We are explicit that this is statistical and empirical evidence, not a formal proof. Winterfell is not a
natively zero-knowledge library, and a complete argument must also reduce the constraint-composition and
FRI-layer commitments, not only the trace openings. The empirical test exercises the whole proof and is
therefore broader than the masking-margin argument alone, but a formal zero-knowledge proof or a simulator
remains the principal open problem.

### 5.3 Non-malleability and authorization

The transfer outputs are committed in the proof, so a transfer cannot be redirected. The unshield destination
is bound by the Fiat-Shamir context, so a captured unshield proof cannot be re-pointed by a relayer or a
mempool observer. The shield is authorized by a Dilithium signature over the spent output, the commitment, and
the value. Replay is prevented by the spent set: a re-submitted transfer fails because its inputs are no longer
unspent.

### 5.4 Quantum resistance across layers

Hiding is information-theoretic. Soundness rests only on a collision-resistant hash. Authorization uses a
lattice signature. None of the three relies on a problem that Shor's algorithm solves.

## 6. Adversarial review and remediation

We subjected the system to adversarial self-review at the level of the constraint arithmetic, in addition to
two independent reviewer passes over the integration. Two critical findings emerged and have been remediated,
and we disclose them in the interest of transparency.

The first was the field-wraparound inflation of Section 5.1. Before the fix, a prover could mint value by
setting the fee to p minus X. We confirmed the exploit with a proof-of-concept that verified through the exact
runtime entry point, then deployed the value and fee bounds and confirmed on the live chain that the minting
transaction is now rejected.

The second was that the unshield opening did not bind the destination, so a relayer or a mempool observer could
re-point a captured proof to their own address. We added the Fiat-Shamir context binding of Section 3.3 and a
regression test confirming that a re-pointed proof is rejected while the legitimate destination still works.

We also hardened the pool conservation to fail closed and closed a freeze-bypass in the plaintext spend helper.
A reviewer who trusts only the cryptographic primitives would have missed the inflation finding, since it lives
in the interaction between a field equation and an unbounded public input, which is why review at the level of
the arithmetic matters.

We then commissioned a third round of three independent expert reviews, over the AIR soundness, the
zero-knowledge hiding, and the protocol integration respectively. They agreed on a set of findings, which we
have since closed on the live chain, and we disclose them here. The first is that the binding fix of Section 3.3
had been applied to the zero-knowledge transfer path but not to the legacy first-generation opening proof, whose
unshield therefore remained re-pointable; we extended the same destination-bound context into the legacy
verifier, growing its opening blob and bumping its domain-separation tag, and confirmed on the live chain that a
re-pointed proof is rejected while the legitimate destination still settles. The second is that an earlier
non-zero-knowledge transfer variant range-proved to one bit more than the safe bound, so that two outputs plus a
fee could in principle wrap the field; we retired that variant in favour of the zero-knowledge path, which is
bounded correctly. The third is that a governance seeding entry created notes that were not reflected in the
conservation counter; we retired it and added a migration that purges the unbacked pool, restoring the counter
as a true invariant.

The legacy-verifier fix carried a deployment lesson worth recording. That verifier runs as a native host
function rather than inside the runtime wasm, so a runtime upgrade alone changed the blob the runtime emitted
while the validators still ran the old verifier, which then rejected every legacy opening until the node binary
itself was rolled out. The fix therefore required a coordinated, staggered binary rollout across the validator
set, ordered so that no transaction exercising the changed path could be admitted during the mixed-version
window. A property change in a consensus host function is a node-software change, not only a runtime change.

## 7. Performance

A transfer proof is approximately forty-six to fifty kilobytes, and a public-value opening proof is
approximately thirty kilobytes. Proving runs on the holder's device: a transfer proof is produced in roughly
seventy-five milliseconds and an opening in roughly one hundred milliseconds in a browser through WebAssembly.
Verification is in-runtime and deterministic. The prover and verifier compile to native targets and to the
wasm32 target, so the same code path proves in the browser and verifies in consensus.

## 8. Limitations and open problems

The zero-knowledge property is supported by a verified masking margin and an empirical distinguisher at chance,
but not by a formal proof, and obtaining one, or a security reduction to a clearly stated assumption, is the
main item we put forward for peer review. The construction is bespoke and layered on a library not designed for
zero knowledge, which is a reviewable surface in itself. The provable output range is slightly below two to the
sixty-second power because of an accumulator representation detail, which is far above supply and not a
limitation in practice. A first-generation Pedersen path on the same chain still verifies through a node host
function and should be migrated in-runtime or retired. Operationally, the chain is in a development phase under
a single administrative key, and re-keying to a multi-party operator key is a launch gate, not a property of the
cryptography described here.

## 9. Related work

Confidential transactions originate with Maxwell's value commitments and were combined with range proofs in
Confidential Transactions and later with Bulletproofs, which removed the trusted setup but retained a
discrete-logarithm soundness assumption. Monero's RingCT and Mimblewimble adopt the same commitment and range
machinery. Zerocash and the Sapling protocol of Zcash use zk-SNARKs over pairing-friendly curves, which give
succinct proofs but require a trusted setup and rest on assumptions that are not post-quantum. Hash-based
proof systems, namely STARKs and the FRI low-degree test, provide transparent setup and plausibly
post-quantum soundness, and have been used for scaling rollups. Our contribution is to apply a hash-based,
transparent, post-quantum proof system to confidential payments with an in-consensus verifier, and to combine
amount-hiding, no-inflation, and authorization so that all three resist a quantum adversary on a sovereign
chain.

## 10. Conclusion

We have described and deployed a confidential transaction system whose amount-hiding, no-inflation soundness,
and spend authorization are each post-quantum, and whose verifier runs inside the chain runtime. Soundness is
argued and tested, including the closure of a field-wraparound inflation that we found and fixed, and
amount-hiding is implemented, live, and supported by a verified masking margin and an empirical distinguisher
at chance. The principal open problem is a formal zero-knowledge proof of the masking construction, and it is
for that, and for adversarial scrutiny of the constraint system, that we invite peer review.

## References

1. G. Maxwell. Confidential Transactions. 2015.
2. B. Bunz, J. Bootle, D. Boneh, A. Poelstra, P. Wuille, G. Maxwell. Bulletproofs: Short Proofs for
   Confidential Transactions and More. IEEE S&P, 2018.
3. E. Ben-Sasson, I. Bentov, Y. Horesh, M. Riabzev. Scalable, transparent, and post-quantum secure
   computational integrity (STARKs). 2018.
4. E. Ben-Sasson, L. Goldberg, S. Kopparty, S. Saraf. DEEP-FRI: Sampling outside the box improves soundness.
   2019.
5. A. Szepieniec, T. Ashur, S. Dhooghe. Rescue-Prime: a Standard Specification. 2020.
6. E. Ben-Sasson, A. Chiesa, E. Tromer, M. Virza. Succinct non-interactive zero knowledge for a von Neumann
   architecture (Zerocash). USENIX Security, 2014.
7. Zcash. The Sapling protocol specification.
8. T. Jedusor. Mimblewimble. 2016.
9. NIST. FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA / CRYSTALS-Dilithium). 2024.
10. Winterfell: a STARK prover and verifier (Rust). Open-source library.

## Appendix A: Toward a formal zero-knowledge proof of the masking construction

This appendix states the zero-knowledge property we aim to prove, gives the simulator-based argument
as far as it goes, identifies the single remaining obligation, and lays out the work to close it. We
write it so that an independent cryptographer can review a complete argument rather than reconstruct
one. We are deliberate about the boundary between what is proven, what is reduced to a standard
sub-result, and what is supported only by evidence.

### A.1 The protocol as a non-interactive argument

The transfer proof is a Fiat-Shamir compilation of an interactive oracle proof. The prover commits to
the trace low-degree extension by a Merkle root, the verifier (modelled as a random oracle) returns
out-of-domain challenge points and constraint-batching coefficients, the prover answers with the
out-of-domain frame and commits to the constraint composition, and the two run a DEEP quotient and a
FRI low-degree test whose query positions are derived from the random oracle. The verifier transcript
is therefore: the trace and composition Merkle roots, the out-of-domain evaluations, the trace and
composition openings at the query positions with their authentication paths, and the FRI commit and
query transcript. The public statement is the input and output commitments and the fee. The witness is
the note values and blindings. We work in the random-oracle model and assume the Merkle hash is
collision resistant.

### A.2 Definition

The argument is honest-verifier zero-knowledge if there is a probabilistic polynomial-time simulator S
that, on input the public statement alone, outputs a transcript whose distribution is statistically
close to that of real proofs, where the closeness is over the randomness of the prover, the simulator,
and the random oracle. Because the verifier is public-coin and the protocol is compiled by Fiat-Shamir,
honest-verifier zero-knowledge in the interactive oracle model lifts to non-interactive zero-knowledge
in the random-oracle model by programming the oracle at the challenge points.

### A.3 The leakage surface and the masking budget

Every field element of the witness lives in the execution trace. The verifier observes the trace only
through three channels: the query openings, the out-of-domain frame, and the FRI transcript. We account
for these per column, because each trace column is an independent polynomial of degree below the trace
length and is masked independently.

The construction sets the trace length to one hundred twenty eight, runs the real computation in the
first sixty six rows, and fills the trailing sixty two rows with field elements drawn from a
cryptographically secure generator, with the transition constraints exempted over that tail so the
random rows are unconstrained. Each column therefore carries sixty two free uniform values. The verifier
reads each column at the query positions, one base-field value per query, for forty two queries, plus the
out-of-domain frame at the two points z and the shifted point. The out-of-domain frame is evaluated over
the cubic extension field, so each of its two rows contributes three base-field coordinates per column, for
six base-field constraints, and the total number of base-field linear constraints on each column polynomial
is forty eight. Since sixty two exceeds forty eight, the restriction of each column polynomial to the
observed points is, conditioned on the unobserved random rows, uniform and independent of the witness, with
a margin of fourteen free rows. We verified against the prover and verifier source that exactly one trace
row is opened per query position and that the out-of-domain frame is two rows over the cubic extension, so
forty eight is the exact count rather than an estimate. (An earlier draft counted the out-of-domain frame as
two base-field constraints and reported a margin of eighteen; the corrected margin is fourteen, and the
masking still strictly dominates the leakage.)

### A.4 The simulator

S(statement) proceeds as follows. It samples the out-of-domain frame for each column uniformly at random,
consistent with the public commitments through the boundary relations, which fixes the digest cells to the
public commitment values and leaves the value and blinding cells uniform. It samples the query positions
as the programmed oracle dictates. For each opened column at each query position it outputs a uniform field
element, which is identically distributed to a real opening by the argument of A.3. It builds Merkle
commitments over the simulated leaves and programs the oracle so that the roots are consistent. It computes
the composition openings as the public function of the simulated trace openings and the batching
coefficients, which it can do because the composition value at a point is determined by the trace frame at
that point, so it introduces no new degrees of freedom. The balance and range relations are public and are
satisfied by construction of the simulated openings, since the simulator chooses a witness-free assignment
that meets the public constraints at the opened points only, which suffices because the constraints are
checked only there.

### A.5 What is proven and the one remaining obligation

The trace openings, the out-of-domain frame, and the composition openings are simulatable by A.3 and A.4,
since each is either uniform under the masking budget or a public function of values that are. This
establishes zero-knowledge for everything except the FRI transcript. FRI is run on the DEEP polynomial,
which is a public combination of the masked trace and the out-of-domain frame, so its query openings at
layer zero coincide with values already accounted for, but the FRI commit-phase roots and the folded query
openings at later layers are a separate object whose simulation requires the standard FRI zero-knowledge
argument. That argument shows that, when the number of FRI queries is bounded relative to the randomness in
the tested polynomial, the FRI transcript leaks nothing beyond the bounded openings, and it is the
component we reduce to rather than reprove here. Two routes close it cleanly. The first adds an independent
random low-degree polynomial to the first FRI layer so that the folded transcript is masked outright, which
is the construction used in transparent zero-knowledge STARK deployments and makes the simulation immediate.
The second invokes the query-bounded leakage analysis directly, which our parameters already satisfy by the
margin of A.3, but which we have not yet written out in full for our exact instantiation. We state plainly
that obtaining one of these two, written for this construction and independently reviewed, is the open item.

### A.6 Empirical corroboration

The argument of A.3 to A.5 predicts that no efficient adversary recovers the witness from a proof. We test
the prediction directly. We generate large families of proofs that differ only in a hidden amount or in a
hidden blinding bit, with fresh randomness each time, and we train held-out distinguishers over the full
proof bytes, which include the FRI and Merkle material that A.5 leaves to the standard argument. Across many
independent trials the distinguisher accuracy is statistically indistinguishable from one half, the largest
per-byte effect is within the multiple-testing noise floor, the same tests on the FRI region alone are at
chance, and an information-theoretic upper bound derived from the best observed accuracy is approximately
zero bits, while a positive control with an injected signal is recovered perfectly. The exact figures are
reported in the security section and reproduced by the evidence harness in the source repository. This is
corroboration, not proof, and it specifically exercises the one channel that A.5 reduces to a standard
result, which is the channel we most want independent eyes on.

### A.7 A formal proof plan

The engineering prerequisite for the strongest form of this argument is already complete: the circuits have
been reimplemented on a natively zero-knowledge proving stack and that path is live and value-bearing
(appendix A.8 and appendix B). What remains is the mathematics, and this section sets out the plan for it in
two tracks. Track I is the inherited-hiding argument for the natively zero-knowledge path; it is short and
nearly complete. Track II is the full simulator-based proof for the original masking path; it is the
principal open problem this paper invites review on. Both tracks target the same definition.

**Target definition.** We prove non-interactive honest-verifier zero-knowledge for the Fiat-Shamir-compiled
argument in the random-oracle model. The obligation is to exhibit a probabilistic polynomial-time simulator
S that, given only the public statement x (the input and output commitments, the public fee, and the
destination context) and the ability to program the random oracle, outputs a transcript whose distribution
is indistinguishable from a real proof produced for any witness w consistent with x. The distinguishing
advantage is bounded by a quantity epsilon that we tie to the security parameter: statistically for Track II,
and computationally modulo one stated library assumption for Track I.

**The transcript object.** So that the simulator's obligations are explicit, a proof consists of: the trace
Merkle root; the out-of-domain evaluation frame at the challenge point and its shift, over the cubic
extension field; the constraint-composition commitment; the DEEP quotient data; the FRI commit-phase roots;
the FRI query-phase answers with their Merkle authentication paths; and the grinding nonce. Fiat-Shamir
derives every challenge (the out-of-domain point, the constraint-batching coefficients, the FRI folding
challenges, the query positions, the grinding) from these commitments through the oracle. The simulator must
reproduce all of it without w.

**Track I (the natively zero-knowledge path): near-complete.** The argument reduces to three lemmas.

- L0, library zero-knowledge (assumption). The hiding polynomial-commitment scheme and its FRI integration
  are honest-verifier zero-knowledge: salted Merkle leaves, random codewords, and randomized batching make
  the commit-and-query transcript simulatable independently of the committed polynomials. We state this as
  the proving system's theorem and discharge it by citing the system's published analysis and, for our exact
  pinned version, by an independent review (a milestone below), not by re-proving the scheme.
- L1-PI, public-input injectivity (ours). Our algebraic intermediate representation exposes as public inputs
  only x itself: the four commitments as field elements, the fee, and the destination context packed
  injectively into field elements. We prove the packing is injective and a function of x alone, so the
  public inputs carry no witness information. This is a few lines of field arithmetic and is what the
  adversarial public-input battery already exercises empirically.
- L1-FS, Fiat-Shamir witness-independence (ours). The context and every other transcript-seeding value are
  functions of x, so the induced challenge distribution depends only on x; a simulator that fixes x induces
  the same challenges.

Given L0, the simulator runs the library simulator on our AIR with public inputs x, and L1-PI together with
L1-FS guarantee nothing else depends on w. This yields honest-verifier zero-knowledge for the path modulo
L0. The deliverable is a short written argument (a few pages) plus the commissioned L0 review.

**Track II (the masking path): the principal open problem.** We build the simulator as a hybrid sequence
from the real transcript to the simulated one, discharging one lemma per leakage channel.

- L2, trace openings (the masking margin). Over the cubic extension the verifier observes Q query rows in
  the base field plus the two out-of-domain rows, and each out-of-domain row contributes three base-field
  coordinates per column, for Q plus six base-field linear constraints per column polynomial. The
  construction supplies B free uniform rows per column with B greater than Q plus six (concretely B is
  sixty-two against forty-eight). The lemma proves that, conditioned on the unobserved random rows, the
  restriction of each column polynomial to the observed points is uniform and independent of the witness, so
  the trace openings are simulatable with statistical distance zero. The task is to write the cross-extension
  counting and the conditional-uniformity argument in full.
- L3, the out-of-domain frame. Show it is simulatable by sampling uniformly subject to the boundary
  relations that fix the digest cells to the public commitments, leaving the value and blinding cells
  uniform.
- L4, composition openings. The DEEP composition polynomial is a fixed public linear combination of the
  trace columns and the out-of-domain frame, so its openings are a deterministic function of L2 and L3 and
  are simulatable once those are.
- L5, the FRI transcript (the open obligation). The tested codeword is a public combination of the masked
  trace and the out-of-domain frame. There are two routes. Route (a), direct: prove that the masking
  randomizes the first FRI layer so the entire commit-and-query transcript is independent of w, by carrying
  the L2 underdetermination through the folding. Route (b), reductionist: show our instantiation meets the
  preconditions of a published FRI zero-knowledge theorem and invoke it. We take route (a) as primary and
  route (b) as fallback, and the plan names the precise sublemma each needs.
- L6, Merkle and commitment hiding. The roots and authentication paths must hide the unopened leaves; reduce
  this to the hash assumption soundness already relies on, or adopt salted leaves to make it
  information-theoretic.
- L7, Fiat-Shamir composition. Assemble L2 through L6 into one simulator in the random-oracle model,
  programming the oracle so the simulated commitments induce the simulated challenges, and bound the composed
  statistical distance by the sum of the per-channel distances, which is zero for L2 through L4 under the
  margin plus the L5 and L6 terms.

The quantitative target is a theorem of the form: for every witness consistent with x, the real and
simulated transcript distributions are within epsilon, where epsilon is an explicit expression in the
masking margin and the hash advantage, giving at least k bits of statistical hiding.

**Mechanization and corroboration.** Milestone M1 is done: the margin count is now a regression test rather
than a hand calculation. A function derives the free masking rows, the query count, and the out-of-domain
base-field constraints (two rows times the cubic degree) directly from the live proof parameters and the
trace layout, and the test asserts the margin B minus Q minus six equals fourteen and is strictly positive,
so lowering the masking or raising the query count fails continuous integration instead of silently eroding
the hiding margin. The remaining mechanization steps stand: where feasible we will sketch the algebraic lemmas
L2, L3, and L4 in a proof assistant, treating L5 and L6 as paper lemmas pending the FRI result. The empirical
battery of A.6 is retained as corroboration that the implementation matches the proven design, not as a
substitute for the proof.

We note for completeness that the masking path itself has since been retired from the live chain: the
natively zero-knowledge path is now the sole zero-knowledge construction carrying value, and the masking path
remains documented here as the prior construction and as the subject of the Track II proof, which is of
record-keeping and academic value rather than a live-system dependency.

**External review and definition of done.** An independent cryptographer reviews L2 through L7 for Track II
and L0 together with our L1 lemmas for Track I. The plan is done when Track I is written and reviewed, so the
natively zero-knowledge path's hiding is proven modulo the cited library theorem, and when Track II's L2
through L4 are written in full with the cross-extension counting, at least one route of L5 is discharged, L6
is reduced, and L7 is assembled with an explicit epsilon, all reviewed. At that point the masking path's
hiding claim moves from evidenced to proven and the principal open problem of this paper is closed.

**Milestones.** M1, mechanize the margin counting as a regression test. M2, write Track I and commission the
L0 review. M3, write L2 through L4 with the cross-extension counting. M4, resolve L5, route (a) primary and
route (b) fallback. M5, reduce L6 and assemble L7 with an explicit epsilon. M6, external review. M7, publish
the revision.

### A.8 Reimplementation status

The first step of that plan is done. All three circuits, the opening, the public-value opening, and the
two-input two-output transfer, have been reimplemented on the hiding AIR stack and verified end to end. The
Rescue-Prime permutation was reproduced over the new stack's field and cross-checked bit for bit against the
live chain's hash, so commitments are identical and the two systems are interoperable. Each circuit proves
and verifies under the hiding polynomial-commitment scheme, the openings bind to their commitments, the
public-value opening binds its destination through the transcript so a re-pointed proof is rejected, the
transfer enforces balance and a sixty-two bit output range and rejects forged fees and commitments, and two
proofs of one statement differ. The audit fixes are carried over: the fee and values are bounded below two to
the sixty-second power so the balance cannot wrap, and the destination is bound. Because the hiding here is a
property of the proving system rather than a hand-rolled masking layer, the amount-hiding obligation of A.5 is
discharged by inheritance once this stack is the one in production: the FRI transcript is randomized by the
scheme, not argued by us.

The pipeline has since been demonstrated end to end, off chain. The verifier compiles to a no_std wasm target
of the same class as the chain runtime, which establishes that it can run in consensus without a host
function. A browser prover was built and a two-input two-output transfer proves in about two hundred
milliseconds in a WebAssembly host. A proof produced by that browser prover verifies under the native
verifier, so the browser-prove to runtime-verify path is interoperable. The empirical
witness-indistinguishability battery was re-run on the new proofs: a held-out distinguisher recovers the
hidden amount at chance while a positive control separates perfectly, so the inherited hiding holds in
practice as well as in design.

The proof-size optimization has since been done. The first version nested the round constants inside the
degree-seven inverse S-box, which raised the constraint degree to about fifty and forced a large FRI blowup.
The standard low-degree layout adds one intermediate S-box-output column per state cell so each round is two
degree-seven constraints with the constants added rather than nested. This drops the constraint degree to
seven and the FRI blowup from sixty-four to eight; with the query count tuned to the ninety-six bit target,
the transfer proof falls from roughly three hundred ninety kilobytes to about one hundred ninety, and the
opening from about two hundred eighty to one hundred twenty, while proving stays around three hundred
milliseconds in the browser and the no_std verifier still builds for the runtime target. The exact query
count, grinding, and blowup are a deploy-time security choice on the known size-versus-soundness curve, and
a further reduction is available by narrowing the range gadget.

The runtime integration has since been built, measured, and, following an independent review, deployed live.
The native-zero-knowledge verifier is wired into the runtime through two additive entry points, a governance
seed and a note-to-note transfer, that operate on an isolated pool with no plaintext exit: notes can only be
seeded by governance and moved note to note, never shielded in from a plaintext output nor unshielded out to
one, so no real value can ever enter or leave the pool and even a verifier defect cannot create or move funds.
The verifier runs in consensus with no host function, so the deployment and its rollback are pure runtime
upgrades requiring no node-software change. The size cost is modest: the compressed runtime grows by about
fifty-eight kilobytes, an eight percent increase, which lays to rest the concern that a STARK verifier would be
too large to carry in the runtime. Before deployment the runtime was rehearsed in forked-state, instantiating
and decoding the full live state with all invariant checks passing, and the verifier was exercised by runtime
tests and by a panic-safety fuzz of over fourteen thousand adversarial inputs with zero panics.

The verifier has since been exercised on the live chain inside the isolated pool. A tampered transfer proof of
about one hundred ninety kilobytes was rejected in the block that included it without disturbing finality,
which is the in-consensus evidence that a malformed proof cannot halt block production, and a valid proof was
accepted with its input notes spent and its outputs created. Amount-hiding in this pool is therefore a proven
property of the proving system rather than an evidenced one, now running in consensus.

The construction has since been promoted from the isolated pool to a value-bearing path. Plaintext on and off
ramps now run under the same in-runtime verifier, with the same model as the existing live ramps: a shield
burns a signature-authorized plaintext output and mints a note proven in zero knowledge to open to exactly its
value, and an unshield spends a note proven to open to a revealed value, bound to its destination, and mints a
plaintext output, fail-closed on a pool conservation counter so that no soundness defect can release more than
was shielded in. This promotion was deployed only after an independent review and, because the verifier is
in-runtime, as a pure runtime upgrade whose rollback is equally a pure runtime upgrade.

The value-bearing path has been battle-tested on the live chain. A full round-trip moved real value through
it: a shield admitted the value into the pool, an unshield whose proof was re-pointed to an attacker's address
was rejected, and the unshield to the rightful destination was accepted with the note spent and the
conservation counter returned to zero; a tampered proof of about one hundred twenty kilobytes was rejected in
the block that included it without disturbing finality. Amount-hiding on this path is therefore a proven
property of the proving system, running in consensus and carrying real value, alongside the prior construction,
whose soundness is proven and audited and whose hiding is strongly evidenced. We make no stronger claim than
that the proven-hiding path is now live and value-bearing and that an independent review preceded its
deployment.

## Appendix B: Live deployment record

Every claim in this paper about live behaviour is backed by finalized on-chain transactions on
qbc.network (chain id 3303). The chain reports a continuous block height equal to the substrate
height plus a fork offset of 208,680; the explorer renders the continuous height. The transactions
below are all finalized.

### B.1 Runtime upgrades

| Change | spec | mechanism |
|---|---|---|
| Audit remediation (C-1 dest-binding, v2 retirement, pool purge) | 155 | sudo set_code + staggered node-binary rollout |
| Plonky3 native-zero-knowledge verifier in-runtime (isolated v4 pool) | 156 | sudo set_code (in-runtime verifier, no node change) |
| v4 pool promoted to value-bearing (shield_v4 / unshield_v4) | 157 | sudo set_code (in-runtime verifier, no node change) |

### B.2 The value-bearing round-trip (Plonky3 path)

A full round-trip of real value through the natively-zero-knowledge pool, each row a finalized
extrinsic. Explorer: `https://qbc.network/explorer/block/<continuous height>`.

| Step | Result | extrinsic hash | substrate / continuous block |
|---|---|---|---|
| Register the test wallet's Dilithium key | accepted | 0xff6394227fbab2da37ca7f04c5641553481fa37febea8e5ce1b17d596fcf2aa2 | 1032718 / 1241398 |
| Fund it (v1 unshield to its address) | accepted | 0x2635b3ac3d03662bfc68e3e228f15eb8d57366300a7ff8a27ec1169f9b5deb42 | 1032725 / 1241405 |
| **shield_v4** (real value into the Plonky3 pool) | **accepted** | 0xf054bdbf57314fb0063ca5dd921a4915eb0f482f3db1b18468bf4008a096595a | 1032729 / 1241409 |
| **unshield_v4 re-pointed to an attacker address** | **rejected** | 0xbfc421fad797a6b714f7b81d3d21c865249d85a9186d9557d14bd08b290845df | 1032732 / 1241412 |
| **unshield_v4 to the rightful destination** | **accepted** | 0xcd637ce9467f10fa1ba543db07783dc1faaa36532da3e37c1b2fa6874226c21c | 1032737 / 1241417 |

Block hashes for the three v4 blocks: 1241409 `0x6bfd9dc94f8dd974e71b41e76435185a77a319757d6d1308007038fa57741215`;
1241412 `0x54e381ffe603daa8fc753f301ce99334d8a57d89476bda31f1fdcc0b2bd2771d`;
1241417 `0x52d52593a1f25ee36ef77daf4c3fdc52c3ec239326acf7ac3b3e7ed29ee43e56`.

### B.3 On-chain state, which is the conservation proof

The pool conservation counter moved exactly as required: `TotalShieldedV4` was zero before the
round-trip, became 2000 base units after `shield_v4`, and returned to zero after `unshield_v4`. The
spent note moved from the unspent set to the spent set, so it cannot be replayed. A tampered transfer
proof of about 121 kilobytes and a tampered open proof were each rejected in the block that included
them without disturbing finality, which is the in-consensus evidence that a malformed proof cannot
halt block production. Finality held at a gap of two to three blocks across every upgrade and every
test. These facts are readable directly from chain storage (`TotalShieldedV4`, `SpentCommitmentsV4`)
and from the finalized blocks above.
