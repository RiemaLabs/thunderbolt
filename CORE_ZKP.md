# Introduction of Core ZK Proof in Thunderbolt

The following two proofs are the core correctness proofs for a single transfer step from Alice to Bob.

Assume Alice is the current holder at step $s$, Bob is the next recipient, and the Committee is the co-signer that maintains the complementary share needed to keep the on-chain lock key fixed. Before the transfer, the current state is represented by a holder secret $x_s$, a Committee secret $y_s$, and a public anchor $X_s = x_s H$, with the invariant
$$
P = (x_s + y_s)G.
$$

All scalar equalities appearing in elliptic-curve relations are interpreted modulo the group order $q$.

The transfer is split into two phases.

First, **Bob publishes a one-time invoice**. In this phase, Bob chooses a fresh refresh value $r_s$ and publishes:
- a public delta point $D_s = r_s H$,
- a ciphertext to himself containing $r_s$,
- a ciphertext to the Committee containing the same $r_s$.

This is the setting of **Core Proof 1 (Invoice Consistency Proof)**. Its role is to prove that all invoice objects are bound to the same refresh value $r_s$.

Second, **Alice consumes Bob's invoice and constructs the next state**. Using her current holder secret $x_s$ and Bob's invoice ciphertext, she forms the new holder ciphertext $T_{s+1}$ for Bob and updates the public anchor from $X_s$ to $X_{s+1} = X_s + D_s$.

This is the setting of **Core Proof 2 (Transfer Consistency Proof)**. Its role is to prove that Alice used the actual current holder secret $x_s$ consistent with the current anchor $X_s$, so that Bob's new ciphertext decrypts to an integer whose class modulo $q$ is the updated holder scalar:
$$
x_{s+1} \equiv x_s + r_s \pmod q.
$$

Together, these two proofs guarantee that the same refresh value $r_s$ is:
- added to the holder side,
- subtracted from the Committee side,
- and reflected consistently in the public anchor transition.

As a result, the off-chain ownership state changes, while the fixed on-chain key remains unchanged.


# Core Proof 1: Invoice Consistency Proof

## Goal

Bob publishes an invoice that defines a fresh refresh value $r_s$.

The invoice contains:

- a public delta point
  $$
  D_s = r_s H,
  $$
- a ciphertext to Bob
  $$
  ct_B = \mathrm{Enc}_{pk_B}(r_s; \rho_B),
  $$
- a ciphertext to the Committee
  $$
  ct_C = \mathrm{Enc}_{pk_C}(r_s; \rho_C).
  $$

The purpose of the invoice proof is to show that **all three objects encode the same integer value** $r_s$.

Without this proof, a malicious Bob could publish an invoice where:

- the anchor delta corresponds to one value,
- Bob's ciphertext corresponds to another value,
- the Committee's ciphertext corresponds to yet another value,

which would break the transfer invariant.

---

## Statement

Public inputs:

- group generator $H \in \mathbb{G}$,
- Paillier public keys $pk_B = (N_B, g_B)$ and $pk_C = (N_C, g_C)$,
- public delta point $D_s$,
- ciphertexts $ct_B, ct_C$.

Witness:

$$
(r_s, \rho_B, \rho_C)
$$

such that

$$
D_s = r_s H,
$$

$$
ct_B = \mathrm{Enc}_{pk_B}(r_s; \rho_B),
$$

$$
ct_C = \mathrm{Enc}_{pk_C}(r_s; \rho_C).
$$

Equivalently, the proof relation is

$$
\mathcal{R}_{\mathrm{inv}} = \left\{ (D_s, ct_B, ct_C; r_s, \rho_B, \rho_C) : D_s = r_s H \land ct_B = g_B^{r_s}\rho_B^{N_B} \bmod N_B^2 \land ct_C = g_C^{r_s}\rho_C^{N_C} \bmod N_C^2 \right\}.
$$

---

## NIZK proof and verification

**Proof:** $\pi_{\mathrm{inv}} = (A_D, A_B, A_C, z, \tau_B, \tau_C)$ (obtained via Fiat--Shamir on the above relation). The prover uses one integer value $r_s$ and one commitment randomness $\alpha$: commitments are $A_D = \alpha H$, $A_B = g_B^{\alpha}\beta_B^{N_B}$, $A_C = g_C^{\alpha}\beta_C^{N_C}$; response $z = \alpha + c r_s$ is the **same** in all three components, so the verifier sees a single $z$ tying $D_s$, $\mathrm{ct}_B$, and $\mathrm{ct}_C$ to the same $r_s$.

**Verification:** set
$$
c = \mathsf{Hash}(\texttt{tb/invoice}, \texttt{ctx\_id}, \texttt{inv\_id}, H, pk_B, pk_C, D_s, ct_B, ct_C, A_D, A_B, A_C) \bmod q,
$$
then check (same $z$ in all three):

- EC:
  $$
  zH \stackrel{?}{=} A_D + cD_s
  $$
- Bob Paillier:
  $$
  z\Gamma_B \stackrel{?}{=} A_B \cdot ct_B^c \pmod{N_B^2},
  \qquad
  z\Gamma_B := g_B^z \tau_B^{N_B}
  $$
- Committee Paillier:
  $$
  z\Gamma_C \stackrel{?}{=} A_C \cdot ct_C^c \pmod{N_C^2},
  \qquad
  z\Gamma_C := g_C^z \tau_C^{N_C}
  $$

Accept iff all three hold. The single $z$ in all three equations forces the same integer value $r_s$ everywhere.

---

## Security Meaning

This proof guarantees the existence of a single integer value $r_s$ such that:

- the public anchor delta is $D_s = r_s H$,
- Bob's ciphertext decrypts to $r_s$,
- the Committee's ciphertext decrypts to the same $r_s$.

Thus the invoice defines one consistent refresh value.

This is exactly the proof that enforces the ``same $r_s$ everywhere'' property on the invoice side.

---

# Core Proof 2: Transfer Consistency Proof

**From Core Proof 1.** We assume the invoice proof has been verified, so the same integer value $r_s$ satisfies $D_s = r_s H$ and $ct_B = \mathrm{Enc}_{pk_B}(r_s)$ (and $ct_C = \mathrm{Enc}_{pk_C}(r_s)$). The transfer proof uses $ct_B$ and $D_s$ as fixed public inputs with that meaning.

---

## Goal

Alice is the current holder at step $s$ and knows the current holder secret $x_s$.

The current public anchor is

$$
X_s = x_s H.
$$

Bob's invoice already contains a ciphertext

$$
ct_B = \mathrm{Enc}_{pk_B}(r_s).
$$

Alice forms Bob's next holder ciphertext as

$$
T_{s+1} = \mathrm{Enc}_{pk_B}(x_s; \eta_s) \oplus ct_B.
$$

Because Paillier is additively homomorphic, Bob decrypts

$$
T_{s+1} \leadsto x_s + r_s,
$$

and therefore the updated holder scalar satisfies

$$
x_{s+1} \equiv x_s + r_s \pmod q.
$$

The purpose of the transfer proof is to show that the value Alice injects into this ciphertext is the **actual current holder secret** opening the current anchor $X_s$.

Without this proof, Alice could fabricate a ciphertext using some unrelated value $x_s' \neq x_s$.

---

## Statement

Public inputs:

- $H \in \mathbb{G}$,
- Bob's Paillier public key $pk_B = (N_B, g_B)$,
- current anchor $X_s$,
- Bob's invoice ciphertext $ct_B$,
- Alice's newly posted ciphertext $T_{s+1}$.

Witness:

$$
(x_s, \eta_s)
$$

such that

$$
X_s = x_s H,
$$

and

$$
T_{s+1} \ominus ct_B = \mathrm{Enc}_{pk_B}(x_s; \eta_s).
$$

Equivalently,

$$
\mathcal{R}_{\mathrm{xfer}} = \left\{ (X_s, ct_B, T_{s+1}; x_s, \eta_s) : X_s = x_s H \land T_{s+1} \cdot ct_B^{-1} = g_B^{x_s}\eta_s^{N_B} \pmod{N_B^2} \right\}.
$$

Note that the verifier also performs the separate public check

$$
X_{s+1} \stackrel{?}{=} X_s + D_s,
$$

but this anchor-transition check is outside the zero-knowledge relation itself.

---

## NIZK proof and verification

**Proof:** $\pi_{\mathrm{xfer}} = (A_X, A_T, z, \tau)$ (obtained via Fiat--Shamir on the above relation).

**Verification:** set
$$
c = \mathsf{Hash}(\texttt{tb/xfer}, \texttt{ctx\_id}, s+1, \texttt{inv\_id}, H, pk_B, X_s, ct_B, T_{s+1}, A_X, A_T) \bmod q,
$$
then check (same $z$ in both):

- EC:
  $$
  zH \stackrel{?}{=} A_X + cX_s
  $$
- Paillier:
  $$
  z\Gamma_B \stackrel{?}{=} A_T \cdot (T_{s+1} \ominus ct_B)^c \pmod{N_B^2},
  \qquad
  z\Gamma_B := g_B^z \tau^{N_B}
  $$

---

## Security Meaning

This proof guarantees that there exists a single integer value $x_s$ such that:

- $X_s = x_s H$, i.e. it is the true opening of the current public anchor,
- $T_{s+1} \ominus ct_B$ encrypts that same $x_s$ under Bob's key.

Therefore the ciphertext Alice contributes to the next state is tied to the actual current holder state.

Since the invoice proof already guarantees that

$$
ct_B = \mathrm{Enc}_{pk_B}(r_s),
$$

we obtain

$$
T_{s+1} = \mathrm{Enc}_{pk_B}(x_s) \oplus \mathrm{Enc}_{pk_B}(r_s) = \mathrm{Enc}_{pk_B}(x_s + r_s).
$$

Combined with the public anchor update

$$
X_{s+1} = X_s + D_s,
$$

and the invoice relation $D_s = r_s H$, we get

$$
X_{s+1} = x_s H + r_s H = (x_s + r_s)H.
$$

Hence Bob decrypts the integer

$$
x_s + r_s
$$

from $T_{s+1}$, while the new public anchor satisfies

$$
X_{s+1} = (x_s + r_s)H.
$$

Therefore the updated holder scalar is determined modulo $q$ by

$$
x_{s+1} \equiv x_s + r_s \pmod q.
$$

This enforces the holder-side update in the sense needed for preservation of the fixed on-chain key.

---

# Joint Consequence of the Two Proofs

Taken together, Core Proof 1 and Core Proof 2 imply the existence of integers $x_s$ and $r_s$ such that

$$
X_s = x_s H,
$$

$$
D_s = r_s H,
$$

$$
T_{s+1} = \mathrm{Enc}_{pk_B}(x_s + r_s),
$$

and the public anchor update satisfies

$$
X_{s+1} = X_s + D_s = (x_s + r_s)H.
$$

At the same time, the Committee decrypts the committee-side invoice object, recovers the same integer $r_s$, and updates its share by

$$
y_{s+1} = y_s - r_s.
$$

Accordingly, the holder-side and Committee-side updates satisfy

$$
x_{s+1} \equiv x_s + r_s \pmod q,
\qquad
y_{s+1} \equiv y_s - r_s \pmod q.
$$

Therefore the fixed on-chain key is preserved:

$$
(x_{s+1} + y_{s+1})G =
(x_s + r_s + y_s - r_s)G =
(x_s + y_s)G.
$$

This is exactly the ``one add / one subtract'' invariant. For this invariant, it is sufficient that the same integer $r_s$ is used consistently in the invoice, in Alice's holder update, and in the committee-side compensating update. This committee-side update may be carried out either by a single honest Committee entity or collectively by a threshold committee via a VESS-based sharing / resharing protocol. Since scalar multiplication on the curve is taken modulo $q$, no additional canonical range condition is needed merely to preserve the fixed on-chain key.

---

# Relationship to Existing Schemas

J.~Camenisch and V.~Shoup, *Practical Verifiable Encryption and Decryption of Discrete Logarithms*, CRYPTO 2003 / ePrint 2002/161, give an efficient protocol for **verifiable encryption of discrete logarithms**: proving that a Paillier ciphertext encrypts the discrete log of a known group element (for example, that $ct = \mathrm{Enc}_{pk}(m)$ and $D = mH$ for the same $m$), using Sigma-style protocols and Fiat--Shamir NIZK without cut-and-choose.

Victor Shoup's *Simple VESS* gives a scheme for **verifiably encrypting a Shamir secret sharing** to a committee of shareholders, so that any party can publicly verify that the encrypted shares are consistent with one well-formed sharing. The paper explicitly positions this as a simple building block for distributed key generation and resharing protocols in threshold signing and decryption systems.

**How our schema relates:**

- **Core Proof 1 (Invoice)** is a multi-receiver extension at the level of the proof relation: we prove that one integer $r_s$ is the discrete log of the public point $D_s$ and also the plaintext of two ciphertexts, namely $\mathrm{ct}_B$ and $\mathrm{ct}_C$. In other words, we perform verifiable encryption of the discrete log of $D_s$ simultaneously for Bob and for the Committee, using one shared response across one EC relation and two Paillier relations.

- **Core Proof 2 (Transfer)** is the same primitive in the single-ciphertext case: the ciphertext $T_{s+1} \ominus \mathrm{ct}_B$ encrypts the integer value $x_s$ whose discrete-log relation is $X_s = x_s H$. Thus Proof 2 is again a verifiable-encryption-of-discrete-log proof in the Camenisch--Shoup style.

- **Committee-side update via VESS.** If the Committee is instantiated as a threshold committee rather than a single actor, then the committee-side object need not be modeled as one ciphertext to one trusted Committee. Instead, Bob can distribute the committee-side refresh using a VESS / resharing protocol: informally, he verifiably encrypts to the committee a Shamir sharing of the compensating update associated with $r_s$. In that case, the protocol no longer relies on a single honest Committee entity locally applying $y_{s+1} = y_s - r_s$. Rather, correctness of the committee-side update follows collectively from successful completion of the VESS-based sharing / resharing protocol under the required threshold-honesty assumption.

**Summary:** Core Proofs 1 and 2 are the Thunderbolt-specific use of **verifiable encryption of discrete logarithms** for the invoice and transfer steps. If the Committee is a single trusted actor, these proofs suffice to justify the holder-side ``add'' and the Committee-side ``subtract.'' If the Committee is instead realized as a threshold committee, then the committee-side ``subtract'' can be implemented via **VESS-based sharing / resharing**, so that its correctness is guaranteed collectively under the threshold assumptions of the VESS protocol rather than by a single honest Committee entity.