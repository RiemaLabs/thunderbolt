# Overview

This document describes the complete Thunderbolt protocol — a secure, verifiable off-chain ownership transfer mechanism for Bitcoin UTXOs.

## Design Goals

We want an **off-chain UTXO payment system** for Bitcoin that provides a **payment-channel-like** user experience (fast transfers off-chain, single on-chain settlement), but **without requiring** the sender and recipient to be P2P peers who pre-establish a channel. Here are crucial goals of Thunderbolt:

1. **No pre-built P2P channel requirement**
   - Sender and recipient do _not_ need an existing channel or a prior interactive relationship.
   - We introduce a **committee** to provide liveness and correctness under a defined trust assumption (the major part of the committee must stay live and honest).

2. **Recipient can be offline**
   - The recipient does _not_ need to be online at the same time as the sender for a transfer to succeed.

3. **No sender–recipient counterparty risk (assuming an honest committee)**
   - If the committee is honest, the sender and recipient are not each other’s counterparty in the payment-channel sense.

4. **Fast transfers; avoid heavy general-purpose ZK**
   - The protocol avoids complex ZK systems (e.g., zkVMs).
   - Transfers should be **seconds-level** and resource-light, using only **purpose-built, lightweight proofs**.

5. **Applies to Bitcoin**
   - Funds remain locked in a Bitcoin UTXO under a **fixed Taproot key-path pubkey**.
   - Final settlement is a standard on-chain spend (no Bitcoin consensus changes required).

## Core Architecture

Thunderbolt is an **off-chain ownership-transfer layer for a single Bitcoin UTXO**. Funds remain locked on Bitcoin under a **fixed Taproot key-path public key** $P$. Off-chain, the “right to redeem” that UTXO is transferred between users by updating a ledger state and delivering the new holder secret to the recipient **asynchronously** (the recipient can prepare an invoice ahead of time and be offline during the sender’s transfer). Both parties only need access to the same ledger $L$; they do not need a direct P2P session at transfer time.

### Key idea and invariant

There are two secret-share parties for the _same_ on-chain key $P$:

- The **current holder** knows a scalar $x_s$.
- The **committee** holds (threshold-wise) a scalar $y_s$.

They satisfy the invariant:

$$
P = (x_s + y_s)\,G \quad \text{for every step } s.
$$

The ledger publishes a per-step **public anchor** that binds the current holder share:

$$
X_s := x_s \cdot H,
$$

where $H\in\mathbb{G}$ is a protocol-fixed base point used only for anchors. We use an anchor-only base point $H$ (independent of $G$) to avoid cross-protocol linkage between the on-chain signing key and the public ownership anchor.

Each transfer uses a fresh **refresh scalar** $r_s$ (chosen by the invoice/recipient and unknown to the sender). Intuitively, $r_s$ is needed to (i) re-randomize the holder secret/anchor so the new owner’s state is fresh and unlinkable to the old one, while (ii) applying an equal-and-opposite update to the committee share so the fixed on-chain key $P$ remains unchanged. Concretely, $r_s$ updates **both** sides in opposite directions:

$$
x_{s+1} = x_s + r_s \pmod q,\qquad
y_{s+1} = y_s - r_s \pmod q,
$$

so the sum $x_s+y_s$ (hence the on-chain pubkey $P$) stays constant, while the owner changes off-chain. The anchor updates consistently via a public commitment:

$$
X_{s+1} = X_s + D_s,\quad D_s := r_s \cdot H.
$$

At registration (step $s=0$), we initialize $x_0$ for the first holder and $y_0 := x_c$ for the committee, so

$$
P = (x_0 + x_c)\,G.
$$

Over many transfers, let the refresh scalars be $r_0, r_1, \dots, r_{n-1}$. Then the holder share evolves as

$$
x_n = x_0 + \sum_{j=0}^{n-1} r_j \pmod q.
$$

In parallel, the committee’s threshold-held share is refreshed in the opposite direction:

$$
y_n = x_c - \sum_{j=0}^{n-1} r_j \pmod q.
$$

Therefore the joint signing key used at redeem time is

$$
(x_n + y_n)G
= \Bigl(x_0 + \sum_{j=0}^{n-1} r_j + x_c - \sum_{j=0}^{n-1} r_j\Bigr)G
= (x_0 + x_c)G
= P,
$$

so a joint Schnorr signature produced by the latest holder (using $x_n$) and the committee (using its current refreshed shares for $y_n$) verifies under the **same fixed** on-chain pubkey $P$.

### Lifecycle

1. **Register**: lock the UTXO to the fixed pubkey $P$ on Bitcoin, then create a ledger context bound to that outpoint $U_{out}$ (keyed by a fresh $\texttt{ctx\_id}$). Publish the initial anchor $X_0 = x_0 H$.

2. **Transfer (repeatable)**: the recipient pre-publishes a **one-time invoice** to the ledger. The invoice samples a fresh refresh scalar $r$ and commits to $D=rH$ (denoted $r_s$ and $D_s$ when consumed at step $s\to s{+}1$). It contains ciphertext material that lets the sender form a takeover ciphertext for the recipient **without learning $r_s$**. Using the invoice, the sender:
   - updates the anchor to $X_{s+1}=X_s+D_s$,
   - posts a new holder ciphertext that the recipient can decrypt to obtain $x_{s+1}=x_s+r_s$,
   - and the ledger verifies the one-time-ness and the state-update proof before appending the next state.

3. **Redeem**: the current holder proves ownership of the latest anchor (knowledge of $x_n$ such that $X_n=x_nH$) and co-signs with the committee to produce a single BIP340 Schnorr signature under the fixed $P$, then spends the UTXO on Bitcoin.

### Components

- **Bitcoin L1 UTXO (fixed lock)**
  - Funds are locked to a fixed Taproot key-path pubkey $P$.
  - Redemption is a standard on-chain spend; no consensus changes.

- **Off-chain ledger $L$ (state + verifier)**
  - Maintains a per-UTXO context $\texttt{ctx\_id}$ with a monotone step index $s$.
  - Enforces one-time invoices and verifies compact proofs for registration/transfer/redeem-readiness.

- **Public anchor $X_s$**
  - A per-step public commitment $X_s=x_sH$ that lets anyone verify anchor transitions $X_{s+1}=X_s+D_s$.

- **Verifiably-encrypted invoice (one-time)**
  - Created/published by the recipient ahead of time (supporting “recipient offline” at transfer time).
  - Samples a refresh scalar $r$ and commits to $D=rH$ (denoted $r_s$ and $D_s$ when consumed at step $s\to s{+}1$), and includes:
    - a distinguished **recipient slot** (slot 0) carrying the recipient ciphertext, enabling the sender to construct a takeover ciphertext for the recipient without learning $r_s$,
    - **committee ciphertext slots** carrying encrypted refresh shares that deliver the information needed for the committee’s threshold-held share update,
    - NIZKs/Σ-proofs binding ciphertext plaintexts to the public commitments (Fiat–Shamir), as summarized in Appendix.

- **Committee (threshold co-signer)**
  - Holds a threshold share of $y_s$ and updates it each transfer using the invoice refresh information.
  - Committee members may apply these updates online per transfer, or reconstruct their current shares later by replaying the invoice history recorded on $L$.
  - At redemption, a threshold subset runs a FROST-style protocol to produce the committee-side partial, which is aggregated with the holder’s partial into a final BIP340 signature under $P$.

# Formalization

This section presents a self-contained formalization of Thunderbolt as:

- an off-chain ledger state machine,
- one-time invoice transcripts recorded on the ledger, implemented as VESS/PVSS-style verifiable encryption of Shamir refresh shares (Paillier-based; see Appendix),
- a small set of lightweight, purpose-built NIZKs for registration, transfer, and redeem-readiness.

## Participants and Notation

### Bitcoin / BIP340 / secp256k1 (standard)

|     Symbol     | Meaning                                                                   |
| :------------: | :------------------------------------------------------------------------ |
|      $G$       | secp256k1 base point (BIP340/Schnorr).                                    |
|      $q$       | secp256k1 group order (prime).                                            |
| $\mathbb{Z}_q$ | Scalar field modulo $q$.                                                  |
|  $\mathbb{G}$  | secp256k1 group (additive notation).                                      |
|      $m$       | BIP340 signing message/digest (the 32-byte value being signed at redeem). |

### Thunderbolt (protocol-specific)

|           Symbol            | Meaning                                                                                                             |
| :-------------------------: | :------------------------------------------------------------------------------------------------------------------ |
|      $\texttt{Alice}$       | Current holder at step $s$ (knows the holder scalar $x_s$).                                                         |
|       $\texttt{Bob}$        | Recipient at step $s{+}1$.                                                                                          |
|             $C$             | Committee (threshold signers using FROST).                                                                          |
|             $n$             | Committee size (member indices are $i\in[n]$).                                                                      |
|             $t$             | Threshold parameter for the committee (e.g., $t$-of-$n$ for FROST/Shamir).                                          |
|             $L$             | Thunderbolt ledger (off-chain state machine + proof verifier).                                                      |
|            $x_0$            | Initial holder scalar chosen at registration.                                                                       |
|            $x_s$            | Holder scalar at step $s$.                                                                                          |
|            $y_s$            | Committee aggregate secret at step $s$ (held threshold-wise; never reconstructed in full).                          |
|            $y_0$            | Committee aggregate secret at registration (output of committee DKG); also denoted $x_c$ in some contexts.          |
|          $y_{s,i}$          | Committee member $i$’s FROST signing share at step $s$ (Shamir share of $y_s$).                                     |
|            $P_c$            | Committee Schnorr public key at registration: $P_c = y_0 G$.                                                        |
|             $P$             | Fixed joint lock key: $P = (x_0 + y_0)G = x_0 G + P_c$.                                                             |
|             $H$             | Protocol-fixed public base point for anchors (independent of $G$).                                                  |
|     $\texttt{ctx\_id}$      | Ledger context identifier for a locked UTXO instance (indexes the off-chain state for that UTXO).                   |
|             $s$             | Monotone step index within a given $\texttt{ctx\_id}$.                                                              |
|          $U_{out}$          | Locked Bitcoin UTXO reference bound to $\texttt{ctx\_id}$ (e.g., $(txid, vout, P, amount)$).                        |
|            $X_s$            | Public anchor: $X_s := x_s H$.                                                                                      |
|            $r_s$            | Refresh scalar sampled by the invoice at transfer $s\to s{+}1$.                                                     |
|            $D_s$            | Refresh commitment: $D_s := r_s H$.                                                                                 |
|         $chain\_id$         | Domain-separation tag for this spec. Default is "thunderbolt".                                                      |
|        $pk_u, sk_u$         | User $u$’s Paillier keypair.                                                                                        |
|          $nonce_u$          | Ledger-tracked monotone nonce for user identity $pk_u$ (used in $\texttt{ctx\_id}$ derivation to avoid collisions). |
|    $pk_{C,i}, sk_{C,i}$     | Committee member $i$’s Paillier keypair (receives encrypted refresh shares in invoices).                            |
| $\mathrm{Enc}_{pk}(m;\eta)$ | Paillier encryption of an encoded scalar $m\in\mathbb{Z}_q$ (decoded and reduced mod $q$ after decryption).         |
|           $\eta$            | Fresh Paillier encryption randomness used in $\mathrm{Enc}_{pk}(m;\eta)$.                                           |
|   $\mathrm{Dec}_{sk}(ct)$   | Paillier decryption.                                                                                                |
|          $\oplus$           | Paillier homomorphic add (ciphertext multiply).                                                                     |
|          $\ominus$          | Paillier homomorphic subtract (multiply by inverse).                                                                |
|        $\mathcal{I}$        | One-time invoice transcript (verifiable encryption of refresh shares; see Appendix).                                |
|     $\texttt{inv\_id}$      | One-time invoice identifier (ledger enforces one-time use).                                                         |
|            $T_s$            | Holder ciphertext at step $s$: Paillier encryption under $pk_s$ that decrypts to the current holder scalar $x_s$.   |
|    $\pi_{\mathrm{reg}}$     | Registration NIZK (lightweight).                                                                                    |
|         $\pi_{s+1}$         | Transfer state-update NIZK (lightweight).                                                                           |
|   $\pi_{\mathrm{redeem}}$   | Redeem-readiness NIZK (lightweight).                                                                                |

### Core invariant

We reuse the invariant described in the Overview: [Core Architecture](#core-architecture). For each step $s$, the fixed on-chain Taproot pubkey is $P=(x_s+y_s)G$ and the public anchor is $X_s=x_sH$. Transfers apply a refresh scalar $r_s$ such that $x_{s+1}=x_s+r_s$, $y_{s+1}=y_s-r_s$, and $X_{s+1}=X_s+r_sH$. Committee members realize the same aggregate update by decrypting Shamir shares $r_{s,i}$ from invoices and updating their signing shares linearly, $y_{s+1,i}=y_{s,i}-r_{s,i}\pmod q$.

## Ledger

### Model and Assumption

We model the Thunderbolt ledger $L$ as a single logical off-chain service that:

- maintains a **totally ordered** append-only log of updates per context $\texttt{ctx\_id}$,
- ensures there is **exactly one latest (alive) row** per context,
- enforces one-time usage of invoices via a global spent set.

This section specifies the state machine behavior; concrete deployment (committee-hosted service, replicated service, etc.) is orthogonal.

### Global State

The ledger stores global parameters and replay-prevention state:

- **Committee configuration**
  - committee Schnorr public key $P_c$ and member index set,
  - the anchor base point $H\in\mathbb{G}$ (independent of $G$),
  - committee members’ Paillier public keys $\{(i, pk_{C,i})\}$.

- **User registry**
  - a registry of registered user identity keys $pk_u$,
  - the current monotone nonce $\texttt{nonce}_u(pk_u)\in\mathbb{N}$ for each registered identity (issued at registration and advanced by the ledger as needed).

- **One-time invoice spent set**
  - $\texttt{spent}(\texttt{inv\_id})\in\{\texttt{false},\texttt{true}\}$,
  - any invoice reuse is rejected.

- **Locked UTXO used set**
  - $\texttt{used}(U_{out})\in\{\texttt{false},\texttt{true}\}$,
  - reject $\mathrm{register}(\cdot)$ if $\texttt{used}(U_{out})=\texttt{true}$ (prevents multiple contexts from claiming the same locked UTXO); once set to $\texttt{true}$ it is never cleared.

- **One-time invoice pool (ledger-hosted)**
  - a set of published one-time invoices keyed by $\texttt{inv\_id}$,
  - reject invoice publication if $\texttt{inv\_id}$ already exists,
  - each invoice record contains the full invoice transcript $\mathcal{I}$ (including $pk_B$, $D$, encrypted slots, and their validity proofs).

### Per-UTXO Context State

For each locked UTXO output $U_{out}$, the ledger derives a context identifier (notice it is a pure function could be also computed by Alice):

$$
\texttt{ctx\_id} = \mathsf{Hash}\!\left(chain\_id\ \|\ pk_u\ \|\ nonce_u\ \|\ U_{out}\right),
$$

where $pk_u$ is the submitter’s registered Paillier public key and $nonce_u$ is a ledger-tracked monotone nonce for that identity (to avoid collisions). Concretely, $nonce_u$ refers to the current value $\texttt{nonce}_u(pk_u)$ in the user registry at the time the context is created.

The ledger maintains a monotone step index $s\in\{0,1,2,\dots\}$. Each $(\texttt{ctx\_id}, s)$ identifies a unique state row, with exactly one “latest” row per context.

Each state row stores:

| Field              | Description                                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------------------- |
| $\texttt{ctx\_id}$ | Context identifier.                                                                                                 |
| $s$                | Step index within the context.                                                                                      |
| $U_{out}$          | Locked UTXO reference (e.g., $(txid, vout, P, amount)$).                                                            |
| $P$                | Fixed Taproot key-path public key locking $U_{out}$.                                                                |
| $pk_s$             | Current holder’s Paillier public key.                                                                               |
| $X_s$              | Public anchor at step $s$ (ownership commitment).                                                                   |
| $T_s$              | Holder ciphertext at step $s$: a Paillier encryption under $pk_s$ that decrypts to the current holder scalar $x_s$. |
| $\texttt{inv\_id}$ | One-time invoice identifier consumed at step $s$ (empty at $s=0$).                                                  |
| $\mathcal{I}_s$    | One-time invoice transcript consumed at step $s$ (empty at $s=0$).                                                  |
| $alive$            | Only the latest row has $alive=true$; after redeem, the latest row sets $alive=false$.                              |

### Responsibilities

- Maintain per-context total order and latest-row uniqueness.
- Verify NIZKs for registration, transfer, and redeem-readiness.
- Verify invoice validity and enforce one-time usage via $spent(\texttt{inv\_id})$.
- Publish committee configuration needed to construct and verify invoices and signatures.

## Thunderbolt Workflow

At a high level, the workflow expands the lifecycle described in the Overview: [Lifecycle](#lifecycle). (i) **Register** locks the UTXO under the fixed key $P$ and creates the initial ledger row $(\texttt{ctx\_id},0)$. (ii) **Transfer** consumes a one-time invoice $\texttt{inv\_id}$ to advance the public anchor and the holder ciphertext to step $s{+}1$, allowing the recipient to take over asynchronously. (iii) **Redeem** proves the latest ownership state and produces a single on-chain spend under $P$ via a joint holder+committee BIP340 signature.

Throughout these steps, the ZK proofs we use are **compact, purpose-built NIZKs** over (a) Schnorr-style linear relations in secp256k1 and (b) Paillier encryption consistency. We do **not** require general-purpose ZK circuits, which are costly in general.

### Unified EC–Paillier NIZK template

Thunderbolt repeatedly needs to prove that **the same scalar** $x\in\mathbb{Z}_q$ is:

- the discrete log of one or more public EC points (under public bases), and
- the plaintext hidden inside a Paillier ciphertext (optionally up to a public offset ciphertext).

We use a single generalized Schnorr/Chaum–Pedersen-style Σ-protocol, made non-interactive via Fiat–Shamir.

- **Inputs (statement):**
  - a domain tag $\texttt{tag}\in\{\texttt{tb/reg},\texttt{tb/xfer},\texttt{tb/redeem}\}$,
  - a context binding tuple that always includes $\texttt{ctx\_id}$, and additionally binds:
    - for $\texttt{tb/reg}$: $U_{out}$,
    - for $\texttt{tb/xfer}$: the step index $s{+}1$ and invoice identifier $\texttt{inv\_id}$,
    - for $\texttt{tb/redeem}$: the step index $n$ and the spend message/digest $m$,
  - EC relations of the form $Y_i = xB_i$ (e.g., $(B_i,Y_i)=(G,P-P_c)$ or $(H,X_s)$), where the statement explicitly includes the public bases $B_i$ and points $Y_i$,
  - optionally, a Paillier relation of the form $C = \mathrm{Enc}_{pk}(x;\eta)\ \oplus\ C_0$, where the statement explicitly includes the Paillier public key $pk$ and the ciphertexts $C$ and $C_0$ (with $C_0$ defaulting to the identity ciphertext).
- **Witness:** $(x,\eta)$ (if the Paillier part is present) or just $x$ (if not).

**Protocol sketch.** Prover samples $t\leftarrow\mathbb{Z}_q$ and Paillier randomness $\rho\in\mathbb{Z}_N^{\times}$ (where $N$ is the modulus embedded in $pk$). It sends EC commitments $A_i := tB_i$ and, if the Paillier part is present, $E := \mathrm{Enc}_{pk}(t;\rho)$. The challenge is

$$
c := \mathsf{Hash}(\texttt{tag},\texttt{ctx\_id},\text{(other bound fields)},\text{(all statement elements)},\text{(all commitments)})\bmod q.
$$

The response is $z := t+cx\pmod q$ and (if Paillier is present) $\tau := \rho\cdot\eta^{\,c}$ (randomness group multiplication in $\mathbb{Z}_N^{\times}$). Verification checks:

$$
zB_i \stackrel{?}= A_i + cY_i\quad \text{for all EC relations } i,
$$

and if Paillier is present,

$$
\mathrm{Enc}_{pk}(z;\tau)\stackrel{?}=E\ \oplus\ (C\ \ominus\ C_0)^{\,c}.
$$

### System Initialization and User Registration

**System initialization (once).** The ledger publishes the global registry needed by all participants, including:

- the committee configuration (FROST public key $P_c$ and member indices),
- the anchor base point $H\in\mathbb{G}$ (independent of $G$),
- committee members’ Paillier public keys $\{(i, pk_{C,i})\}$,
- the global one-time spent set namespace for invoices (e.g., $spent(\texttt{inv\_id})$).

The concrete setup procedures are delegated to underlying primitives (FROST DKG for $P_c$ and the verifiable-encryption details for invoice structure) and are omitted here.

**User registration.** Each user registers a long-term Paillier public key $pk_u$ as their ledger identity and obtains a ledger-tracked monotone $nonce_u$ used for context id derivation.

**One-time invoice publication (base).** In the base version (where Bob publishes a one-time invoice to receive an asynchronous transfer), Bob first reads the committee registry from the ledger’s global state (in particular, the member index set and Paillier public keys $\{(i, pk_{C,i})\}$). He then publishes an invoice transcript $\mathcal{I}$ (as summarized in Appendix) that includes at least:

- the recipient identity key $pk_B$,
- the refresh commitment $D=rH$,
- the recipient slot ciphertext $ct_0=\mathrm{Enc}_{pk_B}(r)$,
- committee ciphertext slots encrypted under $\{pk_{C,i}\}$ carrying the refresh-share material needed for committee share updates,
- the validity proofs/NIZKs that allow the ledger (and anyone) to verify the encrypted slots are consistent with the public commitments (per Appendix).

The invoice identifier is derived (rather than assigned) as a pure function similar in spirit to $\texttt{ctx\_id}$, e.g.,

$$
\texttt{inv\_id}=\mathsf{Hash}\!\left(chain\_id\ \|\ pk_B\ \|\ \mathcal{I}\right),
$$

where $\mathcal{I}$ is serialized deterministically and excludes $\texttt{inv\_id}$ itself.

### Step 1: Register (create a new context)

**Goal:** create $(\texttt{ctx\_id}, 0)$ for a newly locked UTXO and bind the initial holder share.

**Off-ledger (by Alice):**

- Sample $x_0 \leftarrow \mathbb{Z}_q$.
- Compute the joint lock key:
  $$
  P = x_0 G + P_c \;=\; (x_0 + y_0)G.
  $$
- Lock funds on Bitcoin to Taproot key-path pubkey $P$, obtaining
  $$
  U_{out} = (txid, vout, P, amount).
  $$
- Define the initial public anchor:
  $$
  X_0 := x_0 \cdot H.
  $$
- Create the holder-encrypted ciphertext under Alice’s Paillier key:
  $$
  T_0 := \mathrm{Enc}_{pk_A}(x_0;\eta_0).
  $$
- Generate the registration proof $\pi_{\mathrm{reg}}$ by instantiating the Unified EC–Paillier template.
  - **Tag / binding:** $\texttt{tag}=\texttt{tb/reg}$ and bind $(\texttt{ctx\_id},U_{out})$.
  - **EC relations:** $P-P_c = x_0G$ and $X_0=x_0H$.
  - **Paillier relation:** $T_0=\mathrm{Enc}_{pk_A}(x_0;\eta_0)$.

**Ledger call:**

$$
\mathrm{register}(U_{out}, P, pk_A, X_0, T_0, \pi_{\mathrm{reg}})\ \to\ \texttt{ctx\_id}.
$$

(Here $\texttt{ctx\_id}$ is deterministically derived by the ledger from $U_{out}$ and the submitter identity/$nonce_u$; returning it is a convenience.)

**Ledger checks (high level):**

- Reject if $\texttt{used}(U_{out})=\texttt{true}$; otherwise set $\texttt{used}(U_{out})=\texttt{true}$.
- Verify $\pi_{\mathrm{reg}}$ under $\texttt{tb/reg}$.
- Derive and store $\texttt{ctx\_id}$; insert row $(\texttt{ctx\_id}, 0)$ with $pk_0=pk_A$, $X_0$, $T_0$, and $alive=true$.

### Step 2: Transfer (repeatable)

**Goal:** move ownership from the current holder at step $s$ to a new holder at step $s+1$ using a one-time invoice transcript recorded on the ledger.

**Invoice (ledger-hosted):**

- Before receiving funds, $\texttt{Bob}$ publishes a one-time invoice transcript $\mathcal{I}$ to the ledger under a fresh identifier $\texttt{inv\_id}$.
- The invoice:
  - samples a fresh refresh scalar $r$,
  - commits to $D := rH$ (so anyone can update anchors as $X_{s+1}=X_s + D$),
  - includes Paillier-encrypted slots:
    - a **recipient slot** $ct_0 = \mathrm{Enc}_{pk_B}(r)$,
    - **committee slots** encrypting Shamir shares of $r$ under $\{pk_{C,i}\}$,

**Off-ledger (by the current holder, who knows $x_s$):**

- Read $D$ and $ct_0$ from $\mathcal{I}$ via $\texttt{inv\_id}$ and denote $r_s:=r$ and $D_s:=D$ for this consumed step.
- Update the public anchor:
  $$
  X_{s+1} := X_s + D_s.
  $$
- Form the takeover ciphertext encrypted to $\texttt{Bob}$:
  $$
  T_{s+1} := \mathrm{Enc}_{pk_B}(x_s;\eta_s)\ \oplus\ ct_0,
  $$
  so that $T_{s+1}$ decrypts to $x_{s+1} = x_s + r_s \pmod q$ under $sk_B$.
- Generate the transfer proof $\pi_{s+1}$ by instantiating the Unified EC–Paillier template.
  - **Tag / binding:** $\texttt{tag}=\texttt{tb/xfer}$ and bind $(\texttt{ctx\_id},s{+}1,\texttt{inv\_id})$.
  - **EC relation:** $X_s=x_sH$.
  - **Paillier relation:** $T_{s+1}\ \ominus\ ct_0 = \mathrm{Enc}_{pk_B}(x_s;\eta_s)$.
  - **Public (non-ZK) transition check:** the ledger also checks $X_{s+1}=X_s+D_s$ using the committed $D_s$ from $\mathcal{I}$.

**Ledger call:**

$$
\mathrm{transfer}(\texttt{ctx\_id}, s{+}1, pk_B, X_{s+1}, T_{s+1}, \texttt{inv\_id}, \mathcal{I}, \pi_{s+1}).
$$

**Ledger checks (high level):**

- **Invoice one-time:** reject if $spent(\texttt{inv\_id})=true$, otherwise set $spent(\texttt{inv\_id})=true$.
- **Invoice validity:** verify the invoice transcript validity proofs/NIZKs carried in $\mathcal{I}$ (in particular, that the encrypted slots are consistent with the public commitments such as $D=rH$, per Appendix).
- Verify $\pi_{s+1}$ under $\texttt{tb/xfer}$.
- Append row $(\texttt{ctx\_id}, s{+}1)$ with $pk_{s+1}=pk_B$, $X_{s+1}$, $T_{s+1}$; store $\texttt{inv\_id}$ and $\mathcal{I}$; mark it $alive=true$ and prior row $alive=false$.

**Post-transfer effects:**

- **$\texttt{Bob}$** decrypts $T_{s+1}$ to obtain $x_{s+1}$.
- **Committee** members may process online per transfer, or defer and later replay the invoice history:
  each member decrypts its invoice slot to obtain $r_{s,i}$ and updates its share as
  $$
  y_{s+1,i} = y_{s,i} - r_{s,i}\pmod q.
  $$
  Equivalently, if the committee’s aggregate secret $y_s$ is Shamir-shared by a degree-$(t{-}1)$ polynomial $f_s(x)$ with $f_s(0)=y_s$ and shares $y_{s,i}=f_s(i)$, and the invoice defines a degree-$(t{-}1)$ refresh polynomial $\omega_s(x)$ with $\omega_s(0)=r_s$ and refresh shares $r_{s,i}=\omega_s(i)$, then the updated sharing is just polynomial subtraction:
  $$
  f_{s+1}(x) := f_s(x) - \omega_s(x),
  $$
  so $f_{s+1}(0)=y_s-r_s=y_{s+1}$ and each member locally updates $f_{s+1}(i)=y_{s,i}-r_{s,i}$ without reconstructing $y_s$.

### Step 3: Redeem (close the context on Bitcoin)

**Goal:** prove current ownership off-chain and produce a single on-chain spend under the fixed $P$ via a joint holder+committee signature.

**Off-ledger (by the current holder at step $n$):**

- Decrypt the latest ciphertext $T_n$ to obtain the current holder scalar $x_n$.
- Construct the Taproot key-path spend message/digest $m$ for $U_{out}$ under pubkey $P$.
- Generate $\pi_{\mathrm{redeem}}$ by instantiating the Unified EC–Paillier template with **no Paillier part** (EC-only case).
  - **Tag / binding:** $\texttt{tag}=\texttt{tb/redeem}$ and bind $(\texttt{ctx\_id},n,m)$.
  - **EC relation:** $X_n=x_nH$.

**Ledger call:**

$$
\mathrm{redeem}(\texttt{ctx\_id}, n, m, \pi_{\mathrm{redeem}}).
$$

**Ledger checks (high level):**

- Verify $\pi_{\mathrm{redeem}}$ under $\texttt{tb/redeem}$ (in particular, $X_n=x_nH$ bound to $(\texttt{ctx\_id}, n, m)$).
- If valid, emit a redeem-ready record for $(\texttt{ctx\_id}, n, m)$.

**Signing (holder + committee):**

- The holder contributes a Schnorr partial response using $x_n$.
- The committee reconstructs its **current** signing shares by replaying the invoice history $\{\mathcal{I}_j\}_{j=1}^n$ from the ledger (or using cached updates), then a threshold subset runs FROST to produce the committee-party partial for the same message $m$.
- Aggregate the holder partial and committee partial into a valid BIP340 Schnorr signature under $P$, and broadcast the Bitcoin transaction spending $U_{out}$.

**State update:**

- After a valid on-chain spend is produced/observed, mark the latest row as $alive=false$.

# Appendix

This appendix records background assumptions and standard building blocks used by the Thunderbolt protocol.

## Verifiable encryption of Shamir shares (VESS/PVSS-style invoices)

Thunderbolt’s “one-time invoice transcript” is a VESS/PVSS-style dealing that verifiably encrypts Shamir shares of a refresh scalar to a set of recipients (Bob and the committee).
For background on **verifiable encryption of discrete logarithms under Paillier/DCR-type assumptions** and its security properties, we refer to:

- J. Camenisch and V. Shoup, _Practical Verifiable Encryption and Decryption of Discrete Logarithms_, Cryptology ePrint Archive, Paper 2002/161 (`https://eprint.iacr.org/2002/161`).

In our setting, the invoice samples a degree-$(t{-}1)$ polynomial

$$
\omega_s(x)\in\mathbb{Z}_q[x]_{<t}\quad\text{with}\quad \omega_s(0)=r_s,
$$

and defines refresh shares $r_{s,i}:=\omega_s(i)$ for committee member indices $i\in[n]$.
It publishes a public commitment to the constant term under the anchor base:

$$
D_s := r_s H = \omega_s(0)\,H.
$$

To make shares publicly checkable (without revealing them), the invoice can also publish Feldman-style coefficient commitments under the base point $H$:

$$
A_k := a_k H\quad\text{for coefficients}\quad \omega_s(x)=\sum_{k=0}^{t-1} a_k x^k.
$$

Then anyone can derive the committed share-point for index $i$ as

$$
R_{s,i} := \omega_s(i)\,H = \sum_{k=0}^{t-1} i^k A_k.
$$

A one-time invoice transcript $\mathcal{I}$ therefore contains:

- a public refresh commitment $D_s=r_sH$ (and optionally coefficient commitments $\{A_k\}$),
- a recipient ciphertext slot $ct_0=\mathrm{Enc}_{pk_B}(r_s)$ together with a NIZK/Σ-proof that the encrypted plaintext equals the discrete log of $D_s$ w.r.t. $H$ (i.e., verifiable encryption of a discrete log, as in Camenisch–Shoup),
- committee ciphertext slots $ct_i=\mathrm{Enc}_{pk_{C,i}}(r_{s,i})$ together with NIZKs proving that the encrypted plaintext equals the discrete log of $R_{s,i}$ w.r.t. $H$ (hence all encrypted shares are consistent with the committed polynomial and with $D_s$).

## Paillier encryption (additively homomorphic)

Thunderbolt uses Paillier encryption to carry scalars in a way that supports homomorphic addition:
encryptions can be combined so that ciphertext operations correspond to addition/subtraction of plaintext scalars (modulo $q$ after decoding).
Security relies on standard Paillier semantic security assumptions for the chosen key sizes.

Concretely, for plaintext scalars $a,b\in\mathbb{Z}_q$ (encoded into Paillier’s plaintext space), Paillier supports:

$$
\mathrm{Enc}_{pk}(a;\eta_a)\ \oplus\ \mathrm{Enc}_{pk}(b;\eta_b)\ =\ \mathrm{Enc}_{pk}(a+b;\eta),
$$

and similarly $\ominus$ corresponds to subtraction. Thunderbolt uses this to form takeover ciphertexts like

$$
T_{s+1} := \mathrm{Enc}_{pk_B}(x_s;\eta_s)\ \oplus\ \mathrm{Enc}_{pk_B}(r_s),
$$

so that decrypting yields $x_{s+1}=x_s+r_s \pmod q$.

## Schnorr signatures on secp256k1 (BIP340) and threshold signing

Thunderbolt ultimately settles on Bitcoin using a single BIP340 Schnorr signature under a fixed Taproot key-path public key.
The committee acts as a threshold signing party (e.g., FROST-style) holding Shamir shares of its aggregate secret; the current holder provides the complementary share so that the joint public key remains constant across off-chain transfers.

At any step $s$, the fixed on-chain public key is

$$
P = (x_s+y_s)G,
$$

where the holder knows $x_s$ and the committee holds Shamir shares of $y_s$. At redeem time, the holder and a threshold of committee members produce Schnorr partials for the same message $m$ that aggregate into a valid BIP340 signature under $P$.
