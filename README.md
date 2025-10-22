# Thunderbolt Workflow Description

This document describes the complete Thunderbolt protocol workflow — a secure, verifiable off-chain ownership transfer mechanism for Bitcoin UTXOs locked under a joint user–committee key.

# Participants and Notation

|       Symbol        | Meaning                                                                                      |
| :-----------------: | :------------------------------------------------------------------------------------------- |
|       $Alice$       | Current user (holder of the user-side share)                                                 |
|        $Bob$        | Next user (recipient)                                                                        |
|       $Zeta$        | The redeem user (the final holder who performs the on-chain redemption)                      |
|         $C$         | Committee (threshold signers with long-term keys)                                            |
|         $L$         | Thunderbolt ledger (off-chain state and proof verifier)                                      |
|         $G$         | Base point of secp256k1 used in Bitcoin                                                      |
|        $P_c$        | Committee’s Schnorr public key                                                               |
|       $pk_c$        | Committee’s Paillier public key                                                              |
|       $\rho$        | Pedersen blinding factor sampled uniformly from $\mathbb{Z}_q$, used in Pedersen commitment. |
|   $\mathrm{Com}$    | Pedersen commitment function defined as $\mathrm{Com}(y, \rho) = y H_1 + \rho H_2$           |
| $\mathrm{Enc}_{pk}$ | Paillier encryption defined as $\mathrm{Enc}_{pk}(m; r) = g^m \, r^N \bmod N^2$              |

# Thunderbolt Ledger Interface

The Thunderbolt ledger maintains the state of each locked UTXO and verifies zero-knowledge proofs for every ownership transfer and redemption.

## User Identity on Ledger

- user_id: Users are identified by their Paillier public key ($pk\_{user}$).
- nonce: Each user has an associated ledger-tracked $nonce$ (a monotonic counter).

## Ledger State Schema

A Thunderbolt state table uses a **composite primary key**:

- $\text{ctx\_id}$: created at register, $\text{ctx\_id} = \text{Hash}(\text{chain\_id} \|\| \text{user\_id} \|\| \text{nonce} \|\| \text{outpoint})$.
- $\text{s}$: sequence number for this context (starts at $0$; increments by $1$ per valid transfer).

Each $(\text{ctx\_id}, \text{s})$ pair defines exactly one state row.

### Columns (per row)

| Field             | Description                                                                                                                                                                                                    |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| $\text{ctx\_id}$  | Context ID as above.                                                                                                                                                                                           |
| $\text{s}$        | Sequence number for this row ($\text{seq} = \text{s}$). Starts at $0$ and increments by $1$ after each valid transfer.                                                                                         |
| $\text{outpoint}$ | Reference to the locked UTXO, typically $\text{outpoint} = (\text{txid}, \text{vout}, P, \text{amount})$.                                                                                                      |
| $P$               | Joint public key $P = P_{x_n} + P_c = (x_n + x_c)\,G$. Must equal the $P$ embedded in $\text{outpoint}$.                                                                                                       |
| $\text{Tc}_s$     | Committee mask ciphertext at sequence $\text{s}$. For $\text{s}=0$, $\text{Tc}_0 = \varnothing$. For $\text{s} \ge 1$, $\text{Tc}_s = \mathrm{Enc}_{pk_c}(t_s)$.                                               |
| $\text{Tr}_s$     | Recipient takeover ciphertext for the $\text{s} \!\to\! \text{s}{+}1$ hop. For $\text{s}=0$, $\text{Tr}_0 = \varnothing$. For $\text{s} \ge 1$, $\text{Tr}_s = \mathrm{Enc}_{pk_{U_{\text{s}+1}}}(y_s + t_s)$. |
| $\text{Com}_s$    | Current Pedersen commitment $\mathrm{Com}(y_s, \rho_s) = y_s H_1 + \rho_s H_2$ (commits to the **current** holder’s share $y_s$ at sequence $\text{s}$).                                                       |
| $\text{alive}$    | Context liveness flag. **Only the latest row** ($\text{s} = \text{current\_seq}$) has $\text{alive} = \text{true}$. After redeem, the **final row** sets $\text{alive} = \text{false}$.                        |

## Ledger Functions

| Function                                                                           | Purpose                                                                                                            |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| $\mathrm{register}(\text{outpoint}, P, \text{Com}_0, \pi_{\text{init}})$           | Register a newly locked UTXO on the ledger and commit about the initial share $x_n$.                               |
| $\mathrm{transfer}(\text{ctx\_id}, \text{Tc}_s, \text{Tr}_s, \text{Com}_s, \pi_s)$ | Execute an ownership transfer verified by a zero-knowledge proof.                                                  |
| $\mathrm{redeem}(\text{ctx\_id}, m, \pi_{\text{redeem}})$                          | Redeem the locked Bitcoin output. Verifies ownership and closes the context immediately upon successful signature. |

# Thunderbolt Workflow

## System Initialization (Once)

1. The committee generates:

   - Threshold Schnorr key: private share $x_c$, public $P_c = x_c \cdot G$
   - Threshold Paillier key: $pk_c = (N_C, g_C)$
   - Pedersen bases $(H_1, H_2)$

2. Publish parameters $(P_c, pk_c, H_1, H_2)$ to the ledger.

---

> **Workflow Overview:**  
> After the system parameters are initialized, each UTXO goes through three main lifecycle phases:  
> **Preparing**, **Transferring**, and **Redeeming** between the Bitcoin main chain and the Thunderbolt layer.

---

## Step 1: Prepare Funds (Alice on Bitcoin L1)

Alice created her initial key share, combined it with the committee to form the joint key, locked BTC to that key on Bitcoin, computed the initial commitment, and registered the UTXO on the Thunderbolt ledger with a zero-knowledge proof to obtain a context ID.

### Before Call Ledger (Preparation)

- Generate the user share and the joint key:
  - Sample $x_0 \leftarrow \mathbb{Z}_q$ and set $P_{x_0} = x_0 G$.
  - Compute $P = P_{x_0} + P_c = (x_0 + x_c)\,G$.
- Lock BTC on Bitcoin L1 to Taproot key-path with public key $P$, obtaining
  - $\text{outpoint} = (\text{txid}, \text{vout}, P, \text{amount})$.
- Sample the Pedersen blinding factor $\rho_0 \leftarrow \mathbb{Z}_q$ and compute the initial commitment; Define $y_0 := x_0$ (the initial user share), and set:
  $\text{Com}_0 = \mathrm{Com}(y_0, \rho_0) = y_0 H_1 + \rho_0 H_2$.
- Query current nonce for user_id and compute ctx_id accordingly.

### The Call (inputs and binding)

Call:

$$
\mathrm{register}\big(\text{outpoint}, P, \text{Com}_0, \pi_{\text{init}} \big)\ \to\ \text{ctx\_id}.
$$

- $\pi_{\text{init}}$ is the ZK proof for this step (see below).
- Upon receiving the call, the ledger creates and returns $\text{ctx\_id}$ and atomically increments the caller’s ledger-tracked $\text{nonce}$.

### Ledger ZKP verification (Register proof)

**Public input (all absorbed into the Fiat–Shamir challenge):**

$$
\{\ \text{ctx\_id},\ \text{s}=0,\ P,\ P_c,\ \text{Com}_0\ \}.
$$

**Witness:**

$$
\{\, x_0,\ \rho_0 \,\}.
$$

**Constraints to prove:**

$$
P = x_0 G + P_c,\qquad \text{Com}_0 = x_0 H_1 + \rho_0 H_2.
$$

**Fiat–Shamir domain (register):**

$$
\mathcal{H}_{\mathrm{FS}}^{\mathrm{reg}}
= H\!\big(\text{``TB/register''}\ \|\ \text{ctx\_id}\ \|\ s = 0\ \|\ P\ \|\ P_c\ \|\ \text{Com}_0\big).
$$

### State persistence (new row in the schema)

On success, insert a row with composite key $(\text{ctx\_id},\ \text{s}=0)$:

- $\text{ctx\_id}$ = computed value,
- $\text{s}$ = 0,
- $\text{outpoint}$ = provided value,
- $P$ = provided value,
- $\text{Tc}_0$ = $\varnothing$,
- $\text{Tr}_0$ = $\varnothing$,
- $\text{Com}_0$ = provided value,
- $\text{alive}$ = $\text{true}$.

## Step 2: Ownership Transfer (Alice -> Bob)

Transfers ownership from the current holder to the next by encrypting the updated share to the recipient and the mask to the committee, proving correctness in zero-knowledge, and advancing the ledger state with a new commitment and sequence.

### Before Call Ledger (Preparation by Alice)

Assume Alice is the current holder at $(\text{ctx\_id}, \text{s})$ and knows $(y_{\text{s-1}}, \rho_{\text{s-1}})$ such that
$\text{Com}_{\text{s-1}} = \mathrm{Com}(y_{\text{s-1}}, \rho_{\text{s-1}}) = y_{\text{s-1}} H_1 + \rho_{\text{s-1}} H_2$.

- Obtain Bob’s Paillier public key $pk_{r_{\text{s}}}$.
- Sample randomness:
  - $t_{\text{s}} \leftarrow \mathbb{Z}_q$
  - $r_1 \leftarrow \mathbb{Z}_{N_C^2}^{*}$ (for committee mask)
  - $r_2 \leftarrow \mathbb{Z}_{N_{r_{\text{s}}}^2}^{*}$ (for recipient takeover)
  - $\rho_{\text{s}} \leftarrow \mathbb{Z}_q$
- Compute:
  $$
  \begin{aligned}
  \text{Tc}_{\text{s}} &= \mathrm{Enc}_{pk_c}(t_{\text{s}};\ r_1),\\
  \text{Tr}_{\text{s}} &= \mathrm{Enc}_{pk_{r_{\text{s}}}}\big((y_{\text{s-1}}+t_{\text{s}})\bmod q;\ r_2\big),\\
  y_{\text{s}} &= (y_{\text{s-1}} + t_{\text{s}})\bmod q,\\
  \text{Com}_{\text{s}} &= \mathrm{Com}(y_{\text{s}}, \rho_{\text{s}}).
  \end{aligned}
  $$

### The Call (inputs and binding)

Call:

$$
\mathrm{transfer}\big(\ \text{ctx\_id},\ \text{Tc}_{\text{s}},\ \text{Tr}_{\text{s}},\ \text{Com}_{\text{s}},\ \pi_{\text{s}}\ \big).
$$

### Ledger ZKP verification (generic transfer proof)

**Public input (all absorbed into the Fiat–Shamir challenge):**

$$
\{\ \text{ctx\_id},\ \text{s},\ \text{Com}_{\text{s-1}},\ \text{Com}_{\text{s}},\ \text{Tc}_{\text{s}},\ \text{Tr}_{\text{s}}\ \}.
$$

**Witness:**

$$
\{\, y_{\text{s-1}},\ \rho_{\text{s-1}},\ t_{\text{s}},\ \rho_{\text{s}},\ r_1,\ r_2 \,\}.
$$

**Constraints to prove:**

$$
\begin{aligned}
\text{Com}_{\text{s-1}} &= y_{\text{s-1}} H_1 + \rho_{\text{s-1}} H_2,\\
\text{Com}_{\text{s}} &= (y_{\text{s-1}} + t_{\text{s}}) H_1 + \rho_{\text{s}} H_2,\\
\text{Tc}_{\text{s}} &= g_{C}^{\,t_{\text{s}}}\, r_1^{N_{C}} \bmod N_{C}^{2},\\
\text{Tr}_{\text{s}} &= g_{r_{\text{s}}}^{\,\,y_\text{s}}\, r_2^{N_{r_{\text{s}}}} \bmod N_{r_{\text{s}}}^{2}.
\end{aligned}
$$

**Fiat–Shamir domain (transfer):**

$$
\mathcal{H}_{\mathrm{FS}}^{\mathrm{xfer}}
= H\!\big(\text{``TB/transfer''}\ \|\ \text{ctx\_id}\ \|\ \text{s}\ \|\ \text{Com}_{\text{s-1}}\ \|\ \text{Com}_{\text{s}}\ \|\ \text{Tc}_{\text{s}}\ \|\ \text{Tr}_{\text{s}}\big).
$$

Ledger checks:

- $\text{alive}=\text{true}$ for the latest row,
- supplied $\text{s}$ equals the current sequence plus 1,
- $\pi$ verifies under the FS transcript above.

### State persistence (new row in the schema)

On success, insert the new row with composite key $(\text{ctx\_id},\ \text{s})$:

- $\text{outpoint}$ = carried over (unchanged),
- $P$ = carried over (unchanged),
- $\text{Tc}_{\text{s}}$ = provided value,
- $\text{Tr}_{\text{s}}$ = provided value,
- $\text{Com}_{\text{s}}$ = provided value,
- mark the new row $\text{alive}=\text{true}$; prior latest row remains as immutable history.

### Receiver Side (Bob)

Bob decrypts offline:

$$
y_{\text{s}} = \mathrm{Dec}_{sk_{r_{\text{s}}}}(\text{Tr}_{\text{s}})\ \bmod q.
$$

He securely stores $y_{\text{s}}$ and in practice, pack $\rho_{\text{s}}$ together with $y$ in the Paillier plaintext (e.g., fixed-radix packing) so Bob recovers both from a single decryption; Alice deletes $(y_{\text{s}}, \rho_{\text{s}})$.

## Step 3: Further Transfers (Iterative)

Each subsequent transfer repeats **exactly the Step 2 flow**: the current holder encrypts the new share to the next recipient and the mask to the committee, proves correctness in zero-knowledge (binding to the same `ctx_id` and the next sequence), the ledger appends a new state row with the updated commitment and ciphertexts, the recipient decrypts to obtain both the share and its blinding factor, and the previous holder deletes their old secrets. This process can iterate arbitrarily many times until redemption.

## Step 4: Redeem to Bitcoin L1 (Current Holder Zeta + Committee)

Redeem closes the Thunderbolt context by proving the final commitment opening, compensating the committee’s key share, and jointly producing a MuSig2 signature to spend the L1 UTXO.

---

### 4.1 Before the Call (Preparation by Zeta)

- Zeta (the current holder at row $(\text{ctx\_id}, \text{s}=n)$) controls the opening $(y_n, \rho_n)$ of $\text{Com}_n$.
- Zeta prepares the L1 spend message/transaction `m` (the Taproot key-path spend of `outpoint` bound to `P`).

---

### 4.2 The Call (inputs and binding)

Call:

$$
\mathrm{redeem}\big(\ \text{ctx\_id},\ \text{s}=n,\ m,\ \pi_{\text{redeem}}\ \big).
$$

---

### 4.3 Ledger ZKP verification (Redeem proof)

**Public input (absorbed into FS):**

$$
\{\ \text{ctx\_id},\ \text{s}=n,\ P_n,\ \text{Com}_n\ \}.
$$

**Witness (held by Zeta):**

$$
\{\, y_n,\ \rho_n \,\}.
$$

**Constraint to prove:**

$$
\text{Com}_n = y_n H_1 + \rho_n H_2.
$$

**Fiat–Shamir domain (redeem):**

$$
\mathcal{H}_{\mathrm{FS}}^{\mathrm{redeem}}
= H\!\big(\text{``TB/redeem''}\ \|\ \text{ctx\_id}\ \|\ n\ \|\ P_n \|\ \text{Com}_n\big).
$$

**Ledger checks:**

- `alive == true` on the latest row,
- supplied `n` equals the current sequence,
- $\pi_{\text{redeem}}$ verifies under the FS transcript above.

On success, the ledger emits:

$$
\mathrm{RedeemReady}(\text{ctx\_id},\ \text{s}=n).
$$

### 4.4 Committee computes compensation (from stored masks)

Using the per-row committee masks $\text{Tc}_1,\dots,\text{Tc}_n$ (from all rows of the ledger), the committee:

1. Multiplies them homomorphically to obtain an encryption of the sum $t_\Sigma = \sum_{i=1}^n t_i \bmod q$.
2. Threshold-decrypts to recover $t_\Sigma$.
3. Computes the compensated signing share $x_c' = (x_c - t_\Sigma) \bmod q$.

### 4.5 Two-party schnorr signing and finalization

1. With this convention, the final holder’s share satisfies $y_n = (x_n - t_\Sigma) \bmod q$.
2. Zeta and the committee generate nonces $(k_Z, R_Z)$, $(k_C, R_C)$; set $R = R_Z + R_C$.
3. Compute the challenge $e = H(R \parallel P \parallel m)$.
4. Partial signatures:

   - $s_Z = k_Z + e \cdot y_n$
   - $s_C = k_C + e \cdot x_c'$

   Using $y_n = x_n - t_\Sigma$ and $x_c' = x_c + t_\Sigma$:

   $$
   s_Z + s_C
   = (k_Z + e,y_n) + (k_C + e,x_c')
   = (k_Z + k_C) + e,(x_n - t_{\Sigma} + x_c + t_{\Sigma})
   = (k_Z + k_C) + e,(x_n + x_c),
   $$

   i.e., the two-party Schnorr signature equals signing under the original joint secret (x_n + x_c).

5. Aggregate signature $s = (s_Z + s_C) \bmod q$, $\sigma = (R, s)$.
6. Verify $sG \stackrel{?}= R + eP$. If valid, **broadcast** $(m,\sigma)$ to Bitcoin.

### 4.6 State update (close the context)

- Set `alive := false` on the latest row $(\text{ctx\_id}, n)$.

This completes the Thunderbolt lifecycle for the context; the full history (commitments and ciphertexts) remains on the ledger for verification and auditing.
