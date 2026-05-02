pragma circom 2.1.6;

/*
 * Range proof: prove that `low <= amount <= high`, with `low` and `high`
 * public and `amount` private.  Used by the ZK carrier demo to prove that a
 * UTXO's value falls inside a committed-to band, without revealing the
 * exact value.
 *
 * Replay protection (mirrors the PQC carrier signing model):
 * an additional public input `tx_binding` carries the SHA256d sighash of
 * the funding (base) transaction — the same `tx_base` reconstruction the
 * PQC carrier uses (TX_C with OP_RETURN + ZK carrier outputs stripped and
 * carrier cost re-added to the first output).  By exposing it as a public
 * input AND constraining it inside the circuit, the prover MUST commit to
 * a specific tx_base sighash at proving time, so the resulting Groth16 /
 * PLONK proof is bound to one and only one funding tx — replaying the
 * proof under any other TX_C produces a different tx_base sighash and is
 * rejected by snarkjs/rapidsnark verify.
 *
 * The tx_binding public input is a field element on BN254.  To eliminate
 * any modular-reduction ambiguity, callers MUST supply it as a 248-bit
 * value (sighash32 with the top byte zeroed) so two distinct sighashes
 * cannot map to the same field element.
 *
 * Bound: 64-bit unsigned (sufficient for koinu / 2^64-1).
 *
 * Reproduction (see ./README.md for full instructions):
 *   circom range_proof.circom --r1cs --wasm --sym --output build
 *   snarkjs powersoftau prepare phase2 pot12_final.ptau pot12_phase2.ptau
 *   snarkjs groth16 setup build/range_proof.r1cs pot12_phase2.ptau range_proof.zkey
 *   snarkjs zkey export verificationkey range_proof.zkey verification_key.json
 *   snarkjs groth16 fullprove input.json build/range_proof_js/range_proof.wasm \
 *       range_proof.zkey proof.json public.json
 */

include "circomlib/comparators.circom";

template RangeProof(nBits) {
    signal input low;
    signal input high;
    signal input amount;
    signal input tx_binding;

    // amount >= low  <=>  low <= amount  <=>  LessEqThan(low, amount) == 1
    component leLow = LessEqThan(nBits);
    leLow.in[0] <== low;
    leLow.in[1] <== amount;
    leLow.out === 1;

    // amount <= high <=>  LessEqThan(amount, high) == 1
    component leHigh = LessEqThan(nBits);
    leHigh.in[0] <== amount;
    leHigh.in[1] <== high;
    leHigh.out === 1;

    // tx_binding has no semantic relation to the range check, but squaring
    // it injects one R1CS constraint that pulls the value into the witness
    // vector so the public input is bound by the proof.  Any other
    // tx_binding produces a different proof; replay under a different
    // funding tx is detectable purely from snarkjs verify output.
    signal tx_binding_squared;
    tx_binding_squared <== tx_binding * tx_binding;
}

component main { public [low, high, tx_binding] } = RangeProof(64);
