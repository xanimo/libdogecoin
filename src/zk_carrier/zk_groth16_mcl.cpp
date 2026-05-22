/*
 *  zk_groth16_mcl.cpp — In-process Groth16 BN254 verifier
 *
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2026 edtubbs
 *  Copyright (c) 2026 The Dogecoin Foundation
 *
 *  Implements the C entry point declared in zk_groth16.c when libdogecoin
 *  is built with --with-mcl.  Uses herumi/mcl (BN_SNARK1 / "bn128" curve
 *  used by snarkjs / circom) for pairings.
 *
 *  Verification equation (Groth16, snarkjs convention):
 *
 *      e(A, B) == e(alpha_1, beta_2) * e(L, gamma_2) * e(C, delta_2)
 *
 *  where L = IC[0] + sum_i  pub_i * IC[i+1].
 *
 *  Inputs are NUL-terminated JSON strings from snarkjs:
 *    * vk_json     — verification_key.json
 *    * public_json — public.json (top-level array of decimal strings)
 *    * proof_json  — proof.json
 *
 *  Returns 0 on successful verification, non-zero on any error.  When
 *  err_buf is non-NULL it receives a short, non-sensitive diagnostic that
 *  callers may log alongside the return code.
 *
 *  Notes:
 *    * Snarkjs always emits affine points (Z = "1"); we ignore Z and read
 *      the X / Y coordinates directly.  G2 components are Fp2 = (a + b*i).
 *    * No JSON library is required — the input shape is fully determined
 *      by snarkjs; we walk for `"<key>"` then take the next [...] block,
 *      then collect every `"<digits>"` token inside.  This keeps the
 *      verifier dependency-free beyond mcl + libstdc++.
 */

#include <mcl/bn.hpp>

#include <cstddef>
#include <cstring>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>
#include <stdexcept>

extern "C" int groth16_verify_mcl(const char* vk_json,
                                  const char* public_json,
                                  const char* proof_json,
                                  char* err_buf,
                                  unsigned long err_buf_max);

namespace {

using namespace mcl::bn;

/**
 * @brief Internal helper: copy a NUL-terminated message into the caller's
 * error buffer with truncation if needed.  No-ops on NULL inputs.
 *
 * @param err_buf      caller-provided buffer (may be NULL)
 * @param err_buf_max  size of `err_buf` in bytes
 * @param msg          NUL-terminated message to copy
 */
void set_err(char* err_buf, unsigned long err_buf_max, const char* msg) {
    if (!err_buf || err_buf_max == 0 || !msg) return;
    size_t n = std::strlen(msg);
    if (n >= err_buf_max) n = err_buf_max - 1;
    std::memcpy(err_buf, msg, n);
    err_buf[n] = '\0';
}

/**
 * @brief Find the [...] block that follows a top-level `"key"` in a JSON-ish
 * string.
 *
 * Used to locate the per-field arrays inside a snarkjs verification key /
 * proof / public-inputs blob without pulling in a full JSON parser.  The
 * search is anchored: only matches where the byte preceding the key's
 * opening quote is `{` or `,` (skipping ASCII whitespace) are accepted, so
 * a string value that happens to contain the literal `"vk_alpha_1"` cannot
 * mis-redirect the parser to the wrong array.  The verification key bytes
 * are attacker-controlled in v1 self-contained reveals, so an unanchored
 * search would be unsafe.
 *
 * Note: the anchor is structural (preceding `{` / `,`) but not
 * brace-depth-aware — a key buried inside a nested object whose parent is
 * itself directly opened by `{` will still match.  snarkjs vk/proof/public
 * blobs have no nesting at the keys we consult here (vk_alpha_1, vk_beta_2,
 * vk_gamma_2, vk_delta_2, IC, pi_a, pi_b, pi_c) so this is not exploitable
 * today; a maliciously crafted v1 vk that buries one of those keys inside a
 * nested object would have its first (nested) match consumed, the resulting
 * point would not satisfy the pairing equation, and verification would
 * cleanly return 1 ("pairing eq mismatch") — no soundness break, just a
 * harder-to-diagnose error.
 *
 * @param s       the JSON string to search
 * @param key     the key whose value-array to locate (no quotes)
 * @param out_lo  receives the offset of the leading '['
 * @param out_hi  receives the offset just past the matching ']'
 *
 * @return true on success; false when the key is missing or the brackets
 *         are unbalanced
 */
bool find_value_array(const std::string& s, const char* key, size_t& out_lo, size_t& out_hi) {
    std::string needle = std::string("\"") + key + "\"";
    size_t search_from = 0;
    while (search_from < s.size()) {
        size_t p = s.find(needle, search_from);
        if (p == std::string::npos) return false;
        /* Anchor: the byte preceding `"key"` (skipping ASCII whitespace)
         * must be `{` or `,`, i.e. this is a top-level object key, not a
         * substring inside a string value. */
        size_t back = p;
        bool anchored = false;
        while (back > 0) {
            char c = s[back - 1];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') { --back; continue; }
            anchored = (c == '{' || c == ',');
            break;
        }
        if (!anchored) {
            /* Skip past this match and keep searching. */
            search_from = p + needle.size();
            continue;
        }
        /* Require a `:` between the key and the `[`. */
        size_t after = p + needle.size();
        while (after < s.size() && (s[after] == ' ' || s[after] == '\t' ||
                                    s[after] == '\n' || s[after] == '\r')) ++after;
        if (after >= s.size() || s[after] != ':') {
            search_from = p + needle.size();
            continue;
        }
        size_t bracket = s.find('[', after);
        if (bracket == std::string::npos) return false;
        int depth = 0;
        for (size_t i = bracket; i < s.size(); ++i) {
            if (s[i] == '[') depth++;
            else if (s[i] == ']') {
                if (--depth == 0) { out_lo = bracket; out_hi = i + 1; return true; }
            }
        }
        return false;
    }
    return false;
}

/**
 * @brief Collect every `"<digits>"` token between [lo, hi) into a flat vector.
 *
 * snarkjs verification keys and proofs encode field elements as
 * NUL-quoted decimal strings; this skims those tokens out of the
 * value-array slice produced by find_value_array().
 *
 * @param s   the JSON string
 * @param lo  inclusive lower bound (typically the leading '[')
 * @param hi  exclusive upper bound (typically just past the matching ']')
 *
 * @return a vector of decimal-only string tokens, in source order; empty
 *         vector if the cap (ZK_MCL_MAX_DECIMAL_TOKENS) is exceeded so the
 *         caller can treat over-long input as a parse error
 */
/* Hard upper bound on the number of decimal tokens any single JSON value
 * array can yield.  vk_json is attacker-controlled in v1 self-contained
 * reveals, so an unbounded extractor would be a trivial DoS vector
 * (allocate billions of std::string).  131072 tokens is ~3 orders of
 * magnitude beyond any plausible Groth16 IC array (which is nPublic+1
 * entries x 3 coords; real circuits stay well under 10k public inputs)
 * and the public-input array is even smaller. */
static const size_t ZK_MCL_MAX_DECIMAL_TOKENS = 1u << 17;

/* Hard upper bound on the digit-length of any single decimal token.  BN254
 * has r ≈ 2^254 so the largest legitimate Fr / Fp coordinate is 78 decimal
 * digits; 96 leaves comfortable head-room without giving an attacker the
 * room to feed a multi-megabyte numeric string into Fr::setStr / Fp::setStr
 * (which mcl would dutifully reduce mod r, doing O(n) work for an attacker-
 * supplied n).  Tokens that exceed this are silently skipped (treated as
 * non-numeric) so the over-shape consumer checks below catch them. */
static const size_t ZK_MCL_MAX_DECIMAL_DIGITS = 96;

std::vector<std::string> extract_decimal_strings(const std::string& s, size_t lo, size_t hi) {
    std::vector<std::string> out;
    size_t i = lo;
    while (i < hi) {
        if (s[i] != '"') { ++i; continue; }
        size_t j = i + 1;
        while (j < hi && s[j] != '"') ++j;
        if (j >= hi) break;
        size_t tok_len = j - i - 1;
        if (tok_len > ZK_MCL_MAX_DECIMAL_DIGITS) {
            /* Skip absurdly long tokens — see ZK_MCL_MAX_DECIMAL_DIGITS. */
            i = j + 1;
            continue;
        }
        std::string tok = s.substr(i + 1, tok_len);
        bool num = !tok.empty();
        for (char c : tok) { if (!(c >= '0' && c <= '9')) { num = false; break; } }
        if (num) {
            if (out.size() >= ZK_MCL_MAX_DECIMAL_TOKENS) {
                /* Bail out — caller must treat empty-or-malformed-shape as
                 * a parse error (every legitimate consumer below already
                 * checks size != 0 / size % N == 0 / size + 1 == n_ic). */
                return std::vector<std::string>();
            }
            out.push_back(tok);
        }
        i = j + 1;
    }
    return out;
}

/**
 * @brief Build an mcl::bn::G1 point from decimal x/y coordinates.
 *
 * Wraps mcl's affine-non-zero serialization (`"1 <x> <y>"`) so the
 * extractor in groth16_verify_mcl can stay focused on JSON parsing.
 *
 * @param x_dec  affine x-coordinate as decimal string
 * @param y_dec  affine y-coordinate as decimal string
 *
 * @return the constructed G1 point
 */
G1 make_g1(const std::string& x_dec, const std::string& y_dec) {
    G1 P;
    /* mcl decimal serialization: "<flag> <x> <y>" with flag=1 = affine non-zero */
    std::string serial = "1 " + x_dec + " " + y_dec;
    P.setStr(serial, 10);
    /* setStr verifies on-curve; explicit subgroup membership check is
     * required for Groth16 soundness on BN254.  G1 has trivial cofactor=1
     * on BN_SNARK1 so this is a no-op in practice, but keep the check for
     * defence-in-depth and parity with G2.  Throws cybozu::Exception on
     * failure, caught by the top-level try/catch in groth16_verify_mcl. */
    if (!P.isValidOrder()) {
        throw std::runtime_error("G1 point not in prime-order subgroup");
    }
    return P;
}

/**
 * @brief Build an mcl::bn::G2 point from a quadratic-extension affine pair.
 *
 * Wraps mcl's affine-non-zero serialization
 * (`"1 <x0> <x1> <y0> <y1>"`) for the BN_SNARK1 G2 group.
 *
 * @param x0  real part of the affine x-coordinate
 * @param x1  imag part of the affine x-coordinate
 * @param y0  real part of the affine y-coordinate
 * @param y1  imag part of the affine y-coordinate
 *
 * @return the constructed G2 point
 */
G2 make_g2(const std::string& x0, const std::string& x1,
           const std::string& y0, const std::string& y1) {
    G2 P;
    std::string serial = "1 " + x0 + " " + x1 + " " + y0 + " " + y1;
    P.setStr(serial, 10);
    /* G2 on BN254 has a non-trivial cofactor, so a malicious prover could
     * supply an on-curve point in a small subgroup that breaks Groth16
     * soundness (the pairing equation can be satisfied for non-witness
     * inputs).  Reject anything outside the prime-order subgroup.  This is
     * consensus-relevant for v1 self-contained reveals where vk_beta_2 /
     * vk_gamma_2 / vk_delta_2 are attacker-controlled, and for pi_b in
     * every reveal.  Throws cybozu::Exception on failure, caught by the
     * top-level try/catch in groth16_verify_mcl. */
    if (!P.isValidOrder()) {
        throw std::runtime_error("G2 point not in prime-order subgroup");
    }
    return P;
}

std::once_flag g_pairing_once;

/**
 * @brief Initialise mcl's pairing tables for BN_SNARK1 (BN254) on first use.
 *
 * Idempotent and thread-safe — guarded by std::call_once so concurrent
 * SPV/verifier threads cannot race on initPairing().
 */
void ensure_pairing_initialised() {
    std::call_once(g_pairing_once, []() {
        initPairing(mcl::BN_SNARK1);
    });
}

} /* anonymous namespace */

/**
 * @brief Verify a Groth16 (BN_SNARK1) proof using the herumi/mcl pairing engine.
 *
 * snarkjs-style C ABI counterpart to the upstream rapidsnark `groth16_verify`
 * — see depends/packages/mcl.mk.  All three input blobs MUST be NUL-terminated
 * JSON; the libdogecoin wrapper in dogecoin_zk_verify_groth16 takes care of
 * copying caller-supplied byte slices into NUL-terminated buffers.  Returns
 * 0 on a valid proof, 1 on a well-formed-but-invalid proof, 2/3/4 on
 * argument / parse / unexpected-exception errors (with a short non-sensitive
 * diagnostic written to `err_buf`).
 *
 * @param vk_json      NUL-terminated verification-key JSON
 * @param public_json  NUL-terminated public-inputs JSON
 * @param proof_json   NUL-terminated proof JSON
 * @param err_buf      caller-provided buffer for a short diagnostic (may be NULL)
 * @param err_buf_max  size of `err_buf` in bytes (0 if `err_buf` is NULL)
 *
 * @return 0 on a valid proof, 1 on an invalid proof, 2/3/4 on input/parse/exception failure
 */
extern "C" int groth16_verify_mcl(const char* vk_json,
                                  const char* public_json,
                                  const char* proof_json,
                                  char* err_buf,
                                  unsigned long err_buf_max) {
    if (err_buf && err_buf_max > 0) err_buf[0] = '\0';
    if (!vk_json || !public_json || !proof_json) {
        set_err(err_buf, err_buf_max, "null input");
        return 2;
    }
    try {
        ensure_pairing_initialised();

        std::string vk(vk_json);
        std::string pub(public_json);
        std::string prf(proof_json);

        size_t lo = 0, hi = 0;

        /* snarkjs always emits affine points (Z=="1" for G1, Z==["1","0"]
         * for G2) so we reject any other Z up-front: a malformed proof.json
         * with Z="0" would otherwise be accepted as point-at-infinity by
         * make_g1's "1 X Y" affine deserialization, since the Z token is
         * silently dropped. */
        auto check_g1_z = [](const std::vector<std::string>& t) -> bool {
            return t.size() >= 3 && t[2] == "1";
        };
        auto check_g2_z = [](const std::vector<std::string>& t) -> bool {
            return t.size() >= 6 && t[4] == "1" && t[5] == "0";
        };

        /* alpha_1 (G1) */
        if (!find_value_array(vk, "vk_alpha_1", lo, hi)) {
            set_err(err_buf, err_buf_max, "vk_alpha_1 missing"); return 3;
        }
        auto a_t = extract_decimal_strings(vk, lo, hi);
        if (!check_g1_z(a_t)) { set_err(err_buf, err_buf_max, "vk_alpha_1 not affine (Z!=1)"); return 3; }
        G1 alpha = make_g1(a_t[0], a_t[1]);

        /* beta/gamma/delta (G2) */
        auto load_g2 = [&](const char* key, G2& out) -> bool {
            size_t a, b;
            if (!find_value_array(vk, key, a, b)) return false;
            auto t = extract_decimal_strings(vk, a, b);
            if (!check_g2_z(t)) return false;
            out = make_g2(t[0], t[1], t[2], t[3]);
            return true;
        };
        G2 beta, gamma, delta;
        if (!load_g2("vk_beta_2",  beta))  { set_err(err_buf, err_buf_max, "vk_beta_2 missing or not affine");  return 3; }
        if (!load_g2("vk_gamma_2", gamma)) { set_err(err_buf, err_buf_max, "vk_gamma_2 missing or not affine"); return 3; }
        if (!load_g2("vk_delta_2", delta)) { set_err(err_buf, err_buf_max, "vk_delta_2 missing or not affine"); return 3; }

        /* IC array (G1[]).  IC contains nPublic+1 G1 points, each [X,Y,"1"]. */
        if (!find_value_array(vk, "IC", lo, hi)) {
            set_err(err_buf, err_buf_max, "IC missing"); return 3;
        }
        auto ic_t = extract_decimal_strings(vk, lo, hi);
        if (ic_t.size() == 0 || ic_t.size() % 3 != 0) {
            set_err(err_buf, err_buf_max, "IC malformed"); return 3;
        }
        size_t n_ic = ic_t.size() / 3;
        /* Cap nPublic+1 at a generous bound so a malicious vk can't force
         * a huge MSM (each iteration does an Fr*G1 mul + accumulate).  The
         * extract_decimal_strings cap above already bounds raw token count;
         * this is the consumer-side check with a clearer error string. */
        if (n_ic > 65536) {
            set_err(err_buf, err_buf_max, "IC too large"); return 3;
        }
        std::vector<G1> IC; IC.reserve(n_ic);
        for (size_t i = 0; i < n_ic; ++i) {
            if (ic_t[3*i + 2] != "1") {
                set_err(err_buf, err_buf_max, "IC entry not affine (Z!=1)"); return 3;
            }
            IC.push_back(make_g1(ic_t[3*i], ic_t[3*i + 1]));
        }

        /* public inputs (Fr[]) */
        auto pub_t = extract_decimal_strings(pub, 0, pub.size());
        if (pub_t.size() + 1 != n_ic) {
            set_err(err_buf, err_buf_max, "public inputs / IC length mismatch"); return 3;
        }
        std::vector<Fr> public_inputs; public_inputs.reserve(pub_t.size());
        for (auto& s : pub_t) {
            Fr f; f.setStr(s, 10);
            public_inputs.push_back(f);
        }

        /* proof: pi_a (G1), pi_b (G2), pi_c (G1) */
        if (!find_value_array(prf, "pi_a", lo, hi)) { set_err(err_buf, err_buf_max, "pi_a missing"); return 3; }
        auto pa_t = extract_decimal_strings(prf, lo, hi);
        if (!check_g1_z(pa_t)) { set_err(err_buf, err_buf_max, "pi_a not affine (Z!=1)"); return 3; }
        G1 A = make_g1(pa_t[0], pa_t[1]);

        if (!find_value_array(prf, "pi_b", lo, hi)) { set_err(err_buf, err_buf_max, "pi_b missing"); return 3; }
        auto pb_t = extract_decimal_strings(prf, lo, hi);
        if (!check_g2_z(pb_t)) { set_err(err_buf, err_buf_max, "pi_b not affine (Z!=[1,0])"); return 3; }
        G2 B = make_g2(pb_t[0], pb_t[1], pb_t[2], pb_t[3]);

        if (!find_value_array(prf, "pi_c", lo, hi)) { set_err(err_buf, err_buf_max, "pi_c missing"); return 3; }
        auto pc_t = extract_decimal_strings(prf, lo, hi);
        if (!check_g1_z(pc_t)) { set_err(err_buf, err_buf_max, "pi_c not affine (Z!=1)"); return 3; }
        G1 C = make_g1(pc_t[0], pc_t[1]);

        /* L = IC[0] + sum pub_i * IC[i+1] */
        G1 L = IC[0];
        for (size_t i = 0; i < public_inputs.size(); ++i) {
            G1 t;
            G1::mul(t, IC[i + 1], public_inputs[i]);
            L += t;
        }

        /* Pairing equation: e(A, B) == e(alpha, beta) * e(L, gamma) * e(C, delta) */
        Fp12 lhs, e_alpha_beta, e_L_gamma, e_C_delta;
        pairing(lhs,           A,     B);
        pairing(e_alpha_beta,  alpha, beta);
        pairing(e_L_gamma,     L,     gamma);
        pairing(e_C_delta,     C,     delta);
        Fp12 rhs = e_alpha_beta * e_L_gamma * e_C_delta;

        if (lhs == rhs) {
            return 0;
        }
        set_err(err_buf, err_buf_max, "pairing eq mismatch");
        return 1;
    } catch (const std::exception& e) {
        set_err(err_buf, err_buf_max, e.what());
        return 4;
    } catch (...) {
        set_err(err_buf, err_buf_max, "unknown exception");
        return 4;
    }
}
