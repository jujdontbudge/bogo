/*
 * BOGO's C shim around lean.h (ARCHITECTURE §3.4). It is the only code that touches lean.h,
 * because the Lean FFI is documented as unstable. Its public ABI is `bogo_core_*`; it calls the
 * Lean exports `bogo_lean_*`; the Lean extern `bogo_shim_verify` lands here and calls the Rust
 * verifier `bogo_rs_verify`.
 *
 * Inputs are borrowed only for the duration of a call. Returned buffers belong to the shim and
 * are released only through `bogo_core_free`. Every function is called from one thread only
 * (the Rust side enforces this), so the global state needs no lock.
 */
#include <lean/lean.h>
#include <stdlib.h>
#include <string.h>

lean_object *initialize_bogo_BogoCore(uint8_t builtin);
void lean_initialize_runtime_module(void);

uint32_t bogo_lean_abi(lean_object *unit);
lean_object *bogo_lean_init(lean_object *bogo_id, lean_object *boot_id);
lean_object *bogo_lean_step(lean_object *state, lean_object *input);
lean_object *bogo_lean_decode_request(lean_object *bytes);
uint8_t bogo_lean_check_approval(uint16_t alg, lean_object *pk, lean_object *req,
                                 lean_object *proof);

uint8_t bogo_rs_verify(uint16_t alg, const uint8_t *pk, size_t pk_n, const uint8_t *msg,
                       size_t msg_n, const uint8_t *proof, size_t proof_n);

static int g_runtime = 0;
static lean_object *g_state = NULL;

static int ensure_runtime(void) {
  if (g_runtime) return 0;
  lean_initialize_runtime_module();
  lean_object *res = initialize_bogo_BogoCore(1);
  if (lean_io_result_is_error(res)) {
    lean_dec_ref(res);
    return -1;
  }
  lean_dec_ref(res);
  lean_io_mark_end_initialization();
  g_runtime = 1;
  return 0;
}

static lean_object *mk_bytes(const uint8_t *p, size_t n) {
  lean_object *a = lean_alloc_sarray(1, n, n);
  if (n != 0) memcpy(lean_sarray_cptr(a), p, n);
  return a;
}

/* Copies a Lean ByteArray into a fresh buffer and releases the Lean object. */
static int take_bytes(lean_object *a, uint8_t **out, size_t *out_n) {
  size_t n = lean_sarray_size(a);
  uint8_t *buf = (uint8_t *)malloc(n != 0 ? n : 1);
  if (buf == NULL) {
    lean_dec(a);
    return -1;
  }
  if (n != 0) memcpy(buf, lean_sarray_cptr(a), n);
  lean_dec(a);
  *out = buf;
  *out_n = n;
  return 0;
}

uint32_t bogo_core_abi(void) {
  if (ensure_runtime() != 0) return 0;
  return bogo_lean_abi(lean_box(0));
}

int bogo_core_start(const uint8_t *bogo_id, size_t n1, const uint8_t *boot_id, size_t n2) {
  if (ensure_runtime() != 0) return -1;
  if (g_state != NULL) lean_dec(g_state);
  g_state = bogo_lean_init(mk_bytes(bogo_id, n1), mk_bytes(boot_id, n2));
  return 0;
}

int bogo_core_step(const uint8_t *in, size_t n, uint8_t **out, size_t *out_n) {
  if (g_state == NULL) return -1;
  /* bogo_lean_step consumes the state and the input. */
  lean_object *pair = bogo_lean_step(g_state, mk_bytes(in, n));
  lean_object *s = lean_ctor_get(pair, 0);
  lean_object *b = lean_ctor_get(pair, 1);
  lean_inc(s);
  lean_inc(b);
  lean_dec(pair);
  g_state = s;
  return take_bytes(b, out, out_n);
}

/* 0: canonical, and `out` holds the request bytes; 1: not a canonical request; -1: error. */
int bogo_core_decode_request(const uint8_t *in, size_t n, uint8_t **out, size_t *out_n) {
  if (ensure_runtime() != 0) return -1;
  lean_object *r = bogo_lean_decode_request(mk_bytes(in, n));
  if (lean_sarray_size(r) == 0) {
    lean_dec(r);
    return 1;
  }
  return take_bytes(r, out, out_n);
}

/* 1: a valid approval of canonical request bytes; 0: not; -1: error. */
int bogo_core_check_approval(uint16_t alg, const uint8_t *pk, size_t pk_n, const uint8_t *req,
                             size_t req_n, const uint8_t *proof, size_t proof_n) {
  if (ensure_runtime() != 0) return -1;
  return bogo_lean_check_approval(alg, mk_bytes(pk, pk_n), mk_bytes(req, req_n),
                                  mk_bytes(proof, proof_n)) ? 1 : 0;
}

void bogo_core_free(uint8_t *p) { free(p); }

/* The Lean extern target. Its arguments are borrowed Lean ByteArrays. */
uint8_t bogo_shim_verify(uint16_t alg, b_lean_obj_arg pk, b_lean_obj_arg msg,
                         b_lean_obj_arg proof) {
  return bogo_rs_verify(alg, lean_sarray_cptr(pk), lean_sarray_size(pk), lean_sarray_cptr(msg),
                        lean_sarray_size(msg), lean_sarray_cptr(proof),
                        lean_sarray_size(proof)) != 0;
}
