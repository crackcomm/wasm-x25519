import * as xeddsa from '../pkg/wasm_xeddsa';

import {
  crypto_sign_ed25519_pk_to_curve25519,
  crypto_sign_detached,
} from 'sodium-native';

describe('xeddsa', () => {
  const seed_alice = xeddsa.generate_seed();
  const seed_bob = xeddsa.generate_seed();

  test('generates 32 byte seed', () => {
    expect(seed_alice.length).toBe(32);
  });

  const secret_alice = xeddsa.expand_seed(seed_alice);
  const secret_bob = xeddsa.expand_seed(seed_bob);

  test('expands seed to a private key', () => {
    expect(secret_alice.length).toBe(64);
  });

  const edpk_alice = xeddsa.ed25519_public(secret_alice);
  const sign = edpk_alice[31] >> 7 === 1 ? 1 : 0;
  const edpk_bob = xeddsa.ed25519_public(secret_bob);

  test('derives ed25519 public key', () => {
    expect(edpk_alice.length).toBe(32);
  });

  const xsk_alice = secret_alice.slice(0, 32);
  const xpk_alice = xeddsa.x25519_public(xsk_alice);
  const xsk_bob = secret_bob.slice(0, 32);
  const xpk_bob = xeddsa.x25519_public(xsk_bob);

  test('derives shared secret', () => {
    const shared_alice = xeddsa.x25519_shared(xsk_alice, xpk_bob);
    const shared_bob = xeddsa.x25519_shared(xsk_bob, xpk_alice);
    expect(shared_alice).toStrictEqual(shared_bob);
  });

  test('derives x25519 public key', () => {
    expect(xpk_alice.length).toBe(32);
    // Convert `ed25519` public key back to `x25519` public key
    const xpk_alice_ = new Uint8Array(32);
    crypto_sign_ed25519_pk_to_curve25519(xpk_alice_, edpk_alice);
    expect(xpk_alice_).toStrictEqual(xpk_alice);
  });

  test('converts ed25519 public key to x25519 public key', () => {
    const xpk_alice_ = xeddsa.ed25519_to_x25519(edpk_alice, true);
    expect(xpk_alice_).toStrictEqual(xpk_alice);
  });

  test(`converts x25519 public key to ed25519 public key (${sign})`, () => {
    const edpk_alice_ = xeddsa.x25519_to_ed25519(xpk_alice, sign);
    expect(edpk_alice_).toStrictEqual(edpk_alice);
  });

  test('signs and verifies message with ed25519', () => {
    const message = new Uint8Array(Buffer.from('Wonderful'));
    const signature = xeddsa.ed25519_sign(secret_alice, message);
    expect(signature.length).toBe(64);
    const valid = xeddsa.ed25519_verify_strict(signature, message, edpk_alice);
    expect(valid).toBe(true);
    const bob_invalid = () => xeddsa.ed25519_verify_strict(signature, message, edpk_bob);
    expect(bob_invalid).toThrow();
  });
});

describe('sha512', () => {
  const sha512 = xeddsa.sha512_new();
  xeddsa.sha512_update_str(sha512, 'test');
  const hash = xeddsa.sha512_finalize(sha512);
  const hashstr = Buffer.from(hash).toString('hex');
  test('short hash', () => {
    expect(hashstr).toBe('ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff');
  });
});

