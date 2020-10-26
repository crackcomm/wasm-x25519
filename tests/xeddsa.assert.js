"use strict";
exports.__esModule = true;
var xeddsa = require("../pkg/wasm_xeddsa");
var sodium_native_1 = require("sodium-native");
describe('xeddsa', function () {
    var seed_alice = xeddsa.generate_seed();
    var seed_bob = xeddsa.generate_seed();
    test('generates 32 byte seed', function () {
        expect(seed_alice.length).toBe(32);
    });
    var secret_alice = xeddsa.expand_seed(seed_alice);
    var secret_bob = xeddsa.expand_seed(seed_bob);
    test('expands seed to a private key', function () {
        expect(secret_alice.length).toBe(64);
    });
    var edpk_alice = xeddsa.ed25519_public(secret_alice);
    var sign = edpk_alice[31] >> 7 === 1 ? 1 : 0;
    var edpk_bob = xeddsa.ed25519_public(secret_bob);
    test('derives ed25519 public key', function () {
        expect(edpk_alice.length).toBe(32);
    });
    var xsk_alice = secret_alice.slice(0, 32);
    var xpk_alice = xeddsa.x25519_public(xsk_alice);
    var xsk_bob = secret_bob.slice(0, 32);
    var xpk_bob = xeddsa.x25519_public(xsk_bob);
    test('derives shared secret', function () {
        var shared_alice = xeddsa.x25519_shared(xsk_alice, xpk_bob);
        var shared_bob = xeddsa.x25519_shared(xsk_bob, xpk_alice);
        expect(shared_alice).toStrictEqual(shared_bob);
    });
    test('derives x25519 public key', function () {
        expect(xpk_alice.length).toBe(32);
        // Convert `ed25519` public key back to `x25519` public key
        var xpk_alice_ = new Uint8Array(32);
        sodium_native_1.crypto_sign_ed25519_pk_to_curve25519(xpk_alice_, edpk_alice);
        expect(xpk_alice_).toStrictEqual(xpk_alice);
    });
    test('converts ed25519 public key to x25519 public key', function () {
        var xpk_alice_ = xeddsa.ed25519_to_x25519(edpk_alice, true);
        expect(xpk_alice_).toStrictEqual(xpk_alice);
    });
    test("converts x25519 public key to ed25519 public key (" + sign + ")", function () {
        var edpk_alice_ = xeddsa.x25519_to_ed25519(xpk_alice, sign);
        expect(edpk_alice_).toStrictEqual(edpk_alice);
    });
    test('signs and verifies message with ed25519', function () {
        var message = new Uint8Array(Buffer.from('Wonderful'));
        var signature = xeddsa.ed25519_sign(secret_alice, message);
        expect(signature.length).toBe(64);
        var valid = xeddsa.ed25519_verify_strict(signature, message, edpk_alice);
        expect(valid).toBe(true);
        var bob_invalid = function () { return xeddsa.ed25519_verify_strict(signature, message, edpk_bob); };
        expect(bob_invalid).toThrow();
    });
});
describe('sha512', function () {
    var sha512 = xeddsa.sha512_new();
    xeddsa.sha512_update_str(sha512, 'test');
    var hash = xeddsa.sha512_finalize(sha512);
    var hashstr = Buffer.from(hash).toString('hex');
    test('short hash', function () {
        expect(hashstr).toBe('ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff');
    });
});
