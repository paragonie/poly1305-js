"use strict";

const assert = require('assert');
const expect = require('chai').expect;
const crypto = require('crypto');
const Poly1305 = require('../lib/poly1305');

describe('Poly1305', function () {
    it('Test Vector A', async function () {
        let message = Buffer.alloc(32, 0);
        let key = Buffer.from('746869732069732033322d62797465206b657920666f7220506f6c7931333035', 'hex');

        let auth = new Poly1305(key);
        await auth.update(message);
        expect('49ec78090e481ec6c26b33b91ccc0307').to.be.equal(
            (await auth.finish()).toString('hex')
        );
    });

    it('Test Vector B', async function () {
        let message = Buffer.from('48656c6c6f20776f726c6421', 'hex');
        let key = Buffer.from('746869732069732033322d62797465206b657920666f7220506f6c7931333035', 'hex')
        let auth = new Poly1305(key);
        await auth.update(message);
        expect('a6f745008f81c916a20dcc74eef2b2f0').to.be.equal(
            (await auth.finish()).toString('hex')
        );
    });

    it('Test Vector C', async function () {
        let message = Buffer.from(
            '8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a' +
            'c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738' +
            'b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da' +
            '99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74' +
            'e355a5',
            'hex'
        );
        let key = Buffer.from('eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880', 'hex');
        let auth = new Poly1305(key);
        await auth.update(message);
        expect('f3ffc7703f9400e52a7dfb4b3d3305d9').to.be.equal(
            (await auth.finish()).toString('hex')
        );
    });
    it('Test Vector C2', async function () {
        let part1 = Buffer.from(
            '8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a' +
            'c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738',
            'hex'
        );
        let part2 = Buffer.from(
            'b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da' +
            '99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74' +
            'e355a5',
            'hex'
        );
        let key = Buffer.from('eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880', 'hex');
        let auth = new Poly1305(key);
        await auth.update(part1);
        await auth.update(part2);
        expect('f3ffc7703f9400e52a7dfb4b3d3305d9').to.be.equal(
            (await auth.finish()).toString('hex')
        );
    });

    it('Test cloning', async function() {
        let key = Buffer.from('eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880', 'hex');
        let poly = new Poly1305(key);
        await poly.update(Buffer.from('This is part 1\n'));
        let clone = poly.clone();
        await clone.update(Buffer.from('This is part 2\n'));
        let tag0 = await poly.finish();
        let tag1 = await clone.finish();
        expect(tag0.toString('hex')).to.not.equal(tag1.toString('hex'));
    });

    it('onetimeauth API', async function () {
        crypto.randomBytes(32, async function(err, key) {
            if (err) throw err;
            let message = 'This is a test message';
            let mac = await Poly1305.onetimeauth(message, key);
            expect(await Poly1305.onetimeauth_verify(message, key, mac)).to.be.equal(true);
        });

    });
});
