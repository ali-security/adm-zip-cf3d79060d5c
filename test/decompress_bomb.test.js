"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// RSS only grows once pages are touched, so a lazily zero-filled multi-gigabyte
// buffer can slip past the RSS checks above. Spy on the Buffer allocators
// instead: every read path must size its buffers from the real archive data, so
// no single request may come anywhere near the declared size.
describe("decompression bomb (declared size) - allocation size - CVE-2026-39244", () => {
    const DECLARED = 0xffffffff; // largest size a classic zip header can declare (~4 GB)
    const LIMIT = 1024 * 1024; // the crafted archives carry a single byte of data

    // Runs `fn` and returns the largest Buffer.alloc/allocUnsafe request it made.
    // Oversized requests are refused rather than served, so a regression fails the
    // assertion instead of committing gigabytes of memory.
    function largestAllocation(fn) {
        const alloc = Buffer.alloc;
        const allocUnsafe = Buffer.allocUnsafe;
        let largest = 0;
        const guard = (original) =>
            function (size) {
                if (typeof size === "number" && size > largest) largest = size;
                if (size > LIMIT) throw new Error("oversized allocation of " + size + " bytes");
                return original.apply(Buffer, arguments);
            };
        Buffer.alloc = guard(alloc);
        Buffer.allocUnsafe = guard(allocUnsafe);
        try {
            fn();
        } catch (e) {
            // the crafted archives are invalid; only the allocation size matters here
        } finally {
            Buffer.alloc = alloc;
            Buffer.allocUnsafe = allocUnsafe;
        }
        return largest;
    }

    const bombs = [
        { label: "STORED", method: 0, content: Buffer.from("A") },
        { label: "DEFLATED", method: 8, content: Buffer.from([0x00]) }
    ];

    bombs.forEach(({ label, method, content }) => {
        const load = () => new Zip(craftBomb(DECLARED, method, content));

        it(`getData does not allocate the declared size for a ${label} entry`, () => {
            const entry = load().getEntries()[0];
            expect(largestAllocation(() => entry.getData())).to.be.at.most(LIMIT);
            expect(() => entry.getData()).to.throw();
        });

        it(`readFile does not allocate the declared size for a ${label} entry`, () => {
            const zip = load();
            expect(largestAllocation(() => zip.readFile("a"))).to.be.at.most(LIMIT);
        });

        it(`readAsText does not allocate the declared size for a ${label} entry`, () => {
            const zip = load();
            expect(largestAllocation(() => zip.readAsText("a"))).to.be.at.most(LIMIT);
        });

        it(`test() does not allocate the declared size for a ${label} entry`, () => {
            const zip = load();
            let result;
            expect(largestAllocation(() => (result = zip.test()))).to.be.at.most(LIMIT);
            expect(result).to.equal(false);
        });

        it(`getDataAsync does not allocate the declared size for a ${label} entry`, (done) => {
            const entry = load().getEntries()[0];
            let finished = false;
            const finish = (err) => {
                if (finished) return;
                finished = true;
                done(err);
            };
            // the output buffer used to be allocated synchronously, before inflating
            const largest = largestAllocation(() =>
                entry.getDataAsync((data, err) => {
                    // let the synchronous measurement complete before asserting
                    setImmediate(() => {
                        try {
                            expect(err, "the crafted entry must be reported as invalid").to.be.an("error");
                            finish();
                        } catch (e) {
                            finish(e);
                        }
                    });
                })
            );
            if (largest > LIMIT) finish(new Error("getDataAsync requested " + largest + " bytes"));
        });
    });
});
