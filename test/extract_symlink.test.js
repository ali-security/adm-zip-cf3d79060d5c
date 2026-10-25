"use strict";

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util/utils");

// Regression tests for CVE-2026-76845 (symlink attack):
// sanitize() only proves that the textual entry path stays under the target
// folder. When a component of that path already exists on disk as a symlink
// (e.g. "<target>/link -> /somewhere/else"), open()/mkdir() follow it and the
// extraction writes outside the target folder. Extraction must refuse to write
// through any symlink that lives strictly below the target folder.

// Creating symlinks on Windows needs elevated privileges / developer mode, so the
// symlink based scenarios only run where the platform lets us create them.
function makeSymlink(ctx, target, linkPath, type) {
    if (process.platform === "win32") return ctx.skip();
    try {
        fs.symlinkSync(target, linkPath, type);
    } catch (e) {
        if (e && (e.code === "EPERM" || e.code === "EACCES")) return ctx.skip();
        throw e;
    }
}

// build an archive in memory and reload it, as if it came from an attacker
function buildZip(entries) {
    const zip = new Zip();
    entries.forEach(function (entry) {
        zip.addFile(entry[0], entry.length > 1 ? Buffer.from(entry[1]) : null);
    });
    return new Zip(zip.toBuffer());
}

const IN_THE_WAY = /There is a file in the way/;

describe("adm-zip - extraction through pre-existing symlinks (CVE-2026-76845)", () => {
    let base, dest, outside, secret;

    beforeEach(() => {
        base = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-symlink-"));
        dest = pth.join(base, "dest");
        outside = pth.join(base, "outside");
        secret = pth.join(outside, "secret.txt");
        fs.mkdirSync(dest);
        fs.mkdirSync(outside);
        fs.writeFileSync(secret, "secret");
    });

    afterEach(() => rimraf.sync(base));

    describe("extractAllTo", () => {
        it("refuses to write a file through a symlinked directory inside the target", function () {
            makeSymlink(this, outside, pth.join(dest, "link"), "dir");
            const zip = buildZip([["link/evil.txt", "pwned"]]);

            expect(() => zip.extractAllTo(dest, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("refuses to write a file through a nested symlinked directory inside the target", function () {
            fs.mkdirSync(pth.join(dest, "a"));
            makeSymlink(this, outside, pth.join(dest, "a", "link"), "dir");
            const zip = buildZip([["a/link/deep/evil.txt", "pwned"]]);

            expect(() => zip.extractAllTo(dest, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "deep"))).to.equal(false);
        });

        it("refuses to overwrite a file through a symlink inside the target", function () {
            makeSymlink(this, secret, pth.join(dest, "victim.txt"), "file");
            const zip = buildZip([["victim.txt", "pwned"]]);

            expect(() => zip.extractAllTo(dest, true)).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(secret, "utf8")).to.equal("secret");
        });

        it("refuses to create a directory through a symlinked directory inside the target", function () {
            makeSymlink(this, outside, pth.join(dest, "link"), "dir");
            const zip = buildZip([["link/sub/"]]);

            expect(() => zip.extractAllTo(dest, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
        });

        it("still extracts when only unrelated symlinks exist inside the target", function () {
            makeSymlink(this, outside, pth.join(dest, "link"), "dir");
            const zip = buildZip([["other/file.txt", "content"], ["top.txt", "top"]]);

            zip.extractAllTo(dest, true);
            expect(fs.readFileSync(pth.join(dest, "other", "file.txt"), "utf8")).to.equal("content");
            expect(fs.readFileSync(pth.join(dest, "top.txt"), "utf8")).to.equal("top");
            expect(fs.readdirSync(outside)).to.deep.equal(["secret.txt"]);
        });

        it("still extracts when the target folder itself is a symlink", function () {
            const real = pth.join(base, "real");
            const rootLink = pth.join(base, "rootlink");
            fs.mkdirSync(real);
            makeSymlink(this, real, rootLink, "dir");
            const zip = buildZip([["a/b.txt", "content"]]);

            zip.extractAllTo(rootLink, true);
            expect(fs.readFileSync(pth.join(real, "a", "b.txt"), "utf8")).to.equal("content");
        });
    });

    describe("extractEntryTo", () => {
        it("refuses to write a file entry through a symlinked directory inside the target", function () {
            makeSymlink(this, outside, pth.join(dest, "link"), "dir");
            const zip = buildZip([["link/evil.txt", "pwned"]]);

            expect(() => zip.extractEntryTo("link/evil.txt", dest, true, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("refuses to overwrite a file through a symlink inside the target", function () {
            makeSymlink(this, secret, pth.join(dest, "victim.txt"), "file");
            const zip = buildZip([["victim.txt", "pwned"]]);

            expect(() => zip.extractEntryTo("victim.txt", dest, false, true)).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(secret, "utf8")).to.equal("secret");
        });

        it("refuses to write directory children through a symlinked directory inside the target", function () {
            makeSymlink(this, outside, pth.join(dest, "link"), "dir");
            const zip = buildZip([["link/"], ["link/evil.txt", "pwned"]]);

            expect(() => zip.extractEntryTo("link/", dest, true, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("still extracts when the target folder itself is a symlink", function () {
            const real = pth.join(base, "real");
            const rootLink = pth.join(base, "rootlink");
            fs.mkdirSync(real);
            makeSymlink(this, real, rootLink, "dir");
            const zip = buildZip([["a/b.txt", "content"]]);

            zip.extractEntryTo("a/b.txt", rootLink, true, true);
            expect(fs.readFileSync(pth.join(real, "a", "b.txt"), "utf8")).to.equal("content");
        });
    });

    describe("extractAllToAsync", () => {
        it("refuses to write a file through a symlinked directory inside the target", function () {
            makeSymlink(this, outside, pth.join(dest, "link"), "dir");
            const zip = buildZip([["link/evil.txt", "pwned"]]);

            return zip.extractAllToAsync(dest, true).then(
                () => {
                    throw new Error("extraction through a symlink was expected to fail");
                },
                (err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(IN_THE_WAY);
                    expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
                }
            );
        });

        it("refuses to overwrite a file through a symlink inside the target", function (done) {
            makeSymlink(this, secret, pth.join(dest, "victim.txt"), "file");
            const zip = buildZip([["victim.txt", "pwned"]]);

            let finished = false;
            zip.extractAllToAsync(dest, true, false, function (err) {
                if (finished) return;
                finished = true;
                try {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(IN_THE_WAY);
                    expect(fs.readFileSync(secret, "utf8")).to.equal("secret");
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("refuses to create a directory through a symlinked directory inside the target", function () {
            makeSymlink(this, outside, pth.join(dest, "link"), "dir");
            const zip = buildZip([["link/sub/"]]);

            return zip.extractAllToAsync(dest, true).then(
                () => {
                    throw new Error("directory creation through a symlink was expected to fail");
                },
                (err) => {
                    expect(err).to.be.an("error");
                    expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
                }
            );
        });

        it("still extracts when the target folder itself is a symlink", function () {
            const real = pth.join(base, "real");
            const rootLink = pth.join(base, "rootlink");
            fs.mkdirSync(real);
            makeSymlink(this, real, rootLink, "dir");
            const zip = buildZip([["a/"], ["a/b.txt", "content"]]);

            return zip.extractAllToAsync(rootLink, true).then(() => {
                expect(fs.readFileSync(pth.join(real, "a", "b.txt"), "utf8")).to.equal("content");
            });
        });
    });

    describe("Utils.assertPathSafe", () => {
        it("rejects a symlink component below the root", function () {
            makeSymlink(this, outside, pth.join(dest, "link"), "dir");
            const utils = new Utils();

            expect(() => utils.assertPathSafe(dest, pth.join(dest, "link"))).to.throw(IN_THE_WAY);
            expect(() => utils.assertPathSafe(dest, pth.join(dest, "link", "x", "y.txt"))).to.throw(IN_THE_WAY);
        });

        it("accepts the root itself, plain paths and paths that do not exist yet", () => {
            const utils = new Utils();
            fs.mkdirSync(pth.join(dest, "existing"));
            fs.writeFileSync(pth.join(dest, "existing", "file.txt"), "x");

            expect(() => utils.assertPathSafe(dest, dest)).to.not.throw();
            expect(() => utils.assertPathSafe(dest, pth.join(dest, "existing"))).to.not.throw();
            expect(() => utils.assertPathSafe(dest, pth.join(dest, "existing", "file.txt"))).to.not.throw();
            expect(() => utils.assertPathSafe(dest, pth.join(dest, "missing", "deeper", "file.txt"))).to.not.throw();
            // paths outside the root are sanitize()'s responsibility and are left alone
            expect(() => utils.assertPathSafe(dest, outside)).to.not.throw();
        });

        it("is a no-op for a custom fs without lstatSync", () => {
            const customFs = Object.assign({}, fs);
            delete customFs.lstatSync;
            const utils = new Utils({ fs: customFs });

            expect(() => utils.assertPathSafe(dest, pth.join(dest, "anything.txt"))).to.not.throw();
        });
    });
});
