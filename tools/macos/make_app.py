#!/usr/bin/env python3
"""Build a self-contained "NFC PM-Pro.app" (and optionally a DMG) from a GUI build dir.

Usage: make_app.py --build build-gui --version 0.1.0 [--prefix <brew prefix>] [--dmg]
"""
import argparse, os, plistlib, re, shutil, subprocess, sys

BAD_PREFIXES = ("/opt/homebrew", "/usr/local")
FW = "@executable_path/../Frameworks/"


APP_NAME = "NFC PM-Pro.app"


def run(*args):
    try:
        r = subprocess.run(args, capture_output=True, text=True)
    except FileNotFoundError:
        die(f"{args[0]} not found (is it installed and on PATH?)")
    if r.returncode:
        die(f"{' '.join(args)} failed ({r.returncode}): {r.stderr.strip()}")
    return r.stdout


def die(msg):
    raise SystemExit(f"make_app: {msg}")


def is_system(path):
    return path.startswith("/usr/lib/") or path.startswith("/System/")


def is_macho(path):
    with open(path, "rb") as f:
        magic = f.read(4)
    return magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")


def rpaths_of(path):
    out, lines = [], run("otool", "-l", path).splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "cmd LC_RPATH":
            for l2 in lines[i + 1:i + 4]:
                m = re.match(r"\s*path (.*) \(offset \d+\)", l2)
                if m:
                    out.append(m.group(1))
    return out


def deps_of(path):
    lines = run("otool", "-L", path).splitlines()[1:]
    return [l.strip().split(" (compatibility")[0] for l in lines if l.strip()]


def own_id(path):
    lines = run("otool", "-D", path).splitlines()
    return lines[1].strip() if len(lines) > 1 else None


def resolve(ref, src, rpaths):
    d = os.path.dirname(src)
    if ref.startswith("@rpath/"):
        tail = ref[len("@rpath/"):]
        for rp in rpaths:
            rp = rp.replace("@loader_path", d).replace("@executable_path", d)
            cand = os.path.join(rp, tail)
            if os.path.exists(cand):
                return os.path.realpath(cand)
        die(f"cannot resolve {ref} (from {src})")
    if ref.startswith("@loader_path/"):
        cand = os.path.join(d, ref[len("@loader_path/"):])
    elif ref.startswith("@executable_path/"):
        die(f"unexpected {ref} in {src}")
    else:
        cand = ref
    if not os.path.exists(cand):
        die(f"missing dependency {cand} (from {src})")
    return os.path.realpath(cand)


def tokenise_cache(text):
    """Returns (tokenised text, [(loader name, quoted source path)])."""
    loaders = []
    def sub(m):
        loaders.append((m.group(2), m.group(1)))
        return f'"@BUNDLE@/Frameworks/gdk-pixbuf/loaders/{m.group(2)}"'
    out = re.sub(r'^"([^"\n]*/loaders/([^"/\n]+))"', sub, text, flags=re.M)
    out = re.sub(r'^# LoaderDir = .*$', "# LoaderDir = @BUNDLE@/Frameworks/gdk-pixbuf/loaders",
                 out, flags=re.M)
    return out, loaders


def default_prefix():
    try:
        r = subprocess.run(["brew", "--prefix"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except FileNotFoundError:
        pass
    return "/opt/homebrew"


def bundle_closure(roots, fwdir):
    """roots: [(bundled_path, original_path)]. Copies + relinks the closure."""
    seen = {}                       # real source path -> bundled name
    queue = list(roots)
    while queue:
        bundled, src = queue.pop()
        rps = rpaths_of(src)
        myid = own_id(bundled)
        if myid and myid.startswith(BAD_PREFIXES):
            # e.g. the svg pixbuf loader: a .so whose install name is a
            # Homebrew .dylib path. Re-id it (dependency loop skips own id).
            run("install_name_tool", "-id", "@loader_path/" + os.path.basename(bundled), bundled)
            myid = "@loader_path/" + os.path.basename(bundled)
        for ref in deps_of(bundled):
            if ref == myid or is_system(ref) or ref.startswith(FW):
                continue
            real = resolve(ref, src, rps)
            name = os.path.basename(real)
            if real not in seen:
                if name in seen.values():
                    die(f"two different libraries named {name}")
                dst = os.path.join(fwdir, name)
                shutil.copy2(real, dst)
                os.chmod(dst, 0o755)
                run("install_name_tool", "-id", FW + name, dst)
                seen[real] = name
                queue.append((dst, real))
            run("install_name_tool", "-change", ref, FW + seen[real], bundled)
        for rp in rpaths_of(bundled):
            if rp.startswith(BAD_PREFIXES):
                run("install_name_tool", "-delete_rpath", rp, bundled)
    return seen


def min_macos(paths):
    best = (0, 0)
    for p in paths:
        m = re.search(r"minos (\d+)\.(\d+)", run("otool", "-l", p))
        if m:
            best = max(best, (int(m.group(1)), int(m.group(2))))
    return f"{best[0]}.{best[1]}"


def make_icns(svg, res, tmp):
    iconset = os.path.join(tmp, "pmpro.iconset")
    os.makedirs(iconset, exist_ok=True)
    for s in (16, 32, 128, 256, 512):
        for scale, suffix in ((1, ""), (2, "@2x")):
            px = s * scale
            run("rsvg-convert", "-w", str(px), "-h", str(px), svg,
                "-o", os.path.join(iconset, f"icon_{s}x{s}{suffix}.png"))
    run("iconutil", "-c", "icns", iconset, "-o", os.path.join(res, "pmpro.icns"))


SYMBOLIC_RE = re.compile(r'"([a-z0-9-]+-symbolic)"')


def app_icon_names(app_c_text):
    """Sorted unique symbolic icon names used as string literals in app.c."""
    return sorted(set(SYMBOLIC_RE.findall(app_c_text)))


def bundle_icons(prefix, root, res):
    """Copy the Adwaita symbolic icons that app.c uses, plus index.theme."""
    with open(os.path.join(root, "src", "app.c")) as f:
        names = app_icon_names(f.read())
    theme = os.path.join(prefix, "share", "icons", "Adwaita")
    sym = os.path.join(theme, "symbolic")
    index = os.path.realpath(os.path.join(theme, "index.theme"))
    if not os.path.isfile(index):
        die("index.theme not found in Adwaita theme (brew install adwaita-icon-theme)")
    found = {}                      # icon name -> (real source path, subdir)
    for dp, dirs, files in os.walk(sym, followlinks=True):
        dirs.sort()
        for f in sorted(files):
            if f.endswith(".svg") and f[:-4] in names and f[:-4] not in found:
                found[f[:-4]] = (os.path.realpath(os.path.join(dp, f)),
                                 os.path.relpath(dp, sym))
    dst_theme = os.path.join(res, "share", "icons", "Adwaita")
    for name in names:
        if name not in found:
            die(f"icon {name} not found in Adwaita theme (brew install adwaita-icon-theme)")
        src, sub = found[name]
        dst_dir = os.path.join(dst_theme, "symbolic", sub)
        os.makedirs(dst_dir, exist_ok=True)
        shutil.copy2(src, os.path.join(dst_dir, name + ".svg"))
    shutil.copy2(index, os.path.join(dst_theme, "index.theme"))
    return names


def all_machos(root):
    for dp, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(dp, f)
            if not os.path.islink(p) and is_macho(p):
                yield p


def self_check(app):
    for p in all_machos(app):
        text = run("otool", "-L", p) + run("otool", "-l", p)
        for bad in BAD_PREFIXES:
            if bad in text:
                die(f"{p} still references {bad}")
    run("codesign", "--verify", "--deep", "--strict", app)
    run("plutil", "-lint", os.path.join(app, "Contents", "Info.plist"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--prefix", default=None)
    ap.add_argument("--dmg", action="store_true")
    a = ap.parse_args()
    if not a.prefix:
        a.prefix = default_prefix()
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    build = os.path.abspath(a.build)
    app = os.path.join(build, APP_NAME)
    c = os.path.join(app, "Contents")
    fw, res, macos = (os.path.join(c, x) for x in ("Frameworks", "Resources", "MacOS"))
    shutil.rmtree(app, ignore_errors=True)
    loaders_dst = os.path.join(fw, "gdk-pixbuf", "loaders")
    for d in (macos, res, loaders_dst):
        os.makedirs(d)

    roots = []
    for exe in ("pmpro", "pmctl"):
        src = os.path.join(build, exe)
        if not os.path.exists(src):
            die(f"{src} not built")
        dst = os.path.join(macos, exe)
        shutil.copy2(src, dst)
        roots.append((dst, src))

    # gdk-pixbuf loaders + tokenised cache
    pix = os.path.join(a.prefix, "lib", "gdk-pixbuf-2.0", "2.10.0")
    cache_path = os.path.join(pix, "loaders.cache")
    try:
        with open(cache_path) as f:
            cache, loaders = tokenise_cache(f.read())
    except FileNotFoundError:
        die(f"{cache_path} not found (is gdk-pixbuf installed under {a.prefix}?)")
    for n, quoted in loaders:
        src = os.path.realpath(quoted)
        if not os.path.exists(src):
            die(f"pixbuf loader {quoted} (from {cache_path}) not found")
        dst = os.path.join(loaders_dst, n)
        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)
        roots.append((dst, src))
    cdir = os.path.join(res, "lib", "gdk-pixbuf-2.0", "2.10.0")
    os.makedirs(cdir)
    with open(os.path.join(cdir, "loaders.cache"), "w") as f:
        f.write(cache)

    bundle_closure(roots, fw)

    # GSettings schemas (GTK file dialogs abort without them)
    sdir = os.path.join(res, "share", "glib-2.0", "schemas")
    os.makedirs(sdir)
    hb_schemas = os.path.join(a.prefix, "share", "glib-2.0", "schemas")
    for f in os.listdir(hb_schemas):
        if f.startswith("org.gtk.gtk4.") and f.endswith(".gschema.xml"):
            shutil.copy2(os.path.join(hb_schemas, f), sdir)
    run("glib-compile-schemas", sdir)

    # Adwaita symbolic icons named in app.c (GTK does not embed them)
    bundle_icons(a.prefix, root, res)

    tmp = os.path.join(build, "macos-tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    make_icns(os.path.join(root, "data", "com.furui.pmpro.svg"), res, tmp)
    shutil.rmtree(tmp, ignore_errors=True)

    machos = list(all_machos(app))
    info = {
        "CFBundleName": "NFC PM-Pro",
        "CFBundleDisplayName": "NFC PM-Pro",
        "CFBundleIdentifier": "com.furui.pmpro",
        "CFBundleExecutable": "pmpro",
        "CFBundleIconFile": "pmpro",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": a.version,
        "CFBundleVersion": a.version,
        "LSMinimumSystemVersion": min_macos(machos),
        "NSHighResolutionCapable": True,
        "LSApplicationCategoryType": "public.app-category.utilities",
    }
    with open(os.path.join(c, "Info.plist"), "wb") as f:
        plistlib.dump(info, f)

    # sign inside-out: libraries/loaders, then the CLI, then the app (main exe)
    for p in machos:
        if not p.startswith(macos):
            run("codesign", "--force", "--timestamp=none", "-s", "-", p)
    run("codesign", "--force", "--timestamp=none", "-s", "-", os.path.join(macos, "pmctl"))
    run("codesign", "--force", "--timestamp=none", "-s", "-", app)

    self_check(app)
    size = run("du", "-sh", app).split()[0]
    print(f"make_app: {app} ({size}, min macOS {info['LSMinimumSystemVersion']}, "
          f"{len(machos)} Mach-O files)")

    if a.dmg:
        stage = os.path.join(build, "dmg-stage")
        shutil.rmtree(stage, ignore_errors=True)
        os.makedirs(stage)
        run("ditto", app, os.path.join(stage, APP_NAME))
        os.symlink("/Applications", os.path.join(stage, "Applications"))
        dmg = os.path.join(build, f"pmpro-{a.version}-arm64.dmg")
        if os.path.exists(dmg):
            os.remove(dmg)
        run("hdiutil", "create", "-volname", "NFC PM-Pro", "-srcfolder", stage,
            "-ov", "-format", "UDZO", dmg)
        shutil.rmtree(stage)
        print(f"make_app: {dmg}")


if __name__ == "__main__":
    main()
