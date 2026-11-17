import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(__file__))
import make_app

class Resolve(unittest.TestCase):
    def test_loader_path_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "libfoo.1.2.3.dylib"); open(real, "w").close()
            os.symlink("libfoo.1.2.3.dylib", os.path.join(d, "libfoo.1.dylib"))
            src = os.path.join(d, "libbar.dylib")
            self.assertEqual(make_app.resolve("@loader_path/libfoo.1.dylib", src, rpaths=[]),
                             os.path.realpath(real))
            self.assertEqual(make_app.resolve(os.path.join(d, "libfoo.1.dylib"), src, rpaths=[]),
                             os.path.realpath(real))
    def test_rpath(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "lib")); real = os.path.join(d, "lib", "libz.dylib"); open(real, "w").close()
            os.mkdir(os.path.join(d, "bin"))
            src = os.path.join(d, "bin", "x")
            self.assertEqual(make_app.resolve("@rpath/libz.dylib", src, rpaths=["@loader_path/../lib"]),
                             os.path.realpath(real))
    def test_unresolved_raises(self):
        with self.assertRaises(SystemExit):
            make_app.resolve("@rpath/nope.dylib", "/tmp/x", rpaths=[])
    def test_system(self):
        self.assertTrue(make_app.is_system("/usr/lib/libSystem.B.dylib"))
        self.assertTrue(make_app.is_system("/System/Library/Frameworks/IOKit.framework/IOKit"))
        self.assertFalse(make_app.is_system("/opt/homebrew/lib/libglib-2.0.0.dylib"))
    def test_cache_tokenise(self):
        text = '# LoaderDir = /opt/homebrew/lib/gdk-pixbuf-2.0/2.10.0/loaders\n"/opt/homebrew/lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-ani.so"\n"ani" 4\n'
        out, loaders = make_app.tokenise_cache(text)
        self.assertIn('"@BUNDLE@/Frameworks/gdk-pixbuf/loaders/libpixbufloader-ani.so"', out)
        self.assertEqual(loaders, [("libpixbufloader-ani.so",
            "/opt/homebrew/lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-ani.so")])
        self.assertIn("# LoaderDir = @BUNDLE@/Frameworks/gdk-pixbuf/loaders\n", out)
        self.assertNotIn("/opt/homebrew", out)

class AppIcons(unittest.TestCase):
    def test_dedup_sorted(self):
        text = 'a "view-reveal-symbolic" b "document-save-symbolic" c "view-reveal-symbolic"'
        self.assertEqual(make_app.app_icon_names(text),
                         ["document-save-symbolic", "view-reveal-symbolic"])
    def test_ignores_non_symbolic(self):
        text = 'x = "pmpro"; y = "emblem-documents"; z = "dialog-password-symbolic-old-x"; ' \
               'w = "a-symbolic b"; v = "Symbolic-Icon-symbolic"'
        self.assertEqual(make_app.app_icon_names(text), [])
        self.assertEqual(make_app.app_icon_names('"network-wireless-symbolic"'),
                         ["network-wireless-symbolic"])

if __name__ == "__main__":
    unittest.main()
