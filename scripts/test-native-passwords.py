"""Exercise the shipped native password prompt; never print entered values."""
import contextlib,importlib.util,io,sys,types,unittest
from pathlib import Path
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
SOURCE=Path(sys.argv.pop(1))/'native_setup.py' if len(sys.argv)>1 else ROOT/'installer/native_setup.py'
common=types.ModuleType('ota.common')
for name in ('BASE','CONFIG','write','config','compose','current_version'):setattr(common,name,Mock())
spec=importlib.util.spec_from_file_location('native_setup',SOURCE)
setup=importlib.util.module_from_spec(spec)
with patch.dict(sys.modules,{'ota.common':common,'rpc':types.SimpleNamespace(call=Mock())}):spec.loader.exec_module(setup)

class PasswordPromptTests(unittest.TestCase):
    def prompt(self,values):
        log=io.StringIO()
        with patch.object(setup.getpass,'getpass',side_effect=values) as read,contextlib.redirect_stdout(log):
            result=setup.password('GUI administrator password: ')
        for value in values:
            if isinstance(value,str) and len(value)>=8:self.assertNotIn(value,log.getvalue())
        return result,log.getvalue(),read

    def test_valid_minimum_reaches_confirmation(self):
        value='a'*5;result,log,read=self.prompt([value,value])
        self.assertEqual(result,value);self.assertEqual(read.call_count,2)
        self.assertEqual(read.call_args.args,('Confirm password: ',))
        self.assertIn('input is hidden',log)

    def test_valid_maximum(self):
        value='z'*72;self.assertEqual(self.prompt([value,value])[0],value)

    def test_short_password_explains_cause_then_accepts(self):
        value='long enough test passphrase'
        result,log,read=self.prompt(['abcd',value,value])
        self.assertEqual(result,value);self.assertIn('Password too short',log)
        self.assertEqual(read.call_count,3)

    def test_long_password_explains_cause_then_accepts(self):
        value='long enough test passphrase'
        self.assertIn('Password too long',self.prompt(['a'*73,value,value])[1])

    def test_utf8_limits_count_bytes(self):
        value='é'*5;self.assertEqual(self.prompt([value,value])[0],value)
        self.assertIn('Password too short',self.prompt(['é'*4,value,value])[1])
        self.assertIn('Password too long',self.prompt(['é'*37,value,value])[1])

    def test_eight_and_eleven_character_passwords_accepted(self):
        for value in ('abcdefgh','abcdefghijk'):
            self.assertEqual(self.prompt([value,value])[0],value)

    def test_mismatch_has_separate_message(self):
        value='long enough test passphrase'
        result,log,read=self.prompt([value,'different test passphrase',value,value])
        self.assertEqual(result,value);self.assertIn('Passwords do not match',log)

    def test_unsupported_characters_explain_cause(self):
        value='long enough test passphrase'
        for character in ("'",'\\','\n','\r','\x00'):
            with self.subTest(character=repr(character)):
                self.assertIn('unsupported character',self.prompt([value+character,value,value])[1])

    def test_supported_special_characters_and_spaces(self):
        value='Test $#!@% " special spaces'
        self.assertEqual(self.prompt([value,value])[0],value)

    def test_cancel_does_not_loop(self):
        with patch.object(setup.getpass,'getpass',side_effect=KeyboardInterrupt),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):setup.password('Password: ')

    def test_eof_does_not_loop(self):
        with patch.object(setup.getpass,'getpass',side_effect=EOFError),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(EOFError):setup.password('Password: ')

if __name__=='__main__':unittest.main(verbosity=2)
