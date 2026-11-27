"""The exit's advert on Nostr, as `fips-exit advert` makes and sends it.

    python3 -I -m unittest discover -s test

Standard library only, and no network beyond loopback: the relay is a
stand-in that runs inside the test. The tags are held to the same file as
the Rust crate that specifies them, payd/proto/vectors/advert.json.
"""

import base64
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_loader = importlib.machinery.SourceFileLoader("fips_exit", os.path.join(HERE, "..", "fips-exit"))
_spec = importlib.util.spec_from_loader("fips_exit", _loader)
x = importlib.util.module_from_spec(_spec)
_loader.exec_module(x)

with open(os.path.join(HERE, "..", "payd", "proto", "vectors", "advert.json")) as _file:
    VECTORS = json.load(_file)
KEY = bytes(31) + b"\x03"
ZERO = bytes(32)


def bech32(prefix, data):
    """`data` as a bech32 string: what the script only ever reads."""
    acc, bits, values = 0, 0, []
    for byte in data:
        acc, bits = (acc << 8) | byte, bits + 8
        while bits >= 5:
            bits -= 5
            values.append((acc >> bits) & 31)
    if bits:
        values.append((acc << (5 - bits)) & 31)
    expanded = [ord(c) >> 5 for c in prefix] + [0] + [ord(c) & 31 for c in prefix]
    check = x.bech32_polymod(expanded + values + [0] * 6) ^ 1
    values += [(check >> 5 * (5 - i)) & 31 for i in range(6)]
    return prefix + "1" + "".join(x.BECH32[v] for v in values)


class Schnorr(unittest.TestCase):
    """BIP-340, against the BIP's own vectors."""

    def test_the_bips_signing_vectors(self):
        vectors = [
            ("0000000000000000000000000000000000000000000000000000000000000003",
             "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
             "0000000000000000000000000000000000000000000000000000000000000000",
             "0000000000000000000000000000000000000000000000000000000000000000",
             "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
             "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
            ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
             "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
             "0000000000000000000000000000000000000000000000000000000000000001",
             "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
             "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
             "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
        ]
        for seckey, pub, aux, message, sig in vectors:
            seckey, message = bytes.fromhex(seckey), bytes.fromhex(message)
            self.assertEqual(x.schnorr_pubkey(seckey).hex().upper(), pub)
            made = x.schnorr_sign(message, seckey, bytes.fromhex(aux))
            self.assertEqual(made.hex().upper(), sig)
            self.assertTrue(x.schnorr_verify(message, bytes.fromhex(pub), made))

    def test_a_changed_message_key_or_signature_does_not_verify(self):
        message = hashlib.sha256(b"advert").digest()
        sig = x.schnorr_sign(message, KEY, os.urandom(32))
        pub = x.schnorr_pubkey(KEY)
        self.assertTrue(x.schnorr_verify(message, pub, sig))
        self.assertFalse(x.schnorr_verify(hashlib.sha256(b"other").digest(), pub, sig))
        self.assertFalse(x.schnorr_verify(message, x.schnorr_pubkey(bytes(31) + b"\x05"), sig))
        self.assertFalse(x.schnorr_verify(message, pub, sig[:-1] + bytes([sig[-1] ^ 1])))
        self.assertFalse(x.schnorr_verify(message, pub, sig[:40]))

    def test_what_is_not_a_key_is_refused(self):
        for bad in (ZERO, bytes.fromhex("ff" * 32), b"\x03", KEY + b"\x00"):
            with self.assertRaises(x.AdvertError):
                x.schnorr_pubkey(bad)
            with self.assertRaises(x.AdvertError):
                x.schnorr_sign(ZERO, bad, ZERO)


class Keys(unittest.TestCase):
    def read(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".key") as f:
            f.write(text)
            f.flush()
            return x.read_key(f.name)

    def test_hex_and_nsec_give_the_same_key(self):
        self.assertEqual(self.read(KEY.hex() + "\n"), KEY)
        self.assertEqual(self.read(KEY.hex().upper()), KEY)
        self.assertEqual(self.read(bech32("nsec", KEY) + "\n"), KEY)
        self.assertEqual(self.read("  " + bech32("nsec", KEY).upper() + "  "), KEY)

    def test_what_is_not_a_key_is_not_read_and_not_repeated(self):
        nsec = bech32("nsec", KEY)
        for bad in (nsec[:-1] + ("q" if nsec[-1] != "q" else "p"), bech32("npub", KEY), nsec[:-4], "", "abc",
                    KEY.hex()[:-2], bech32("nsec", KEY[:20])):
            with self.assertRaises(x.AdvertError) as refused:
                self.read(bad)
            if bad:
                self.assertNotIn(bad, str(refused.exception), "what the file held is not printed")
        # A key as 32 raw bytes, or any file that is not text: the same answer,
        # and no error of Python's own that would quote a byte of it.
        for held in (KEY, bytes(range(200, 232)), b"\xff\xfe" + nsec.encode()):
            with tempfile.NamedTemporaryFile("wb", suffix=".key") as f:
                f.write(held)
                f.flush()
                with self.assertRaises(x.AdvertError) as refused:
                    x.read_key(f.name)
            self.assertIn("holds neither an nsec nor 64 hex digits", str(refused.exception))
            self.assertIsNone(refused.exception.__cause__)
            self.assertTrue(refused.exception.__suppress_context__, "nothing of the first error is shown")
        with self.assertRaises(x.AdvertError) as missing:
            x.read_key("/nonexistent/fips.key")
        self.assertIn("/nonexistent/fips.key", str(missing.exception))

    def test_the_address_of_a_key_is_what_fips_derives(self):
        # One identity three ways: its npub, its public key, its address.
        pub = x.schnorr_pubkey(KEY)
        self.assertEqual(x.bech32_key(bech32("npub", pub), "npub"), pub)
        self.assertEqual(x.npub_to_address(bech32("npub", pub)), x.key_address(pub))
        self.assertEqual(x.key_address(pub).packed, b"\xfd" + hashlib.sha256(pub).digest()[:15])
        for bad in ("npub1", "nsec1" + bech32("npub", pub)[5:], bech32("npub", pub)[:-1] + "!"):
            with self.assertRaises(ValueError):
                x.npub_to_address(bad)


class Tags(unittest.TestCase):
    """What an exit writes, against the cases the Rust crate is held to."""

    def test_an_exit_writes_the_tags_the_vectors_say(self):
        self.assertGreaterEqual(len(VECTORS["write"]), 45)
        for case in VECTORS["write"]:
            with self.subTest(case["case"]):
                if "tags" in case:
                    self.assertEqual(x.advert_tags(case["advert"], case["now"]), case["tags"])
                else:
                    with self.assertRaises(x.AdvertError):
                        x.advert_tags(case["advert"], case["now"])

    def test_the_countries_are_the_vectors(self):
        self.assertEqual(x.COUNTRIES, VECTORS["countries"].split())
        self.assertEqual(len(x.COUNTRIES), 249)

    def test_an_access_word_nobody_knows_is_refused(self):
        advert = {"access": "invite", "name": "", "about": "", "expires": 10, "terms": None}
        with self.assertRaises(x.AdvertError):
            x.advert_tags(advert, 1)

    def test_text_is_tidied_as_the_vectors_say(self):
        self.assertGreaterEqual(len(VECTORS["tidy"]), 70)
        for case in VECTORS["tidy"]:
            with self.subTest(repr(case["text"])):
                self.assertEqual(x.tidy(case["text"], case["limit"]), case["tidy"])
                # An exit writes only what a reader would show as it is.
                self.assertEqual(x.text_in_order(case["text"], case["limit"]), case["text"] == case["tidy"])

    def test_no_character_that_cannot_be_seen_is_written_in_these_files(self):
        """The script, this test and the vectors name such characters by
        number or as escapes. As themselves they could not be reviewed, and
        an editor that drops them would change what the code does."""
        files = ("../fips-exit", "test_advert.py", "../payd/proto/vectors/advert.json", "../payd/proto/src/lib.rs")
        for name in files:
            with open(os.path.join(HERE, name), encoding="utf-8") as file:
                for number, line in enumerate(file, 1):
                    unseen = [hex(ord(c)) for c in line.rstrip("\n") if x._among(c, x.HIDDEN)]
                    self.assertEqual(unseen, [], f"{name}:{number}")


class Event(unittest.TestCase):
    TAGS = [["d", "fips-exit"], ["v", "1"], ["access", "allow-list"], ["name", "Zürich ☕"],
            ["country", "CH"], ["expiration", "1800010800"]]

    def test_id_and_signature_are_nip_01s(self):
        e = x.build_event(KEY, self.TAGS, 1_800_000_000, aux=ZERO)
        self.assertEqual((e["kind"], e["content"], e["created_at"]), (30078, "", 1_800_000_000))
        self.assertEqual(e["pubkey"], x.schnorr_pubkey(KEY).hex())
        self.assertEqual(e["tags"], self.TAGS)
        # The id is the hash of this exact serialisation: no spaces, and
        # characters outside ASCII as themselves, not escaped.
        body = '[0,"%s",1800000000,30078,%s,""]' % (
            e["pubkey"], json.dumps(self.TAGS, separators=(",", ":"), ensure_ascii=False))
        self.assertIn("Zürich ☕", body)
        self.assertEqual(e["id"], hashlib.sha256(body.encode()).hexdigest())
        self.assertTrue(x.schnorr_verify(bytes.fromhex(e["id"]), bytes.fromhex(e["pubkey"]), bytes.fromhex(e["sig"])))
        # The same event again is the same event, but for the signature's randomness.
        again = x.build_event(KEY, self.TAGS, 1_800_000_000)
        self.assertEqual(again["id"], e["id"])
        self.assertNotEqual(again["sig"], e["sig"])


class Relays(unittest.TestCase):
    NPUB = bech32("npub", x.schnorr_pubkey(KEY))

    def test_urls(self):
        self.assertEqual(x.parse_relay("wss://relay.example.org"), (True, "relay.example.org", 443, "/"))
        self.assertEqual(x.parse_relay("ws://10.0.0.5:7777/nostr"), (False, "10.0.0.5", 7777, "/nostr"))
        self.assertEqual(x.parse_relay(f"ws://{self.NPUB}.fips:7777"), (False, f"{self.NPUB}.fips", 7777, "/"))

    def test_bad_urls_are_refused(self):
        for bad in ("relay.example.org", "http://relay.example.org", "wss://relay.example.org:99999",
                    "wss://relay.example.org:0", "ws://home.fips", f"wss://{self.NPUB}.fips", "wss://exa mple.org",
                    "wss://x/ y", "ws://[fd00::1]:80", "",
                    # Names the resolver would refuse with an error of its own.
                    "wss://relay..example.org", "wss://.example.org", "wss://example.org.", "wss://-a.example",
                    "wss://a-.example", "wss://" + "a" * 64 + ".example", "wss://" + "a." * 127 + "example"):
            with self.assertRaises(x.AdvertError, msg=bad):
                x.parse_relay(bad)

    def test_the_list_needs_one_relay_and_has_a_ceiling(self):
        self.assertEqual(x.parse_relays("wss://a.example, ws://b.example"), ["wss://a.example", "ws://b.example"])
        for bad in ("", " , ", " ".join(f"wss://r{i}.example" for i in range(9)), "wss://a.example nonsense"):
            with self.assertRaises(x.AdvertError, msg=bad):
                x.parse_relays(bad)


def frame(opcode, payload, last=True):
    """One frame as a server sends it: not masked."""
    head = bytes([(0x80 if last else 0) | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack(">H", n)
    else:
        head += bytes([127]) + struct.pack(">Q", n)
    return head + payload


class Relay:
    """A Nostr relay as far as an EVENT goes: on loopback, for one test.
    `answer` makes its reply to an event out of the event; `seen` is what
    it was sent."""

    def __init__(self, answer):
        self.answer, self.seen = answer, []
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.url = "ws://127.0.0.1:%d/" % self.listener.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                peer, _ = self.listener.accept()
            except OSError:
                return
            with peer:
                try:
                    self.talk(peer)
                except (OSError, ValueError, x.AdvertError):
                    pass

    def talk(self, peer):
        peer.settimeout(5)
        head = b""
        while b"\r\n\r\n" not in head:
            head += peer.recv(1)
        key = [line.split(b": ", 1)[1] for line in head.split(b"\r\n")
               if line.lower().startswith(b"sec-websocket-key")][0]
        accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        peer.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
        # A client's frames are masked, which the script's own reader takes too.
        message = json.loads(x._receive_message(peer, time.monotonic() + 5))
        self.seen.append(message)
        for reply in self.answer(message[1]):
            if callable(reply):
                reply(peer)  # whatever it does with the connection
                continue
            payload = reply if isinstance(reply, bytes) else json.dumps(reply).encode()
            peer.sendall(frame(0x9 if reply == b"ping" else 0x1, payload))
        peer.recv(64)  # until the client hangs up

    def close(self):
        self.listener.close()


class Publish(unittest.TestCase):
    def event(self):
        return x.build_event(KEY, Event.TAGS, 1_800_000_000)

    def relay(self, answer):
        relay = Relay(answer)
        self.addCleanup(relay.close)
        return relay

    def test_an_accepted_event_is_the_one_that_was_made(self):
        relay = self.relay(lambda e: [["OK", e["id"], True, ""]])
        event = self.event()
        self.assertEqual(x.publish(event, relay.url), "")
        self.assertEqual(relay.seen, [["EVENT", event]])

    def test_a_relay_may_say_other_things_first_and_ping(self):
        relay = self.relay(lambda e: [["NOTICE", "hello"], b"not json", b"ping", ["OK", "another id", True, ""],
                                      ["OK", e["id"], True, "duplicate: already have this event"]])
        self.assertEqual(x.publish(self.event(), relay.url), "duplicate: already have this event")

    def test_a_rejection_is_said_with_the_relays_reason(self):
        relay = self.relay(lambda e: [["OK", e["id"], False, "blocked: not on the list " + "x" * 500]])
        with self.assertRaises(x.AdvertError) as refused:
            x.publish(self.event(), relay.url)
        self.assertIn("blocked: not on the list", str(refused.exception))
        self.assertLess(len(str(refused.exception)), 200, "a relay's words are cut")

    def test_a_relays_words_cannot_do_anything_to_the_terminal(self):
        relay = self.relay(lambda e: [["OK", e["id"], True, "fine\x1b[2J\x07\nfips-exit: all is lost"]])
        self.assertEqual(x.publish(self.event(), relay.url), "fine?[2J??fips-exit: all is lost")

    def test_a_relay_that_says_nothing_is_not_waited_for_for_ever(self):
        relay = self.relay(lambda e: [])
        with self.assertRaises((x.AdvertError, OSError)):
            x.publish(self.event(), relay.url, timeout=0.5)

    def test_an_oversized_frame_ends_it(self):
        relay = self.relay(lambda e: [lambda peer: peer.sendall(bytes([0x81, 127]) + struct.pack(">Q", 1 << 40))])
        with self.assertRaises(x.AdvertError) as refused:
            x.publish(self.event(), relay.url, timeout=2)
        self.assertIn("oversized", str(refused.exception))
        # And one that is within the limit frame by frame, and not as a whole.
        def three_parts(peer):
            for part in range(3):
                peer.sendall(frame(0x1 if part == 0 else 0x0, b"x" * 60000, last=False))
        relay = self.relay(lambda e: [three_parts])
        with self.assertRaises(x.AdvertError) as refused:
            x.publish(self.event(), relay.url, timeout=2)
        self.assertIn("oversized", str(refused.exception))

    def test_an_answer_in_several_frames_is_one_answer(self):
        def in_parts(e):
            answer = json.dumps(["OK", e["id"], True, "stored"]).encode()
            return [lambda peer: peer.sendall(frame(0x1, answer[:10], last=False) + frame(0x9, b"still there?")
                                              + frame(0x0, answer[10:30], last=False) + frame(0x0, answer[30:]))]
        self.assertEqual(x.publish(self.event(), self.relay(in_parts).url), "stored")
        # A binary message, whole or in parts, is not an answer; the text after it is.
        def binary_first(e):
            return [lambda peer: peer.sendall(frame(0x2, b"\x00\x01", last=False) + frame(0x0, b"\x02")),
                    ["OK", e["id"], True, ""]]
        self.assertEqual(x.publish(self.event(), self.relay(binary_first).url), "")

    def test_a_relay_that_keeps_sending_is_not_waited_for_any_longer(self):
        """The time is for the whole answer: a ping now and then, or a byte
        now and then, does not buy more of it."""
        def pings(peer):
            for _ in range(40):
                peer.sendall(frame(0x9, b"ping"))
                time.sleep(0.2)

        def drips(peer):
            peer.sendall(bytes([0x81, 126]) + struct.pack(">H", 65535))
            for _ in range(20):
                peer.sendall(b"x")
                time.sleep(0.4)

        for behaviour in (pings, drips):
            relay = self.relay(lambda e, behaviour=behaviour: [behaviour])
            started = time.monotonic()
            with self.assertRaises(x.AdvertError) as refused:
                x.publish(self.event(), relay.url, timeout=1)
            self.assertIn("in time", str(refused.exception))
            self.assertLess(time.monotonic() - started, 3, behaviour.__name__)

    def test_an_answer_nested_deeper_than_python_follows_is_not_an_answer(self):
        relay = self.relay(lambda e: [b"[" * 60000, ["OK", e["id"], True, "after it"]])
        self.assertEqual(x.publish(self.event(), relay.url), "after it")

    def test_what_is_not_a_relay_is_said(self):
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)

        def http():
            peer, _ = listener.accept()
            with peer:
                peer.recv(4096)
                peer.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        threading.Thread(target=http, daemon=True).start()
        with self.assertRaises(x.AdvertError) as refused:
            x.publish(self.event(), "ws://127.0.0.1:%d" % listener.getsockname()[1], timeout=2)
        self.assertIn("404", str(refused.exception))


class Command(unittest.TestCase):
    """`fips-exit advert`, with the node's address and the daemon's device
    stood in for: everything else is the command as it runs."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.key = os.path.join(self.dir.name, "fips.key")
        with open(self.key, "w") as f:
            f.write(bech32("nsec", KEY) + "\n")
        self.config = os.path.join(self.dir.name, "config")
        self.saved = (x.CONFIG, x.mesh_address, x.tun_present)
        x.CONFIG = self.config
        x.mesh_address = lambda config: x.key_address(x.schnorr_pubkey(KEY))
        x.tun_present = lambda config: True
        self.addCleanup(self.restore)

    def restore(self):
        x.CONFIG, x.mesh_address, x.tun_present = self.saved

    def configure(self, **settings):
        settings.setdefault("FIPS_KEY", self.key)
        with open(self.config, "w") as f:
            f.write("# an exit\n" + "".join(f"{k}={v}\n" for k, v in settings.items()))

    def run_advert(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            try:
                x.cmd_advert(*args)
                status = 0
            except SystemExit as stopped:
                status = stopped.code
        return status, out.getvalue()

    def test_nothing_is_said_without_a_relay(self):
        self.configure(COUNTRY="DE")
        self.assertEqual(self.run_advert(), (0, f"fips-exit: no advert: ADVERT_RELAYS is not set in {self.config}\n"))

    def test_the_advert_says_what_the_config_says(self):
        relay = Relay(lambda e: [["OK", e["id"], True, ""]])
        self.addCleanup(relay.close)
        self.configure(ADVERT_RELAYS=f"{relay.url}", ADVERT_NAME='"An   exit"', ADVERT_ABOUT="In a rack   # not this",
                       COUNTRY="DE", ACCESS="paid")
        status, out = self.run_advert()
        self.assertEqual((status, out), (0, f"{relay.url}: accepted\n"))
        (_, event), = relay.seen
        self.assertEqual(event["pubkey"], x.schnorr_pubkey(KEY).hex())
        self.assertTrue(x.schnorr_verify(bytes.fromhex(event["id"]), bytes.fromhex(event["pubkey"]),
                                         bytes.fromhex(event["sig"])))
        expires = event["created_at"] + 3 * 3600
        # Nothing takes a payment yet, so even an exit with ACCESS=paid says allow-list.
        self.assertEqual(event["tags"], [["d", "fips-exit"], ["v", "1"], ["access", "allow-list"],
                                         ["name", "An exit"], ["about", "In a rack"], ["country", "DE"],
                                         ["expiration", str(expires)]])

    def test_show_prints_the_event_and_sends_nothing(self):
        self.configure(COUNTRY="IS")
        status, out = self.run_advert("show")
        self.assertEqual(status, 0)
        event = json.loads(out)
        self.assertIn(["country", "IS"], event["tags"])
        self.assertNotIn("name", [t[0] for t in event["tags"]])

    def test_one_relay_down_is_said_and_the_other_counts(self):
        relay = Relay(lambda e: [["OK", e["id"], True, ""]])
        self.addCleanup(relay.close)
        dead = socket.create_server(("127.0.0.1", 0))
        gone = "ws://127.0.0.1:%d" % dead.getsockname()[1]
        dead.close()
        self.configure(ADVERT_RELAYS=f"{gone} {relay.url}")
        status, out = self.run_advert()
        self.assertEqual(status, 0)
        self.assertIn(f"{relay.url}: accepted", out)
        self.assertIn(f"{gone}: ", out)
        self.configure(ADVERT_RELAYS=gone)
        self.assertNotEqual(self.run_advert()[0], 0, "no relay took it: that is a failure")

    def test_a_hash_in_a_quoted_name_is_part_of_the_name(self):
        self.configure(COUNTRY="DE", ADVERT_NAME='"Exit #2"', ADVERT_ABOUT='"a # b"  # a comment',
                       WAN="eth0 # the uplink", TUN='"tun9"', MESH_IF="fips0#x")
        with open(self.config, "a") as f:
            f.write("#ACCESS=paid\n  # WAN=other\nnothing here\n")
        config = x.load_config()
        self.assertEqual((config["ADVERT_NAME"], config["ADVERT_ABOUT"]), ("Exit #2", "a # b"))
        self.assertEqual((config["WAN"], config["TUN"], config["MESH_IF"], config["ACCESS"]),
                         ("eth0", "tun9", "fips0", "allow-list"))
        status, out = self.run_advert("show")
        self.assertEqual(status, 0)
        self.assertIn(["name", "Exit #2"], json.loads(out)["tags"])

    def test_what_is_wrong_stops_it_before_anything_is_sent(self):
        relay = Relay(lambda e: [["OK", e["id"], True, ""]])
        self.addCleanup(relay.close)
        for settings in (dict(COUNTRY="de"), dict(COUNTRY="Germany"), dict(ADVERT_NAME="x" * 41),
                         dict(ADVERT_RELAYS="relay.example.org"), dict(FIPS_KEY="/nonexistent/fips.key")):
            settings.setdefault("ADVERT_RELAYS", relay.url)
            self.configure(**settings)
            status, _ = self.run_advert()
            self.assertNotIn(status, (0, None), settings)
        self.assertEqual(relay.seen, [])

    def test_a_key_that_is_not_this_nodes_is_not_signed_with(self):
        relay = Relay(lambda e: [["OK", e["id"], True, ""]])
        self.addCleanup(relay.close)
        self.configure(ADVERT_RELAYS=relay.url)
        x.mesh_address = lambda config: x.key_address(x.schnorr_pubkey(bytes(31) + b"\x05"))
        status, _ = self.run_advert()
        self.assertIn("is not this node's", str(status))
        self.assertEqual(relay.seen, [])

    def test_nothing_is_said_for_an_exit_that_is_not_running(self):
        relay = Relay(lambda e: [["OK", e["id"], True, ""]])
        self.addCleanup(relay.close)
        # With fips itself stopped there is no mesh interface to ask, and
        # perhaps no key: none of that is looked at, and the timer's unit
        # does not fail every hour.
        self.configure(ADVERT_RELAYS=relay.url, FIPS_KEY="/nonexistent/fips.key")
        x.tun_present = lambda config: False
        x.mesh_address = lambda config: x.die("no interface fips0: is fips running?")
        self.assertEqual(self.run_advert(), (0, "fips-exit: no advert: the exit is not running\n"))
        self.assertEqual(relay.seen, [])

    def test_one_relay_that_breaks_the_client_does_not_stop_the_next(self):
        relay = Relay(lambda e: [["OK", e["id"], True, ""]])
        self.addCleanup(relay.close)
        self.configure(ADVERT_RELAYS=f"ws://first.example {relay.url}")
        real = x.publish

        def publish(event, url):
            if "first" in url:
                raise RuntimeError("something nobody expected\x1b[2J")
            return real(event, url)
        x.publish = publish
        self.addCleanup(setattr, x, "publish", real)
        status, out = self.run_advert()
        self.assertEqual(status, 0)
        self.assertIn("ws://first.example: something nobody expected?[2J\n", out)
        self.assertIn(f"{relay.url}: accepted", out)


if __name__ == "__main__":
    unittest.main()
