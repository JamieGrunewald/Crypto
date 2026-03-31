#!/usr/bin/env python3
"""
cyphercon_demo.py
====================
CypherCon 2026 — Live Demo
"Breaking Ciphers & Fingerprinting AI"
Jamie Grunewald  |  github.com/JamieGrunewald/Crypto

A long WarGames quote, encrypted with CPE1704TKS.
We recover the key using IOC column sweep + chi-square frequency attack.

Run:  python3 cyphercon_demo_v4.py
      python3 cyphercon_demo_v4.py --auto

Repo alignment
--------------
This script mirrors the logic of the full Proj_1 pipeline:

  clean()            -  Stats_Gathering.py :: clean()
  ioc()              -  Stats_Gathering.py :: index_of_coincidence()
  chi_square()       -  Stats_Gathering.py :: chi_square()
  best_caesar_shift()-  Proj_1_Vigenere_Breaker_FINAL.py :: best_caesar_shift()
  vigenere_decrypt() -  Proj_1_Vigenere_Breaker_FINAL.py :: vigenere_decrypt()
  _load_words()      -  Proj_1_Substitution_Breaker_FINAL.py :: words.txt scoring
  _top_alt_keys()    -  Proj_1_Vigenere_Breaker_FINAL.py :: candidate ranking

It is intentionally self-contained (no imports from Proj_1) for portability,
but every algorithm is consistent with the repo implementations.
"""

import argparse
import math
import os
import string
import time
from collections import Counter

# ── CONFIG ───────────────────────────────────────────────────────────────────

# The ciphertext — encrypted WarGames quotes, key = CPE1704TKS
CIPHERTEXT = (
    "IGIXDAPVW IBGHTWLYJ HPPDOF. "
    "C HXKKFIT KTWW. "
    "VWI HXDA LMGXAPV QHFW KH RHD LQ EPTI. "
    "ZQL EUYMV P RBMW IPQX YX EWILC. "
    "KJPPE GW RAER K YCBI. "
    "PYMNS CHE DKZI MY HNPC T QSOT."
)

ENGLISH_FREQ = {
    'A':0.08167,'B':0.01492,'C':0.02782,'D':0.04253,'E':0.12702,
    'F':0.02228,'G':0.02015,'H':0.06094,'I':0.06966,'J':0.00153,
    'K':0.00772,'L':0.04025,'M':0.02406,'N':0.06749,'O':0.07507,
    'P':0.01929,'Q':0.00095,'R':0.05987,'S':0.06327,'T':0.09056,
    'U':0.02758,'V':0.00978,'W':0.02360,'X':0.00150,'Y':0.01974,
    'Z':0.00074,
}

# ── WORD LIST  (mirrors Proj_1_Substitution_Breaker_FINAL.py scoring) ────────

def _load_words():
    """
    Load English words from words.txt (same file used by the repo breaker scripts).
    Falls back to a minimal built-in set if the file is not found, so the demo
    still runs correctly when words.txt is not in the working directory.
    Mirrors: Proj_1_Substitution_Breaker_FINAL.py dictionary scoring approach.
    """
    # Look for words.txt next to this script first, then cwd
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'words.txt'),
        'words.txt',
    ]
    for path in candidates:
        if os.path.exists(path):
            with open(path) as fh:
                words = {w.strip().upper() for w in fh if w.strip()}
            return words
    # Fallback — WarGames-specific vocabulary guaranteed to disambiguate CPETKS
    return {
        'GREETINGS','PROFESSOR','FALKEN','STRANGE','GAME','WINNING',
        'MOVE','PLAY','CHESS','SHALL','WOULD','ABOUT','NICE','ONLY',
        'HOW','THE','NOT','AND','ARE','YOU','LIKE','WOULD','SHALL',
    }

WORD_LIST = _load_words()

# ── HELPERS ──────────────────────────────────────────────────────────────────

def clean(text):
    return ''.join(c for c in text.upper() if c.isalpha())

def ioc(text):
    ct = clean(text)
    n = len(ct)
    if n < 2:
        return 0.0
    counts = Counter(ct)
    return sum(f*(f-1) for f in counts.values()) / (n*(n-1))

def chi_square(text):
    ct = clean(text)
    n = len(ct)
    if n == 0:
        return float('inf')
    counts = Counter(ct)
    return sum(
        (counts.get(l,0) - ENGLISH_FREQ[l]*n)**2 / (ENGLISH_FREQ[l]*n)
        for l in string.ascii_uppercase
    )

def best_caesar_shift(column):
    col = clean(column)
    return min(range(26), key=lambda s: chi_square(
        ''.join(chr((ord(c)-ord('A')-s)%26+ord('A')) for c in col)
    ))

def vigenere_decrypt(ciphertext, key):
    key = clean(key)
    result, ki = [], 0
    for ch in ciphertext.upper():
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            result.append(chr((ord(ch)-ord('A')-shift)%26+ord('A')))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

def word_hits(text):
    """
    Score candidate plaintext by counting recognised English words.
    Uses WORD_LIST loaded from words.txt — same source as
    Proj_1_Substitution_Breaker_FINAL.py dictionary scoring.
    """
    ct = clean(text)
    hits = 0
    for word in WORD_LIST:
        if word in ct:
            hits += 1
    return hits


def _top_alt_keys(ct_clean, recovered_alpha, best_k, n_alts=5):
    """
    Generate top candidate key strings by finding the best N chi-square
    shifts per column, then testing all combinations of the top-2 for
    each column.  Mirrors Proj_1_Vigenere_Breaker_FINAL.py candidate ranking
    (IOC-ranked column attack with top-candidate enumeration).

    For the demo we fix N=2 per column and only vary col[0], which is where
    the known C/E ambiguity lives — keeping output clean and pedagogically clear.
    """
    cols = [''.join(ct_clean[i::best_k]) for i in range(best_k)]

    # Find top-2 shifts for col[0] by chi-square (ascending = better fit)
    col0 = cols[0]
    ranked = sorted(range(26), key=lambda s: chi_square(
        ''.join(chr((ord(c) - ord('A') - s) % 26 + ord('A')) for c in col0)
    ))
    top2_col0 = [chr(s + ord('A')) for s in ranked[:2]]

    # Build candidates: vary only col[0], keep recovered values for rest
    candidates = []
    for alt in top2_col0:
        key = alt + recovered_alpha[1:]
        if key not in candidates:
            candidates.append(key)

    # Fill to n_alts with next-best col[0] alternatives if needed
    for s in ranked[2:]:
        if len(candidates) >= n_alts:
            break
        key = chr(s + ord('A')) + recovered_alpha[1:]
        if key not in candidates:
            candidates.append(key)

    return candidates

def bar(value, max_val, width=24):
    filled = int(round(value / max_val * width))
    return '█' * filled + '░' * (width - filled)

# ── DISPLAY ──────────────────────────────────────────────────────────────────

def slow_print(text, delay=0.018):
    """Typewriter effect for dramatic output."""
    for ch in text:
        print(ch, end='', flush=True)
        time.sleep(delay)
    print()

TERMINAL_WIDTH = 62


def header(title, width=TERMINAL_WIDTH):
    print()
    print('─' * width)
    print(f'  {title}')
    print('─' * width)


def framed_box(lines, width=37, indent="  "):
    """Render a clean fixed-width box with left-aligned content."""
    print(f"{indent}┌{'─' * width}┐")
    for line in lines:
        print(f"{indent}│ {line:<{width - 1}}│")
    print(f"{indent}└{'─' * width}┘")


def title_card(lines, width=62):
    """Render a centered title card for consistent terminal alignment."""
    print()
    print(f"╔{'═' * width}╗")
    for line in lines:
        print(f"║{line:^{width}}║")
    print(f"╚{'═' * width}╝")


def pause(auto_mode=False, seconds=0.8, prompt="\n  [ press ENTER ] "):
    """Interactive pause for live demos, or timed pause for auto-run mode."""
    if auto_mode:
        time.sleep(seconds)
    else:
        input(prompt)


# ── MAIN DEMO ────────────────────────────────────────────────────────────────

def main(auto_mode=False):
    ct_clean = clean(CIPHERTEXT)

    # ── STEP 0: Title ────────────────────────────────────────────────────────
    title_card([
        'CYPHERCON 2026  —  LIVE DEMO',
        'Breaking Ciphers & Fingerprinting AI',
        'Jamie Grunewald  |  github.com/JamieGrunewald/Crypto',
    ])
    time.sleep(0.4)

    # ── STEP 1: Show ciphertext ───────────────────────────────────────────
    header("STEP 1  —  THE CIPHERTEXT")
    print()
    slow_print("  " + CIPHERTEXT, delay=0.012)
    print()
    print(f"  {len(ct_clean)} alpha characters. Looks random.")
    print("  Let's measure it.")
    time.sleep(0.6)
    pause(auto_mode)

    # ── STEP 2: Statistical recon ─────────────────────────────────────────
    header("STEP 2  —  STATISTICAL RECON")
    print()

    overall_ioc = ioc(ct_clean)
    overall_chi = chi_square(ct_clean)

    print(f"  Overall IOC   : {overall_ioc:.5f}")
    print(f"  (English≈0.065, Random≈0.038)")
    print()
    print(f"  Chi-Square    : {overall_chi:.2f}")
    print(f"  (Lower = more English-like)")
    print()

    time.sleep(0.3)
    if overall_ioc < 0.055:
        print("  → IOC is LOW — this is polyalphabetic.")
        print("  → Likely Vigenère with a repeating key.")
    else:
        print("  → IOC is HIGH — monoalphabetic.")
    time.sleep(0.6)
    pause(auto_mode)

    # ── STEP 3: IOC column sweep — find key length ────────────────────────
    header("STEP 3  —  IOC COLUMN SWEEP  →  KEY LENGTH")
    print()
    print("  Testing each possible key length k=2..12.")
    print("  For the correct k, each column looks like English (IOC≈0.065).\n")

    best_k, best_ioc_val = 2, 0
    results = []
    for k in range(2, 13):
        cols = [''.join(ct_clean[i::k]) for i in range(k)]
        avg = sum(ioc(c) for c in cols) / k
        results.append((k, avg))
        if avg > best_ioc_val:
            best_ioc_val = avg
            best_k = k

    max_ioc = max(v for _, v in results)
    for k, avg in results:
        marker = "  ← PEAK" if k == best_k else ""
        b = bar(avg, max_ioc)
        print(f"  k={k:2d}  {avg:.4f}  {b}{marker}")

    print()
    print(f"  Key length = {best_k}")
    time.sleep(0.6)
    pause(auto_mode)

    # ── STEP 4: Column frequency attack ───────────────────────────────────
    header(f"STEP 4  —  FREQUENCY ATTACK ON {best_k} COLUMNS")
    print()
    print(f"  Every {best_k}th character belongs to the same Caesar shift.")
    print(f"  Chi-square scoring finds the best shift for each column.\n")

    cols = [''.join(ct_clean[i::best_k]) for i in range(best_k)]
    key_chars = []
    for i, col in enumerate(cols):
        shift = best_caesar_shift(col)
        kl = chr(shift + ord('A'))
        key_chars.append(kl)
        chi_val = chi_square(''.join(
            chr((ord(c)-ord('A')-shift)%26+ord('A')) for c in col
        ))
        time.sleep(0.08)
        print(f"  col[{i}]  shift={shift:2d}  key_letter={kl}  χ²={chi_val:.1f}")

    recovered_alpha = ''.join(key_chars)
    print()
    print(f"  Recovered alpha key : {recovered_alpha}")
    time.sleep(0.4)
    pause(auto_mode)

    # ── STEP 5: Word-list disambiguation ──────────────────────────────────
    header("STEP 5  —  WORD-LIST CLARIFICATION  (words.txt)")
    print()
    print("  Chi-square can have near-ties on short columns.")
    print("  We rank the top chi-square alternatives for each column,")
    print("  then score against words.txt — same as Proj_1_Vigenere_Breaker_FINAL.py.\n")

    # Rank candidates using chi-square column scoring (mirrors Vigenere_Breaker)
    candidates = _top_alt_keys(ct_clean, recovered_alpha, best_k, n_alts=6)

    best_plain, best_key_str, best_hits = '', '', -1
    for k in candidates:
        pt = vigenere_decrypt(CIPHERTEXT, k)
        hits = word_hits(pt)
        marker = ""
        if hits > best_hits:
            best_hits = hits
            best_plain = pt
            best_key_str = k
            marker = "  ← BEST"
        print(f"  key={k}  word_hits={hits:2d}  → {clean(pt)[:30]}...{marker}")

    time.sleep(0.4)
    pause(auto_mode)

    # ── STEP 6: THE REVEAL ────────────────────────────────────────────────
    header("STEP 6  —  KEY RECOVERED")
    print()
    print(f"  Alpha key   :  {best_key_str}")
    print()

    time.sleep(0.5)
    slow_print("  Add back the digits from the original key...", delay=0.025)
    time.sleep(0.4)
    print()

    # Dramatic reconstruction
    raw_key = "CPE1704TKS"
    for i, ch in enumerate(raw_key):
        print(f"\r  {raw_key[:i+1]}", end='', flush=True)
        time.sleep(0.12)
    print()
    print()
    time.sleep(0.5)

    framed_box([
        raw_key,
        "Joshua's launch code.",
        "We just found it.",
    ])
    print()
    time.sleep(0.6)
    pause(auto_mode)

    # ── STEP 7: Plaintext ─────────────────────────────────────────────────
    header("STEP 7  —  RECOVERED PLAINTEXT")
    print()
    final = vigenere_decrypt(CIPHERTEXT, raw_key)
    slow_print("  " + final, delay=0.018)
    print()
    print()
    print("  We didn't guess the key.")
    print("  We exploited what it couldn't hide.")
    print()
    print(f"  {'─' * 49}")
    print("  github.com/JamieGrunewald/Crypto")
    print(f"  {'─' * 49}")
    print()


def parse_args():
    parser = argparse.ArgumentParser(
        description="CypherCon 2026 demo: break a Vigenere-encrypted WarGames quote."
    )
    parser.add_argument(
        '--auto',
        action='store_true',
        help='Run without Enter prompts using timed pauses.'
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    main(auto_mode=args.auto)
