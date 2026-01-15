# Fuzzing and Random Invalid Inputs

This file contains fuzzing-style invalid inputs - random, malformed, and edge cases that automated testing tools might generate.

## Random Character Injection

### Random Characters in Tag Names
```html
<iwc-build!@#$%time />
<iwc-™®©buildtime />
<iwc-😀🎉🔥time />
<iwc-∞∑∏buildtime />
<iwc-▲▼◄►time />
<iwc-♠♣♥♦buildtime />
<iwc-αβγδtime />
<iwc-ひらがなtime />
<iwc-汉字time />
<iwc-مرحباtime />
<iwc-שלוםtime />
```

### Random Special Sequences
```html
<iwc-build\x00\x01\x02time />
<iwc-build\r\n\ttime />
<iwc-build\u0000time />
<iwc-build\uFFFFtime />
<iwc-build\uFEFFtime />
<iwc-build\u200Btime />
<iwc-build\u200Ctime />
<iwc-build\u200Dtime />
<iwc-build\u202Atime />
<iwc-build\u202Etime />
<iwc-build\uFFFDtime />
```

### Random Binary Data
```html
<iwc-\x89\x50\x4E\x47\x0D\x0A\x1A\x0A />
<iwc-\xFF\xD8\xFF\xE0 />
<iwc-\x1F\x8B\x08 />
<iwc-\x50\x4B\x03\x04 />
<iwc-\xCA\xFE\xBA\xBE />
```

## Length Variations

### Zero Length
```html
<iwc- />
<iwc->
</iwc->
< />
<>
</>
```

### Single Character After Prefix
```html
<iwc-a />
<iwc-b />
<iwc-1 />
<iwc-- />
<iwc-_ />
<iwc-! />
```

### Power-of-Two Lengths
```html
<!-- 2 chars -->
<iwc-ab />

<!-- 4 chars -->
<iwc-abcd />

<!-- 8 chars -->
<iwc-abcdefgh />

<!-- 16 chars -->
<iwc-abcdefghijklmnop />

<!-- 32 chars -->
<iwc-abcdefghijklmnopqrstuvwxyz12345 />

<!-- 64 chars -->
<iwc-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz />

<!-- 128 chars -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa />

<!-- 256 chars -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa />

<!-- 512 chars -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa />

<!-- 1024 chars -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa />

<!-- 2048 chars -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa />

<!-- 4096 chars -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa />
```

### Off-by-One Around Common Limits
```html
<!-- 254 chars (one less than typical limit) -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa />

<!-- 255 chars (typical limit) -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa />

<!-- 256 chars (one over typical limit) -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa />

<!-- 257 chars (two over typical limit) -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa />
```

## Nesting Depth Variations

### Exact Powers of Two
```html
<!-- Depth 1 -->
<iwc-a></iwc-a>

<!-- Depth 2 -->
<iwc-a><iwc-a></iwc-a></iwc-a>

<!-- Depth 4 -->
<iwc-a><iwc-a><iwc-a><iwc-a></iwc-a></iwc-a></iwc-a></iwc-a>

<!-- Depth 8 -->
<iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a>

<!-- Depth 16 -->
<iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a>

<!-- Depth 32 -->
<iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a>
```

### Unbalanced Nesting
```html
<!-- More opening than closing -->
<iwc-a><iwc-a><iwc-a><iwc-a><iwc-a></iwc-a>

<!-- More closing than opening -->
<iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a>

<!-- Alternating imbalance -->
<iwc-a><iwc-a></iwc-a><iwc-a></iwc-a><iwc-a>
```

## Attribute Count Variations

### Exact Powers of Two
```html
<!-- 1 attribute -->
<iwc-a a1="v" />

<!-- 2 attributes -->
<iwc-a a1="v" a2="v" />

<!-- 4 attributes -->
<iwc-a a1="v" a2="v" a3="v" a4="v" />

<!-- 8 attributes -->
<iwc-a a1="v" a2="v" a3="v" a4="v" a5="v" a6="v" a7="v" a8="v" />

<!-- 16 attributes -->
<iwc-a a1="v" a2="v" a3="v" a4="v" a5="v" a6="v" a7="v" a8="v" a9="v" a10="v" a11="v" a12="v" a13="v" a14="v" a15="v" a16="v" />

<!-- 32 attributes -->
<iwc-a a1="v" a2="v" a3="v" a4="v" a5="v" a6="v" a7="v" a8="v" a9="v" a10="v" a11="v" a12="v" a13="v" a14="v" a15="v" a16="v" a17="v" a18="v" a19="v" a20="v" a21="v" a22="v" a23="v" a24="v" a25="v" a26="v" a27="v" a28="v" a29="v" a30="v" a31="v" a32="v" />
```

## Numeric Edge Cases

### Integer Boundaries
```html
<!-- Max int8 -->
<iwc-127 />

<!-- Max uint8 -->
<iwc-255 />

<!-- Max int16 -->
<iwc-32767 />

<!-- Max uint16 -->
<iwc-65535 />

<!-- Max int32 -->
<iwc-2147483647 />

<!-- Max uint32 -->
<iwc-4294967295 />

<!-- Negative -->
<iwc--1 />
<iwc--2147483648 />

<!-- Zero -->
<iwc-0 />
```

### Float Edge Cases
```html
<!-- Zero -->
<iwc-a v="0.0" />

<!-- Negative zero -->
<iwc-a v="-0.0" />

<!-- Infinity -->
<iwc-a v="Infinity" />
<iwc-a v="-Infinity" />

<!-- NaN -->
<iwc-a v="NaN" />

<!-- Very small -->
<iwc-a v="1e-308" />
<iwc-a v="1e-324" />

<!-- Very large -->
<iwc-a v="1e308" />

<!-- Subnormal -->
<iwc-a v="2.2250738585072014e-308" />
```

## Random Mutation Patterns

### Single Character Mutations
```html
<!-- Each character deleted -->
<wc-buildtime />
<ic-buildtime />
<iw-buildtime />
<iwcbuildtime />
<iwc-uildtime />
<iwc-bildtime />
<iwc-buldtime />
<iwc-buidtime />
<iwc-builtime />
<iwc-buildime />
<iwc-buildtme />
<iwc-buildtie />
<iwc-buildtim />

<!-- Each character duplicated -->
<iiwc-buildtime />
<iwwc-buildtime />
<iwcc-buildtime />
<iwc--buildtime />
<iwc-bbuildtime />
<iwc-buuildtime />
<iwc-buiildtime />
<iwc-builldtime />
<iwc-builddtime />
<iwc-buildttime />
<iwc-buildtiime />
<iwc-buildtimme />
<iwc-buildtimee />

<!-- Each character replaced with 'x' -->
<xwc-buildtime />
<ixc-buildtime />
<iwx-buildtime />
<iwcxbuildtime />
<iwc-xuildtime />
<iwc-bxildtime />
<iwc-buxldtime />
<iwc-buixdtime />
<iwc-builxtime />
<iwc-buildxime />
<iwc-buildtxme />
<iwc-buildtixe />
<iwc-buildtimx />
```

### Random Insertions
```html
<xiwc-buildtime />
<ixwc-buildtime />
<iwxc-buildtime />
<iwcx-buildtime />
<iwc-xbuildtime />
<iwc-bxuildtime />
<iwc-buxildtime />
<iwc-buixldtime />
<iwc-builxdtime />
<iwc-buildxtime />
<iwc-buildtxime />
<iwc-buildtixme />
<iwc-buildtimxe />
<iwc-buildtimex />
```

## Boundary Character Values

### ASCII Control Characters
```html
<iwc-\x00build />
<iwc-\x01build />
<iwc-\x02build />
<iwc-\x03build />
<iwc-\x04build />
<iwc-\x05build />
<iwc-\x06build />
<iwc-\x07build />
<iwc-\x08build />
<iwc-\x09build />
<iwc-\x0Abuild />
<iwc-\x0Bbuild />
<iwc-\x0Cbuild />
<iwc-\x0Dbuild />
<iwc-\x0Ebuild />
<iwc-\x0Fbuild />
<iwc-\x10build />
<iwc-\x11build />
<iwc-\x12build />
<iwc-\x13build />
<iwc-\x14build />
<iwc-\x15build />
<iwc-\x16build />
<iwc-\x17build />
<iwc-\x18build />
<iwc-\x19build />
<iwc-\x1Abuild />
<iwc-\x1Bbuild />
<iwc-\x1Cbuild />
<iwc-\x1Dbuild />
<iwc-\x1Ebuild />
<iwc-\x1Fbuild />
<iwc-\x7Fbuild />
```

### ASCII Printable Special Characters
```html
<iwc- build />
<iwc-!build />
<iwc-"build />
<iwc-#build />
<iwc-$build />
<iwc-%build />
<iwc-&build />
<iwc-'build />
<iwc-(build />
<iwc-)build />
<iwc-*build />
<iwc-+build />
<iwc-,build />
<iwc-/build />
<iwc-:build />
<iwc-;build />
<iwc-<build />
<iwc-=build />
<iwc->build />
<iwc-?build />
<iwc-@build />
<iwc-[build />
<iwc-\build />
<iwc-]build />
<iwc-^build />
<iwc-`build />
<iwc-{build />
<iwc-|build />
<iwc-}build />
<iwc-~build />
```

### High ASCII
```html
<iwc-\x80build />
<iwc-\x81build />
<iwc-\x82build />
<iwc-\xFF build />
```

## Unicode Plane Boundaries

### Basic Multilingual Plane (BMP)
```html
<iwc-\u0000build />
<iwc-\u0001build />
<iwc-\uFFFEbuild />
<iwc-\uFFFFbuild />
```

### Surrogate Pairs
```html
<!-- High surrogates -->
<iwc-\uD800build />
<iwc-\uDBFFbuild />

<!-- Low surrogates -->
<iwc-\uDC00build />
<iwc-\uDFFFbuild />

<!-- Invalid surrogate combinations -->
<iwc-\uD800\uD800build />
<iwc-\uDC00\uDC00build />
```

### Supplementary Planes
```html
<!-- Supplementary Multilingual Plane -->
<iwc-𐀀build />
<iwc-𐐀build />

<!-- Supplementary Ideographic Plane -->
<iwc-𠀀build />

<!-- Tertiary Ideographic Plane -->
<iwc-𰀀build />
```

## Whitespace Fuzzing

### All Whitespace Types
```html
<!-- U+0009 CHARACTER TABULATION -->
<iwc-build	time />

<!-- U+000A LINE FEED -->
<iwc-build
time />

<!-- U+000B LINE TABULATION -->
<iwc-build time />

<!-- U+000C FORM FEED -->
<iwc-build time />

<!-- U+000D CARRIAGE RETURN -->
<iwc-buildtime />

<!-- U+0020 SPACE -->
<iwc-build time />

<!-- U+0085 NEXT LINE -->
<iwc-build time />

<!-- U+00A0 NO-BREAK SPACE -->
<iwc-build time />

<!-- U+1680 OGHAM SPACE MARK -->
<iwc-build time />

<!-- U+2000-U+200A (various spaces) -->
<iwc-build time />
<iwc-build time />
<iwc-build time />

<!-- U+2028 LINE SEPARATOR -->
<iwc-build time />

<!-- U+2029 PARAGRAPH SEPARATOR -->
<iwc-build time />

<!-- U+202F NARROW NO-BREAK SPACE -->
<iwc-build time />

<!-- U+205F MEDIUM MATHEMATICAL SPACE -->
<iwc-build time />

<!-- U+3000 IDEOGRAPHIC SPACE -->
<iwc-build　time />
```

## Quote Fuzzing

### All Quote-Like Characters
```html
<iwc-a v="value" />
<iwc-a v='value' />
<iwc-a v‚value‚ />
<iwc-a v„value„ />
<iwc-a v"value" />
<iwc-a v"value" />
<iwc-a v'value' />
<iwc-a v'value' />
<iwc-a v‹value› />
<iwc-a v«value» />
<iwc-a v`value` />
<iwc-a v´value´ />
<iwc-a v'value' />
```

## Dash Fuzzing

### All Dash-Like Characters
```html
<iwc‐buildtime />
<iwc‑buildtime />
<iwc‒buildtime />
<iwc–buildtime />
<iwc—buildtime />
<iwc―buildtime />
<iwc−buildtime />
<iwc－buildtime />
<iwc⸺buildtime />
<iwc⸻buildtime />
```

## Slash Fuzzing

### All Slash-Like Characters
```html
<iwc-buildtime ⁄>
<iwc-buildtime ∕>
<iwc-buildtime ⧸>
<iwc-buildtime ⁄>
<iwc-buildtime ／>
<iwc-buildtime ⧹>
<iwc-buildtime ＼>
```

## Angle Bracket Fuzzing

### All Angle Bracket-Like Characters
```html
‹iwc-buildtime ›
«iwc-buildtime »
⟨iwc-buildtime ⟩
❮iwc-buildtime ❯
˂iwc-buildtime ˃
＜iwc-buildtime ＞
〈iwc-buildtime 〉
《iwc-buildtime 》
```

## Combination Fuzzing

### Random Valid/Invalid Mixes
```html
<iwc-valid /><iwc-invalid
<iwc-broken<iwc-valid />
<iwc-valid /><iwc-!@#$%
<iwc-\x00\x01\x02<iwc-valid />
```

### Repeated Error Patterns
```html
<!-- Repeated unclosed -->
<iwc-a<iwc-a<iwc-a<iwc-a<iwc-a

<!-- Repeated missing quotes -->
<iwc-a v=x /><iwc-a v=x /><iwc-a v=x />

<!-- Repeated invalid chars -->
<iwc-!!! /><iwc-!!! /><iwc-!!! />
```

## Pathological Regex Cases

### ReDoS Patterns
```html
<!-- Catastrophic backtracking -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX />
<iwc-(a+)+(b+)+c />
<iwc-((((((((((a)))))))))) />

<!-- Alternation explosion -->
<iwc-a|a|a|a|a|a|a|a|a|a|a|a|a|a|a|aX />

<!-- Nested quantifiers -->
<iwc-(a*)*b />
<iwc-(a+)*b />
<iwc-(a?)*b />
```

## Hash Collision Patterns

### Names Designed to Collide
```html
<!-- DJB2 hash collisions -->
<iwc-hetairas />
<iwc-mentioner />
<iwc-heliotropes />
<iwc-neurospora />
<iwc-depravement />
<iwc-serafins />
```

## Memory Pressure Patterns

### Repeated Allocations
```html
<!-- Force many allocations -->
<iwc-a /><iwc-b /><iwc-c /><iwc-d /><iwc-e /><iwc-f /><iwc-g /><iwc-h />
... [repeat 10000 times with different names]

<!-- Many attributes forcing hash table growth -->
<iwc-a
  a0="v" a1="v" a2="v" a3="v" a4="v" a5="v" a6="v" a7="v" a8="v" a9="v"
  ... [continue to a999="v"]
/>
```

## File Format Edge Cases

### Archive Format Headers
```html
<!-- ZIP header -->
<iwc-PK\x03\x04 />

<!-- GZIP header -->
<iwc-\x1F\x8B />

<!-- RAR header -->
<iwc-Rar! />

<!-- 7z header -->
<iwc-7z¼¯' />
```

### Image Format Headers
```html
<!-- PNG -->
<iwc-\x89PNG\r\n\x1a\n />

<!-- JPEG -->
<iwc-\xFF\xD8\xFF />

<!-- GIF -->
<iwc-GIF89a />

<!-- BMP -->
<iwc-BM />
```

### Executable Headers
```html
<!-- ELF -->
<iwc-\x7FELF />

<!-- Mach-O -->
<iwc-\xCA\xFE\xBA\xBE />

<!-- PE -->
<iwc-MZ />
```

## Network Protocol Patterns

### HTTP-Like
```html
<iwc-GET / HTTP/1.1 />
<iwc-POST /api HTTP/1.1 />
<iwc-Content-Length: 1000 />
```

### SQL-Like
```html
<iwc-SELECT * FROM users />
<iwc-DROP TABLE users />
<iwc-' OR '1'='1 />
```

### URL-Like
```html
<iwc-http://example.com />
<iwc-https://example.com:8080/path?query=value />
<iwc-ftp://user:pass@host />
```

## Environment Variable Patterns
```html
<iwc-$PATH />
<iwc-$HOME />
<iwc-%PATH% />
<iwc-${VARIABLE} />
<iwc-$(command) />
<iwc-`command` />
```

## Extreme Repetition

### Same Character Repeated
```html
<!-- 1000 a's -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa... />

<!-- 1000 hyphens -->
<iwc--------------------------------------------------------... />

<!-- 1000 slashes -->
<iwc-build///////////////////////////////////////////... />
```

### Pattern Repetition
```html
<!-- Repeated pattern -->
<iwc-abcabcabcabcabcabcabc... [1000 times] />

<!-- Alternating pattern -->
<iwc-ababababababababababab... [1000 times] />

<!-- Progressive pattern -->
<iwc-aabaaabaaaabaaaaa... [expanding] />
```

## Stack Manipulation Attempts

### Deep Call Stack
```html
<!-- Force deep recursion -->
<iwc-a><iwc-a><iwc-a><iwc-a><iwc-a>
... [10000 levels deep]
</iwc-a></iwc-a></iwc-a></iwc-a></iwc-a>

<!-- Alternating types forcing different code paths -->
<iwc-a><iwc-b><iwc-a><iwc-b><iwc-a><iwc-b>
... [5000 alternations]
</iwc-b></iwc-a></iwc-b></iwc-a></iwc-b></iwc-a>
```

## Type Confusion Attempts

### Numeric vs String
```html
<iwc-123abc />
<iwc-0x1234 />
<iwc-0o777 />
<iwc-0b1010 />
<iwc-1e10 />
<iwc-1.234e-5 />
```

### Boolean-like
```html
<iwc-true />
<iwc-false />
<iwc-null />
<iwc-undefined />
<iwc-None />
<iwc-nil />
```
