# Parser Implementation Edge Cases - Invalid Inputs

This file contains parser-breaking edge cases that test the boundaries of the implementation.

## Tokenization Boundary Cases

### Incomplete Token Sequences
```html
<!-- Tag starts but file ends -->
<iwc-buildtime format="iso-8601"

<!-- Tag name starts but incomplete -->
<iwc-bu

<!-- Opening bracket only -->
<

<!-- Closing bracket only -->
>

<!-- Just the prefix -->
<iwc-

<!-- Attribute starts but incomplete -->
<iwc-buildtime for

<!-- Attribute value starts but incomplete -->
<iwc-buildtime format="

<!-- Comment-like start -->
<iwc-<!

<!-- Processing instruction-like start -->
<iwc-<?
```

### Buffer Boundary Issues
```html
<!-- Tag split across potential buffer boundary (4096 bytes) -->
<iwc-buildtime format="[4095 bytes of padding]value" />

<!-- Very long tag name at boundary -->
<iwc-[4090 characters][more characters] />

<!-- Attribute value crossing boundary -->
<iwc-buildtime format="[value split at 4096 bytes boundary]" />
```

### Lookahead/Lookbehind Failures
```html
<!-- Requires unlimited lookahead -->
<iwc-buildtime format="value[thousands of characters]" />

<!-- Multiple potential matches -->
<iwc-buildtime<iwc-buildtime />

<!-- Ambiguous end -->
<iwc-buildtime format="value"<

<!-- Double-starting -->
<<iwc-buildtime />

<!-- False ending -->
<iwc-buildtime />/>
```

## State Machine Edge Cases

### State Transitions
```html
<!-- Unexpected transitions -->
<iwc-buildtime format="value"<iwc-other />

<!-- Stuck in attribute state -->
<iwc-buildtime format=format=format= />

<!-- Tag name state confusion -->
<iwc-<iwc-buildtime />

<!-- Attribute name never ends -->
<iwc-buildtime formatformatformat />

<!-- Quote state never exits -->
<iwc-buildtime format="value"value" />
```

### Recursion and Stack Issues
```html
<!-- Deep nesting (1000+ levels) -->
<iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a>
<iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a>
... [repeat 1000 times]
</iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a>

<!-- Alternating nesting -->
<iwc-a><iwc-b><iwc-a><iwc-b><iwc-a><iwc-b><iwc-a><iwc-b>
... [repeat 500 times]

<!-- Unbalanced deep nesting -->
<iwc-a><iwc-a><iwc-a><iwc-a><iwc-a>
... [1000 opening tags]
</iwc-a>
... [only 1 closing tag]
```

## Memory Exhaustion Attempts

### Large Input Scenarios
```html
<!-- 10MB attribute value -->
<iwc-buildtime format="[10 megabytes of 'a' characters]" />

<!-- 1000 attributes -->
<iwc-buildtime
  a0="v" a1="v" a2="v" a3="v" a4="v" a5="v" a6="v" a7="v" a8="v" a9="v"
  a10="v" a11="v" a12="v" a13="v" a14="v" a15="v" a16="v" a17="v" a18="v" a19="v"
  ... [repeat 1000 times]
/>

<!-- Extremely long tag name (100KB) -->
<iwc-[100,000 characters] />

<!-- Many tags in sequence (10,000+) -->
<iwc-a/><iwc-a/><iwc-a/><iwc-a/><iwc-a/>
... [repeat 10,000 times]
```

### Exponential Expansion
```html
<!-- Quadratic blowup in validation -->
<iwc-a><iwc-a><iwc-a></iwc-a></iwc-a></iwc-a>
<iwc-a><iwc-a><iwc-a><iwc-a></iwc-a></iwc-a></iwc-a></iwc-a>
<iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a>
... [exponentially increasing]

<!-- Cartesian product explosion -->
<iwc-a attr1="v1" attr2="v2" attr3="v3" ... attr20="v20">
  <iwc-a attr1="v1" attr2="v2" attr3="v3" ... attr20="v20">
    <iwc-a attr1="v1" attr2="v2" attr3="v3" ... attr20="v20">
      ... [deeply nested with many attributes each]
```

## Encoding Edge Cases

### Mixed Encodings
```html
<!-- UTF-8 with Latin-1 bytes -->
<iwc-buildtime format="valüe" />

<!-- Invalid UTF-8 sequences in middle -->
<iwc-buildtime format="before\xC0\x80after" />

<!-- Mixed line endings throughout -->
<iwc-buildtime\r\nformat="value"\nattr="val"\r/>

<!-- UTF-16 BOM in UTF-8 stream -->
\xFF\xFE<iwc-buildtime />
```

### Normalization Issues
```html
<!-- Combining characters breaking tag structure -->
<iwc-bui̇̈ldtime />

<!-- Different Unicode representations of same character -->
<iwc-café /> <!-- precomposed -->
<iwc-café /> <!-- decomposed with combining marks -->

<!-- Right-to-left interference -->
<iwc-‮emitdliub />

<!-- Invisible separators -->
<iwc-build\u200Btime />
```

## Regex and Pattern Matching Edge Cases

### Catastrophic Backtracking Patterns
```html
<!-- Pathological regex inputs -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab />

<!-- Nested quantifiers -->
<iwc-((((((((((a))))))))))/>

<!-- Alternation explosion -->
<iwc-a|b|c|d|e|f|g|h|i|j|k|l|m|n|o />

<!-- Backreference hell -->
<iwc-buildtime format="(a+)+(b+)+c" />
```

### Greedy vs Non-Greedy Issues
```html
<!-- Multiple closing sequences -->
<iwc-buildtime>Content</iwc-buildtime>Extra</iwc-buildtime>

<!-- Attributes with tag-like content -->
<iwc-buildtime format="</iwc-buildtime>" value="<iwc-other />" />

<!-- Nested quotes -->
<iwc-buildtime format="outer "inner" outer" />
```

## Comment and Special Section Handling

### Malformed Comments
```html
<!-- Comment with shortcode and wrong closing -->
<!-- <iwc-buildtime /> --->

<!-- Comment with double-dash inside -->
<!-- <iwc-buildtime -- breaks -- here /> -->

<!-- Comment that looks like CDATA -->
<!--[CDATA[<iwc-buildtime />]]-->

<!-- Nested comment-like structures -->
<!-- outer <!-- inner <iwc-buildtime /> --> -->

<!-- Comment with processing instruction -->
<!-- <?php <iwc-buildtime /> ?> -->

<!-- Comment with invalid syntax -->
<!--- <iwc-buildtime /> --->
<!---- <iwc-buildtime /> ---->
```

### CDATA Sections
```html
<!-- CDATA with shortcode but broken closing -->
<![CDATA[<iwc-buildtime />]>

<!-- CDATA with double closing -->
<![CDATA[<iwc-buildtime />]]]]>

<!-- Nested CDATA -->
<![CDATA[<![CDATA[<iwc-buildtime />]]>]]>

<!-- CDATA-like but invalid -->
<![CDATA<iwc-buildtime />]]>
<[CDATA[<iwc-buildtime />]]>

<!-- CDATA with processing instruction -->
<![CDATA[<?php <iwc-buildtime /> ?>]]>
```

### Processing Instructions
```html
<!-- PI with shortcode -->
<?php <iwc-buildtime /> ?>

<!-- Broken PI -->
<?php <iwc-buildtime />

<!-- Nested PI-like -->
<?outer <?inner <iwc-buildtime /> ?> ?>

<!-- PI without closing -->
<?xml version="1.0" <iwc-buildtime />
```

## DOCTYPE and XML Declaration Edge Cases

### DOCTYPE Interference
```html
<!-- DOCTYPE with shortcode -->
<!DOCTYPE html <iwc-buildtime />>

<!-- Shortcode in DOCTYPE -->
<!DOCTYPE html PUBLIC "<iwc-buildtime />">

<!-- Malformed DOCTYPE with shortcode -->
<!DOCTYPE <iwc-buildtime />

<!-- DTD with entity and shortcode -->
<!DOCTYPE html [
  <!ENTITY test "<iwc-buildtime />">
]>
<root>&test;</root>
```

### XML Declaration
```html
<!-- XML declaration with shortcode -->
<?xml version="1.0" encoding="<iwc-buildtime />" ?>

<!-- Broken XML declaration -->
<?xml version="1.0" <iwc-buildtime />

<!-- Multiple XML declarations -->
<?xml version="1.0"?>
<?xml version="1.0"?>
<iwc-buildtime />
```

## Attribute Parsing Edge Cases

### Ambiguous Attribute Boundaries
```html
<!-- No space between attributes -->
<iwc-buildtime format="value"other="value2"/>

<!-- Attribute name merging with tag name -->
<iwc-buildtimeformat="value" />

<!-- Equals sign variations -->
<iwc-buildtime format ="value" />
<iwc-buildtime format= "value" />
<iwc-buildtime format = "value" />

<!-- Multiple equals signs -->
<iwc-buildtime format==="value" />

<!-- Attribute name with dash at end -->
<iwc-buildtime format-="value" />
```

### Quote Confusion in Attributes
```html
<!-- Three quotes in a row -->
<iwc-buildtime format="""value""" />

<!-- Backtick instead of quote -->
<iwc-buildtime format=`value` />

<!-- Smart quotes -->
<iwc-buildtime format="value" />
<iwc-buildtime format='value' />

<!-- Mixed straight and curly quotes -->
<iwc-buildtime format="value" />

<!-- No quotes at all with special chars -->
<iwc-buildtime format=val<ue />
<iwc-buildtime format=val>ue />
<iwc-buildtime format=val/ue />
```

### Attribute Value Edge Cases
```html
<!-- Empty attribute name with value -->
<iwc-buildtime ="value" />

<!-- Just equals and quotes -->
<iwc-buildtime ="" />

<!-- Attribute with slash -->
<iwc-buildtime format/="value" />

<!-- Attribute with brackets -->
<iwc-buildtime [format]="value" />
<iwc-buildtime (format)="value" />
<iwc-buildtime {format}="value" />

<!-- Data attributes (HTML5) -->
<iwc-buildtime data-format="value" />

<!-- ARIA attributes -->
<iwc-buildtime aria-label="value" />
```

## Tag Name Parsing Edge Cases

### Unicode in Tag Names
```html
<!-- Non-ASCII letters -->
<iwc-bûildtïme />
<iwc-построить />
<iwc-建造时间 />
<iwc-بناء />

<!-- Emoji -->
<iwc-⏰ />
<iwc-🏗️ />

<!-- Mathematical symbols -->
<iwc-∞ />
<iwc-∑ />

<!-- Box drawing characters -->
<iwc-╔═══╗ />
```

### Special ASCII Characters
```html
<!-- Underscore variations -->
<iwc-build_time />
<iwc-_buildtime />
<iwc-buildtime_ />

<!-- Period in name -->
<iwc-build.time />

<!-- Colon in name -->
<iwc-build:time />

<!-- Semicolon in name -->
<iwc-build;time />

<!-- Dollar sign -->
<iwc-$buildtime />

<!-- At sign -->
<iwc-@buildtime />
```

## Self-Closing Tag Edge Cases

### Slash Position Variations
```html
<!-- Slash at beginning -->
</iwc-buildtime>

<!-- Multiple slashes -->
<iwc-buildtime ////>
<iwc-buildtime //>

<!-- Slash in wrong position -->
<iwc-buildtime / format="value">

<!-- Slash without space before -->
<iwc-buildtime format="value"/>

<!-- Slash with lots of space -->
<iwc-buildtime format="value"     /     >

<!-- Slash on separate line -->
<iwc-buildtime format="value"
/
>
```

## Closing Tag Edge Cases

### Wrong Closing Syntax
```html
<!-- Self-closing syntax on closing tag -->
</iwc-buildtime />

<!-- Attributes on closing tag -->
</iwc-buildtime format="value">

<!-- Space before tag name in closing -->
</ iwc-buildtime>

<!-- No space after slash -->
</iwc-buildtime

<!-- Multiple slashes -->
<//iwc-buildtime>
<///iwc-buildtime>

<!-- Slash at end -->
</iwc-buildtime/>
```

## HTML5 Specific Edge Cases

### Custom Element Confusion
```html
<!-- Looks like custom element -->
<iwc-buildtime is="time" />

<!-- Autonomous custom element syntax -->
<iwc-buildtime:extended />

<!-- Shadow DOM related -->
<iwc-buildtime slot="content" />

<!-- Template related -->
<iwc-template>
  <iwc-buildtime />
</iwc-template>
```

### HTML5 Void Elements Confusion
```html
<!-- Trying to close void elements -->
<iwc-br></iwc-br>
<iwc-img></iwc-img>
<iwc-input></iwc-input>

<!-- Void element with content -->
<iwc-br>Content</iwc-br>
```

## Whitespace Variations

### Different Whitespace Characters
```html
<!-- No-break space -->
<iwc-buildtime format=" value" />

<!-- Em space -->
<iwc-buildtime format=" value" />

<!-- Figure space -->
<iwc-buildtime format=" value" />

<!-- Zero-width space -->
<iwc-buildtime​format="value" />

<!-- Tab characters -->
<iwc-buildtime	format="value"	/>

<!-- Vertical tab -->
<iwc-buildtime format="value" />

<!-- Form feed -->
<iwc-buildtime format="value" />
```

### Mixed Line Endings
```html
<!-- CR only -->
<iwc-buildtime
format="value"
/>

<!-- LF only -->
<iwc-buildtime
format="value"
/>

<!-- CRLF -->
<iwc-buildtime
format="value"
/>

<!-- Mixed in same tag -->
<iwc-buildtime
format="value"
attr="val"
/>
```

## Stress Test Patterns

### Repeated Pattern Attacks
```html
<!-- Same tag 10,000 times -->
<iwc-a/><iwc-a/><iwc-a/><iwc-a/><iwc-a/><iwc-a/><iwc-a/><iwc-a/>
... [repeat 10,000 times]

<!-- Alternating valid/invalid -->
<iwc-valid/><iwc-invalid<iwc-valid/><iwc-invalid
... [repeat 5,000 times]

<!-- Opening without closing, repeated -->
<iwc-a><iwc-a><iwc-a><iwc-a><iwc-a>
... [10,000 times without any closing tags]
```

### Hash Collision Attempts
```html
<!-- Names designed to collide in hash tables -->
<iwc-aaaaaaaaaaaaaaaaab />
<iwc-aaaaaaaaaaaaaaaaac />
<iwc-aaaaaaaaaaaaaaaaad />
... [1000 similar names]

<!-- Attributes designed to collide -->
<iwc-buildtime
  attr0000000000001="v"
  attr0000000000002="v"
  attr0000000000003="v"
  ... [1000 similar attributes]
/>
```

## Error Recovery Scenarios

### Sequential Errors
```html
<!-- Multiple broken tags in sequence -->
<iwc-broken
<iwc-also-broken
<iwc-still-broken
<iwc-more-broken

<!-- Error, valid, error pattern -->
<iwc-broken
<iwc-valid />
<iwc-broken-again
<iwc-valid-again />
```

### Partial Recovery Attempts
```html
<!-- Almost-valid after error -->
<iwc-broken attribute
<iwc-buildtime format="value" />

<!-- Error in middle of valid stream -->
<iwc-a /><iwc-b /><iwc-broken<iwc-c /><iwc-d />

<!-- Progressive errors -->
<iwc-tag1 />
<iwc-tag2>
<iwc-tag3
<iwc-tag4
<iwc
<iw
<i
<
```

## Platform and Language Specific Issues

### Filesystem Path Injection Attempts
```html
<!-- Absolute paths -->
<iwc-include file="/etc/passwd" />
<iwc-include file="C:\Windows\System32\config\SAM" />

<!-- Relative path traversal -->
<iwc-include file="../../../../../../etc/passwd" />

<!-- UNC paths -->
<iwc-include file="\\server\share\file" />

<!-- URL-like paths -->
<iwc-include file="file:///etc/passwd" />
```

### SQL Injection Patterns
```html
<!-- Classic SQL injection -->
<iwc-query sql="' OR '1'='1" />
<iwc-query sql="'; DROP TABLE users; --" />

<!-- Union-based -->
<iwc-query sql="' UNION SELECT * FROM users --" />

<!-- Stacked queries -->
<iwc-query sql="'; DELETE FROM users WHERE '1'='1" />
```

### Command Injection Patterns
```html
<!-- Shell metacharacters -->
<iwc-exec cmd="test; rm -rf /" />
<iwc-exec cmd="test | cat /etc/passwd" />
<iwc-exec cmd="test && malicious" />
<iwc-exec cmd="test `whoami`" />
<iwc-exec cmd="test $(whoami)" />

<!-- Null byte injection -->
<iwc-exec cmd="test\x00; malicious" />
```

### Template Injection Patterns
```html
<!-- Server-side template injection -->
<iwc-render tpl="{{7*7}}" />
<iwc-render tpl="${{7*7}}" />
<iwc-render tpl="<%= 7*7 %>" />
<iwc-render tpl="{7*7}" />

<!-- Expression language injection -->
<iwc-render tpl="${T(java.lang.Runtime).getRuntime().exec('calc')}" />
```

## Parser Bomb Patterns

### Zip Bomb Equivalent
```html
<!-- Highly compressible, expands massively -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
     ... [repeated pattern that compresses to tiny size]
/>
```

### Billion Laughs Attack
```html
<!-- Exponential entity expansion equivalent -->
<iwc-lol0>lol</iwc-lol0>
<iwc-lol1><iwc-lol0></iwc-lol0><iwc-lol0></iwc-lol0></iwc-lol1>
<iwc-lol2><iwc-lol1></iwc-lol1><iwc-lol1></iwc-lol1></iwc-lol2>
<iwc-lol3><iwc-lol2></iwc-lol2><iwc-lol2></iwc-lol2></iwc-lol3>
... [exponential expansion]
```

## Lookalike Character Attacks

### Homoglyph Confusion
```html
<!-- Cyrillic 'a' instead of Latin 'a' -->
<iwc-buildtime /> <!-- 'а' is Cyrillic -->

<!-- Greek question mark (looks like semicolon) -->
<iwc-buildtime format="value"; />

<!-- Hebrew/Arabic lookalikes -->
<iwc-bսildtime /> <!-- contains Armenian 's' -->
```

## Truncation and Length Limits

### Boundary Length Testing
```html
<!-- Exactly at typical buffer size -->
<iwc-[4095 characters]/>

<!-- One over buffer size -->
<iwc-[4097 characters]/>

<!-- At max identifier length (common: 255) -->
<iwc-[254 characters]/>
<iwc-[255 characters]/>
<iwc-[256 characters]/>

<!-- At max tag length if different from identifier -->
<iwc-buildtime format="[8190 characters]" />
<iwc-buildtime format="[8191 characters]" />
<iwc-buildtime format="[8192 characters]" />
```
