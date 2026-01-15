# Invalid Shortcode Input Test Cases

This document contains comprehensive examples of INVALID shortcode inputs that should be rejected by the parser.

## Category 1: Malformed Tag Structure

### Unclosed Tags
```html
<!-- Missing closing tag -->
<iwc-buildtime format="iso-8601">

<!-- Self-closing but with content -->
<iwc-quotefig cite="example.com" />This shouldn't be here</iwc-quotefig>

<!-- Opening tag but no closing -->
<iwc-button>Click me

<!-- Multiple opening tags, single closing -->
<iwc-container><iwc-container>Content</iwc-container>

<!-- Closing tag without opening -->
</iwc-buildtime>

<!-- Closing tag appears before opening -->
</iwc-box><iwc-box>

<!-- Unclosed with attributes -->
<iwc-image src="test.jpg" alt="description"
```

### Mismatched Opening/Closing Tags
```html
<!-- Different tag names -->
<iwc-buildtime>2025-01-15</iwc-button>

<!-- Case mismatch -->
<iwc-buildtime>2025-01-15</IWC-BUILDTIME>

<!-- Extra characters in closing -->
<iwc-box>Content</iwc-box1>

<!-- Missing hyphen in closing -->
<iwc-buildtime>2025-01-15</iwcbuildtime>

<!-- Typo in closing tag -->
<iwc-quotefig>Quote</iwc-quotfig>

<!-- Space in closing tag -->
<iwc-buildtime>2025-01-15</iwc- buildtime>

<!-- Reversed tag name parts -->
<iwc-buildtime>2025-01-15</buildtime-iwc>
```

### Invalid Self-Closing Syntax
```html
<!-- Missing closing bracket -->
<iwc-buildtime format="iso-8601" /

<!-- Double slash -->
<iwc-buildtime format="iso-8601" //

<!-- Slash before attributes -->
<iwc-buildtime / format="iso-8601">

<!-- Slash in middle of tag -->
<iwc-build/time format="iso-8601" />

<!-- Multiple slashes -->
<iwc-buildtime format="iso-8601" ////>

<!-- Space before slash -->
<iwc-buildtime format="iso-8601" / >

<!-- No slash but looks self-closing -->
<iwc-buildtime format="iso-8601" >

<!-- Slash without closing bracket -->
<iwc-buildtime format="iso-8601" /
```

### Mixed Self-Closing and Regular Closing
```html
<!-- Self-closing with content -->
<iwc-container />Content here</iwc-container>

<!-- Self-closing with only closing tag -->
<iwc-buildtime />Some content</iwc-buildtime>

<!-- Both self-closing and closing tag -->
<iwc-box /></iwc-box>
```

## Category 2: Invalid Tag Names

### Missing or Wrong Prefix
```html
<!-- No prefix -->
<buildtime format="iso-8601" />

<!-- Wrong prefix -->
<iwc_buildtime format="iso-8601" />
<IWC-buildtime format="iso-8601" />
<iwc.buildtime format="iso-8601" />
<web-buildtime format="iso-8601" />
<wc-buildtime format="iso-8601" />
<custom-buildtime format="iso-8601" />

<!-- Partial prefix -->
<iw-buildtime format="iso-8601" />
<ic-buildtime format="iso-8601" />
<wc-buildtime format="iso-8601" />

<!-- Space in prefix -->
<i wc-buildtime format="iso-8601" />
<iwc -buildtime format="iso-8601" />

<!-- Double prefix -->
<iwc-iwc-buildtime format="iso-8601" />
```

### Empty or Invalid Tag Name
```html
<!-- Empty tag name (just prefix) -->
<iwc- format="iso-8601" />
<iwc->Content</iwc->

<!-- Missing tag name after prefix -->
<iwc- />

<!-- Only whitespace after prefix -->
<iwc-   />
<iwc-	>Content</iwc-	>

<!-- Just hyphen -->
<iwc-->Content</iwc-->

<!-- Double hyphen -->
<iwc--buildtime />
<iwc-build--time />
```

### Invalid Characters in Tag Name
```html
<!-- Special characters -->
<iwc-build$time />
<iwc-build@time />
<iwc-build#time />
<iwc-build%time />
<iwc-build&time />
<iwc-build*time />
<iwc-build(time) />
<iwc-build+time />
<iwc-build=time />
<iwc-build[time] />
<iwc-build{time} />
<iwc-build|time />
<iwc-build\time />
<iwc-build:time />
<iwc-build;time />
<iwc-build"time" />
<iwc-build'time' />
<iwc-build<time />
<iwc-build>time />
<iwc-build,time />
<iwc-build.time />
<iwc-build?time />
<iwc-build/time />
<iwc-build~time />
<iwc-build`time />
<iwc-build!time />

<!-- Spaces in tag name -->
<iwc-build time format="iso-8601" />
<iwc- buildtime format="iso-8601" />
<iwc-buildtime  format="iso-8601" />

<!-- Newline in tag name -->
<iwc-build
time />

<!-- Tab in tag name -->
<iwc-build	time />

<!-- Unicode special characters -->
<iwc-build™time />
<iwc-build©time />
<iwc-build®time />
<iwc-build€time />
<iwc-build£time />
```

### Tag Names with Only Numbers or Starting with Numbers
```html
<!-- Only numbers -->
<iwc-123 />
<iwc-456>Content</iwc-456>

<!-- Starting with numbers -->
<iwc-1buildtime />
<iwc-99problems />

<!-- Numbers and special chars -->
<iwc-123-456 />
```

### Reserved or Problematic Names
```html
<!-- Looks like HTML comments -->
<iwc--- />
<iwc-!-- />

<!-- Looks like processing instructions -->
<iwc-? />
<iwc-?xml />

<!-- DOCTYPE-like -->
<iwc-!doctype />

<!-- CDATA-like -->
<iwc-![CDATA[ />
```

### Very Long Tag Names
```html
<!-- Excessively long -->
<iwc-thisisaverylongtagnamethatgoesonnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnandonandonandon />

<!-- 1000+ characters -->
<iwc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa />
```

## Category 3: Invalid Attributes

### Malformed Attribute Syntax
```html
<!-- No equals sign -->
<iwc-buildtime format />
<iwc-buildtime format "iso-8601" />

<!-- Multiple equals signs -->
<iwc-buildtime format=="iso-8601" />
<iwc-buildtime format==="iso-8601" />

<!-- Equals without value -->
<iwc-buildtime format= />
<iwc-buildtime format=/>

<!-- Equals without name -->
<iwc-buildtime ="iso-8601" />

<!-- Special characters in attribute name -->
<iwc-buildtime for@mat="iso-8601" />
<iwc-buildtime for$mat="iso-8601" />
<iwc-buildtime for mat="iso-8601" />
<iwc-buildtime for-mat*="iso-8601" />
```

### Unclosed or Mismatched Quotes
```html
<!-- Unclosed double quotes -->
<iwc-buildtime format="iso-8601 />

<!-- Unclosed single quotes -->
<iwc-buildtime format='iso-8601 />

<!-- Mixed quotes -->
<iwc-buildtime format="iso-8601' />
<iwc-buildtime format='iso-8601" />

<!-- Nested quotes without escaping -->
<iwc-buildtime format="iso-"8601"" />
<iwc-buildtime format='iso-'8601'' />

<!-- No opening quote -->
<iwc-buildtime format=iso-8601" />
<iwc-buildtime format=iso-8601' />

<!-- Multiple opening quotes -->
<iwc-buildtime format=""iso-8601" />
<iwc-buildtime format="'iso-8601" />
```

### Invalid Attribute Names
```html
<!-- Empty attribute name -->
<iwc-buildtime ="" />

<!-- Whitespace as attribute name -->
<iwc-buildtime  ="value" />

<!-- Special characters at start -->
<iwc-buildtime @format="iso-8601" />
<iwc-buildtime $format="iso-8601" />
<iwc-buildtime #format="iso-8601" />
<iwc-buildtime *format="iso-8601" />
<iwc-buildtime (format)="iso-8601" />

<!-- Numbers only -->
<iwc-buildtime 123="value" />

<!-- Starting with number -->
<iwc-buildtime 1format="iso-8601" />

<!-- Brackets in attribute name -->
<iwc-buildtime [format]="iso-8601" />
<iwc-buildtime {format}="iso-8601" />

<!-- Control characters -->
<iwc-buildtime format\n="iso-8601" />
<iwc-buildtime format\t="iso-8601" />
```

### Duplicate Attributes
```html
<!-- Same attribute twice -->
<iwc-buildtime format="iso-8601" format="rfc-3339" />

<!-- Case variations -->
<iwc-buildtime format="iso-8601" Format="rfc-3339" />
<iwc-buildtime format="iso-8601" FORMAT="rfc-3339" />

<!-- Multiple duplicates -->
<iwc-buildtime format="a" format="b" format="c" />
```

### Attributes Without Values (when required)
```html
<!-- Boolean-style attributes where values required -->
<iwc-buildtime format />
<iwc-image src />
<iwc-link href />
<iwc-quotefig cite />
```

### Invalid Attribute Values
```html
<!-- Newlines in values -->
<iwc-buildtime format="iso
8601" />

<!-- Control characters -->
<iwc-buildtime format="iso-8601\0" />
<iwc-buildtime format="\x00\x01\x02" />

<!-- Unescaped special HTML chars in unquoted values -->
<iwc-buildtime format=iso<8601 />
<iwc-buildtime format=iso>8601 />
<iwc-buildtime format=iso&8601 />
```

## Category 4: Invalid Nesting and Structure

### Improperly Nested Same Shortcodes
```html
<!-- Same tag nested without closing first -->
<iwc-container>
  <iwc-container>
</iwc-container>
Content here
</iwc-container>

<!-- Crossed nesting -->
<iwc-box>
  <iwc-container>
</iwc-box>
  </iwc-container>
```

### Invalid Content Inside Shortcodes
```html
<!-- Unclosed HTML inside -->
<iwc-quotefig cite="example.com">
  <p>This paragraph is not closed
</iwc-quotefig>

<!-- Mismatched HTML inside -->
<iwc-container>
  <div>Content</span>
</iwc-container>

<!-- Invalid HTML entities inside -->
<iwc-quotefig>
  Quote with &invalidEntity;
</iwc-quotefig>
```

### Deep/Complex Invalid Nesting
```html
<!-- Crossing boundaries -->
<iwc-outer>
  <iwc-inner>
    Content
  </iwc-outer>
</iwc-inner>

<!-- Multiple cross-nested -->
<iwc-a>
  <iwc-b>
    <iwc-c>
    </iwc-b>
  </iwc-c>
</iwc-a>

<!-- Self-referential nesting issues -->
<iwc-box>
  <iwc-box>
    <iwc-box>
</iwc-box>
```

## Category 5: Whitespace and Formatting Issues

### Invalid Whitespace in Critical Locations
```html
<!-- Whitespace before closing bracket -->
<iwc-buildtime >

<!-- Whitespace in closing tag before slash -->
<iwc-buildtime / >

<!-- Whitespace after opening bracket -->
< iwc-buildtime />

<!-- Whitespace after closing bracket slash -->
</ iwc-buildtime>

<!-- Excessive whitespace everywhere -->
<  iwc-buildtime   format  =  "iso-8601"  / >

<!-- Newlines in wrong places -->
<iwc-buildtime
format
=
"iso-8601"
/>

<!-- Tabs and mixed whitespace -->
<iwc-buildtime	format="iso-8601"	/>
```

### Line Breaks in Tag Structure
```html
<!-- Line break in tag name -->
<iwc-build
time />

<!-- Line break before closing -->
<iwc-buildtime format="iso-8601"
/>

<!-- Line break in closing tag -->
</iwc-
buildtime>

<!-- Multiple line breaks -->
<iwc-buildtime


format="iso-8601"


/>
```

## Category 6: Escaping and Context Issues

### Broken Escape Sequences
```html
<!-- Incomplete HTML entity -->
<iwc-buildtime format="iso&" />
<iwc-buildtime format="&8601" />
<iwc-buildtime format="&#" />
<iwc-buildtime format="&#x" />

<!-- Invalid numeric entity -->
<iwc-buildtime format="&#999999999;" />
<iwc-buildtime format="&#xGGGG;" />

<!-- Partially escaped shortcode -->
&lt;iwc-buildtime />
<iwc-buildtime &gt;
&lt;iwc-buildtime>Content</iwc-buildtime>
```

### Invalid iwc-raw Usage
```html
<!-- Unclosed iwc-raw -->
<iwc-raw><iwc-buildtime />

<!-- Mismatched iwc-raw -->
<iwc-raw><iwc-buildtime /></iwc-raw-different>

<!-- Nested iwc-raw -->
<iwc-raw>
  <iwc-raw>
    <iwc-buildtime />
  </iwc-raw>
</iwc-raw>

<!-- Self-closing iwc-raw with content -->
<iwc-raw /><iwc-buildtime />

<!-- Empty iwc-raw -->
<iwc-raw></iwc-raw>
```

## Category 7: Special Characters and Encoding

### NULL Bytes and Control Characters
```html
<!-- NULL byte in tag name -->
<iwc-build\x00time />

<!-- Control characters -->
<iwc-buildtime\x01\x02\x03 />

<!-- Vertical tab, form feed -->
<iwc-buildtime\x0B\x0C />

<!-- BOM characters -->
\xEF\xBB\xBF<iwc-buildtime />
```

### Invalid UTF-8 Sequences
```html
<!-- Broken UTF-8 -->
<iwc-buildtime format="\xC0\xC0" />

<!-- Overlong encodings -->
<iwc-buildtime format="\xC0\x80" />

<!-- Invalid continuation bytes -->
<iwc-buildtime format="\x80\x80" />
```

### Unicode Edge Cases
```html
<!-- Right-to-left override -->
<iwc-buildtime format="‮8601-osi" />

<!-- Zero-width characters -->
<iwc-​buildtime />
<iwc-buildtime​ />

<!-- Combining characters in tag name -->
<iwc-bùildtīme />

<!-- Emoji in tag names -->
<iwc-🕐buildtime />
<iwc-⏰ />

<!-- Surrogate pairs -->
<iwc-\uD800\uDC00buildtime />
```

## Category 8: Edge Cases and Boundary Conditions

### Empty or Whitespace-Only
```html
<!-- Empty tags -->
<iwc-></iwc->

<!-- Only whitespace in tag name -->
<iwc- > </iwc- >

<!-- Empty attributes -->
<iwc-buildtime ="" />
<iwc-buildtime ''='' />

<!-- Whitespace-only content -->
<iwc-container>   </iwc-container>
<iwc-container>

</iwc-container>
```

### Very Large Content
```html
<!-- Extremely large attribute value (10KB+) -->
<iwc-buildtime format="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa... [continues for 10000+ characters]" />

<!-- Huge content block -->
<iwc-quotefig>
Lorem ipsum... [50000+ characters of content]
</iwc-quotefig>

<!-- Thousands of attributes -->
<iwc-buildtime a1="v" a2="v" a3="v" ... a9999="v" />
```

### Ambiguous or Tricky Patterns
```html
<!-- Looks like comment but isn't -->
<iwc-!--buildtime -->

<!-- Looks like CDATA -->
<iwc-![CDATA[buildtime]]>

<!-- Looks like processing instruction -->
<iwc-?xml version="1.0" ?>

<!-- Multiple angle brackets -->
<iwc-buildtime format="<>" />
<<iwc-buildtime>>

<!-- Looks like HTML5 custom element -->
<iwc-buildtime is="button" />

<!-- Namespace-like syntax -->
<iwc:buildtime xmlns:iwc="example" />
```

## Category 9: Comment and CDATA Confusion

### Malformed Comments with Shortcodes
```html
<!-- Not actually a comment
<iwc-buildtime />

<!-- Unclosed comment
<iwc-buildtime /> -->

<!--- Extra dash
<iwc-buildtime />
--->

<!-- Multiple starts
<!-- <iwc-buildtime /> -->
<!-- <iwc-buildtime /> -->
```

### CDATA Confusion
```html
<!-- Malformed CDATA -->
<![CDATA[
<iwc-buildtime />

<!-- CDATA without closing -->
<![CDATA[<iwc-buildtime />]

<!-- Double CDATA markers -->
<![CDATA[<![CDATA[<iwc-buildtime />]]]]>

<!-- CDATA in wrong context -->
<iwc-container>
<![CDATA[Content]]>
</iwc-container>
```

## Category 10: Combined and Complex Errors

### Multiple Errors at Once
```html
<!-- Missing closing + invalid attribute -->
<iwc-buildtime format="iso-8601 broken

<!-- Wrong prefix + unclosed quotes + invalid chars -->
<web-build$time format="value />

<!-- Nested errors -->
<iwc-outer missing="quote>
  <iwc-inner extra space>
    <iwc-deep/wrong/>
  </iwc-inner
</iwc-outer>

<!-- Everything wrong -->
< iwc_build@time format==iso-8601 extra / >>Content</iwc-wrongname
```

### Pathological Cases
```html
<!-- Binary data in shortcode -->
<iwc-buildtime format="\x89PNG\r\n\x1a\n" />

<!-- SQL injection attempt -->
<iwc-query sql="'; DROP TABLE users; --" />

<!-- XSS attempt -->
<iwc-content value="<script>alert('xss')</script>" />

<!-- Path traversal -->
<iwc-include file="../../../etc/passwd" />

<!-- Command injection -->
<iwc-exec command="rm -rf /" />

<!-- Template injection -->
<iwc-render template="${{7*7}}" />

<!-- Billion laughs variant -->
<iwc-a>
<iwc-b><iwc-b></iwc-b></iwc-b>
<iwc-c><iwc-b></iwc-b><iwc-b></iwc-b></iwc-c>
<iwc-d><iwc-c></iwc-c><iwc-c></iwc-c></iwc-d>
... [exponential expansion]
</iwc-a>
```

## Category 11: Parser State Confusion

### Ambiguous Boundaries
```html
<!-- Tag inside attribute value -->
<iwc-container class="<iwc-buildtime />" />

<!-- Closing tag in attribute -->
<iwc-buildtime format="</iwc-buildtime>" />

<!-- Shortcode delimiter confusion -->
<iwc-buildtime format="<iwc-" />

<!-- Quote confusion -->
<iwc-buildtime format='Say "hello"' message="Say 'goodbye'" broken="mix'match" />
```

### State Machine Breaking Sequences
```html
<!-- Rapid open/close -->
<iwc-a></iwc-a><iwc-b></iwc-b><iwc-c>

<!-- Alternating valid/invalid -->
<iwc-valid /><iwc-invalid <iwc-valid />

<!-- Cascading failures -->
<iwc-outer>
  <iwc-middle
    <iwc-inner>
  </iwc-middle>
</iwc-outer>
```

## Category 12: Specific Shortcode Validation Failures

### iwc-buildtime Invalid Inputs
```html
<!-- Invalid format values -->
<iwc-buildtime format="invalid-format-name" />
<iwc-buildtime format="" />
<iwc-buildtime format="123" />
<iwc-buildtime format="format with spaces" />

<!-- Missing required format -->
<iwc-buildtime />

<!-- Invalid timezone -->
<iwc-buildtime format="iso-8601" timezone="Invalid/Zone" />
<iwc-buildtime format="iso-8601" timezone="UTC+99:99" />

<!-- Content where there shouldn't be -->
<iwc-buildtime format="iso-8601">Unexpected content</iwc-buildtime>

<!-- Invalid combinations -->
<iwc-buildtime format="iso-8601" format="rfc-3339" />
```

### iwc-quotefig Invalid Inputs
```html
<!-- Missing required cite -->
<iwc-quotefig>Quote without citation</iwc-quotefig>

<!-- Invalid URL in cite -->
<iwc-quotefig cite="not a url">Quote</iwc-quotefig>
<iwc-quotefig cite="javascript:alert(1)">Quote</iwc-quotefig>
<iwc-quotefig cite="<script>">Quote</iwc-quotefig>

<!-- Empty cite -->
<iwc-quotefig cite="">Quote</iwc-quotefig>

<!-- Empty content -->
<iwc-quotefig cite="https://example.com"></iwc-quotefig>

<!-- Caption without cite -->
<iwc-quotefig caption="Author Name">Quote</iwc-quotefig>

<!-- Invalid HTML in caption -->
<iwc-quotefig cite="https://example.com" caption="<unclosed>">Quote</iwc-quotefig>

<!-- Nested quotefigs -->
<iwc-quotefig cite="https://example.com">
  <iwc-quotefig cite="https://example.com">
    Nested quote
  </iwc-quotefig>
</iwc-quotefig>
```

### iwc-image Invalid Inputs (hypothetical)
```html
<!-- Missing required src -->
<iwc-image alt="Description" />

<!-- Invalid src -->
<iwc-image src="" />
<iwc-image src="javascript:alert(1)" />
<iwc-image src="<script>" />

<!-- Invalid dimension values -->
<iwc-image src="test.jpg" width="abc" />
<iwc-image src="test.jpg" height="-100" />
<iwc-image src="test.jpg" width="0" />

<!-- Content inside self-closing element -->
<iwc-image src="test.jpg" />Extra content
```

### iwc-link Invalid Inputs (hypothetical)
```html
<!-- Missing required href -->
<iwc-link>Click here</iwc-link>

<!-- Empty href -->
<iwc-link href="">Click here</iwc-link>

<!-- Invalid protocols -->
<iwc-link href="javascript:alert(1)">Click</iwc-link>
<iwc-link href="data:text/html,<script>alert(1)</script>">Click</iwc-link>
<iwc-link href="vbscript:msgbox">Click</iwc-link>

<!-- Malformed URLs -->
<iwc-link href="ht!tp://example.com">Click</iwc-link>
<iwc-link href="http://exam ple.com">Click</iwc-link>

<!-- Empty content -->
<iwc-link href="https://example.com"></iwc-link>
```

### iwc-raw Invalid Inputs
```html
<!-- Self-closing raw -->
<iwc-raw />

<!-- Empty raw -->
<iwc-raw></iwc-raw>

<!-- Unclosed raw -->
<iwc-raw><iwc-something />

<!-- Nested raw -->
<iwc-raw>
  <iwc-raw>Content</iwc-raw>
</iwc-raw>

<!-- Raw with attributes -->
<iwc-raw format="html"><iwc-something /></iwc-raw>
```

## Category 13: Injection and Security Test Cases

### Attempting to Break Parser with Special Sequences
```html
<!-- HTML comment injection -->
<iwc-buildtime format="iso<!--injection-->8601" />

<!-- Processing instruction injection -->
<iwc-buildtime format="iso<?php echo 'hi' ?>8601" />

<!-- CDATA injection -->
<iwc-buildtime format="iso<![CDATA[injection]]>8601" />

<!-- Entity expansion -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<iwc-buildtime format="&xxe;" />

<!-- Character reference overflow -->
<iwc-buildtime format="&#xFFFFFFFF;" />

<!-- UTF-7 XSS attempt -->
<iwc-buildtime format="+ADw-script+AD4-alert(1)+ADw-/script+AD4-" />
```

### DoS Attempts
```html
<!-- Regex DoS patterns -->
<iwc-buildtime format="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac" />

<!-- Quadratic blowup -->
<iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a><iwc-a>
... [deeply nested]
</iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a></iwc-a>

<!-- Memory exhaustion via huge attributes -->
<iwc-buildtime a="[1MB of 'a' characters]" />

<!-- Stack overflow via deep nesting -->
<iwc-a><iwc-a><iwc-a>...[1000 levels deep]...</iwc-a></iwc-a></iwc-a>
```

## Category 14: Encoding and Character Set Issues

### Invalid XML/HTML Character References
```html
<!-- Non-existent entities -->
<iwc-buildtime format="&doesnotexist;" />

<!-- Incomplete entities -->
<iwc-buildtime format="&lt" />
<iwc-buildtime format="&#" />

<!-- Invalid hex entities -->
<iwc-buildtime format="&#xZZZZ;" />

<!-- Out of range -->
<iwc-buildtime format="&#x110000;" />

<!-- Reserved ranges -->
<iwc-buildtime format="&#xD800;" />
```

### BOM and Zero-Width Characters
```html
<!-- BOM in middle of tag -->
<iwc-﻿buildtime />

<!-- Zero-width spaces -->
<iwc-​build​time />

<!-- Zero-width joiner -->
<iwc-build‍time />

<!-- Direction override -->
<iwc-build‮time />
```

## Category 15: Platform-Specific Edge Cases

### Windows-Specific Issues
```html
<!-- Windows path separators -->
<iwc-include file="path\to\file" />

<!-- Windows reserved names -->
<iwc-file name="CON" />
<iwc-file name="PRN" />
<iwc-file name="NUL" />

<!-- CRLF vs LF confusion -->
<iwc-buildtime format="iso-8601"\r\n/>
```

### Case Sensitivity Confusion
```html
<!-- Mixed case prefix -->
<IWC-buildtime />
<Iwc-buildtime />
<iWC-buildtime />

<!-- Mixed case tag name -->
<iwc-BuildTime />
<iwc-BUILDTIME />
<iwc-BuIlDtImE />

<!-- Mixed case attributes -->
<iwc-buildtime FORMAT="iso-8601" />
<iwc-buildtime Format="iso-8601" />
```

## Category 16: Timing and Ordering Issues

### Out-of-Order Elements
```html
<!-- Closing before opening -->
</iwc-buildtime><iwc-buildtime />

<!-- Multiple closings -->
<iwc-buildtime /></iwc-buildtime></iwc-buildtime>

<!-- Interleaved -->
<iwc-a><iwc-b></iwc-a></iwc-b>
```

## Category 17: Namespace and Prefix Confusion

### XML Namespace Attempts
```html
<!-- Namespace declarations -->
<iwc-buildtime xmlns:iwc="http://example.com" />

<!-- Namespace prefix -->
<foo:iwc-buildtime />

<!-- Multiple colons -->
<iwc:custom:buildtime />

<!-- Empty namespace -->
<iwc-buildtime xmlns="" />
```

## Category 18: Tokenization Edge Cases

### Difficult to Tokenize Patterns
```html
<!-- Multiple tags on one line -->
<iwc-a /><iwc-b /><iwc-c /><iwc-broken

<!-- Tags without spacing -->
<iwc-a/><iwc-b/><iwc-c/>

<!-- Comment-like but not -->
<iwc-<!----> />

<!-- Almost-valid patterns -->
<iwc-buildtime/ >
< iwc-buildtime/>
<iwc -buildtime/>
```

## Category 19: Attribute Value Edge Cases

### Complex Attribute Values
```html
<!-- Attributes with HTML inside -->
<iwc-container class="<div>test</div>" />

<!-- Attributes with quotes inside -->
<iwc-buildtime format="He said "hello"" />

<!-- Attributes with newlines -->
<iwc-buildtime format="line1
line2" />

<!-- Attributes with equals signs -->
<iwc-buildtime format="key=value" />

<!-- Attributes with closing tag syntax -->
<iwc-buildtime format="</script>" />
```

## Category 20: Recovery and Partial Parsing Issues

### Parser Recovery Challenges
```html
<!-- Sequence of errors -->
<iwc-broken
<iwc-also-broken
<iwc-valid />
<iwc-broken-again

<!-- Alternating valid/invalid -->
<iwc-valid /><iwc-broken<iwc-valid /><iwc-broken

<!-- Error followed by similar valid -->
<iwc-broken-buildtime />
<iwc-buildtime />
```
