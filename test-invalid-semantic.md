# Semantic Validation Errors

This file contains inputs that may be syntactically correct but semantically invalid - wrong values, missing required attributes, invalid combinations, etc.

## iwc-buildtime Semantic Errors

### Invalid Format Values
```html
<!-- Non-existent format -->
<iwc-buildtime format="invalid-format" />
<iwc-buildtime format="iso8601" />
<iwc-buildtime format="ISO-8601" />
<iwc-buildtime format="iso_8601" />
<iwc-buildtime format="iso.8601" />
<iwc-buildtime format="rfc3339" />
<iwc-buildtime format="RFC-3339" />
<iwc-buildtime format="unix-timestamp" />
<iwc-buildtime format="epoch" />
<iwc-buildtime format="datetime" />

<!-- Empty format -->
<iwc-buildtime format="" />

<!-- Whitespace-only format -->
<iwc-buildtime format="   " />
<iwc-buildtime format="	" />

<!-- Format with typos -->
<iwc-buildtime format="iso-8061" />
<iwc-buildtime format="iso-8610" />
<iwc-buildtime format="rfc-3339" />
<iwc-buildtime format="rfc-3393" />

<!-- Case variations -->
<iwc-buildtime format="ISO-8601" />
<iwc-buildtime format="Iso-8601" />
<iwc-buildtime format="iso-8601-EXTENDED" />

<!-- Missing required format attribute -->
<iwc-buildtime />
<iwc-buildtime timezone="UTC" />

<!-- Content where there shouldn't be any -->
<iwc-buildtime format="iso-8601">2025-01-15</iwc-buildtime>
<iwc-buildtime format="iso-8601">   </iwc-buildtime>
```

### Invalid Timezone Values
```html
<!-- Non-existent timezones -->
<iwc-buildtime format="iso-8601" timezone="Invalid/Zone" />
<iwc-buildtime format="iso-8601" timezone="US/InvalidCity" />
<iwc-buildtime format="iso-8601" timezone="Foo/Bar" />

<!-- Misspelled timezones -->
<iwc-buildtime format="iso-8601" timezone="America/New_York" />
<iwc-buildtime format="iso-8601" timezone="America/LosAngeles" />
<iwc-buildtime format="iso-8601" timezone="Europe/Paaris" />
<iwc-buildtime format="iso-8601" timezone="Asia/Tokio" />

<!-- Invalid offset format -->
<iwc-buildtime format="iso-8601" timezone="+5" />
<iwc-buildtime format="iso-8601" timezone="UTC+5" />
<iwc-buildtime format="iso-8601" timezone="+0500" />
<iwc-buildtime format="iso-8601" timezone="GMT+5" />

<!-- Out of range offsets -->
<iwc-buildtime format="iso-8601" timezone="+25:00" />
<iwc-buildtime format="iso-8601" timezone="-15:00" />
<iwc-buildtime format="iso-8601" timezone="+00:61" />

<!-- Empty timezone -->
<iwc-buildtime format="iso-8601" timezone="" />
```

### Invalid Locale Values
```html
<!-- Non-existent locales -->
<iwc-buildtime format="iso-8601" locale="xx-XX" />
<iwc-buildtime format="iso-8601" locale="invalid" />
<iwc-buildtime format="iso-8601" locale="English" />

<!-- Malformed locales -->
<iwc-buildtime format="iso-8601" locale="en_US" />
<iwc-buildtime format="iso-8601" locale="EN-us" />
<iwc-buildtime format="iso-8601" locale="en-us-POSIX" />
<iwc-buildtime format="iso-8601" locale="e-n" />

<!-- Empty locale -->
<iwc-buildtime format="iso-8601" locale="" />
```

### Invalid Attribute Combinations
```html
<!-- Mutually exclusive attributes -->
<iwc-buildtime format="iso-8601" unixtime="true" />

<!-- Conflicting options -->
<iwc-buildtime format="iso-8601" utc="true" timezone="America/New_York" />

<!-- Attributes that don't apply to format -->
<iwc-buildtime format="iso-8601" milliseconds="true" />
```

## iwc-quotefig Semantic Errors

### Invalid URL Values in cite
```html
<!-- Missing protocol -->
<iwc-quotefig cite="example.com">Quote</iwc-quotefig>
<iwc-quotefig cite="www.example.com">Quote</iwc-quotefig>

<!-- Invalid protocol -->
<iwc-quotefig cite="javascript:alert(1)">Quote</iwc-quotefig>
<iwc-quotefig cite="data:text/html,<script>alert(1)</script>">Quote</iwc-quotefig>
<iwc-quotefig cite="vbscript:msgbox">Quote</iwc-quotefig>
<iwc-quotefig cite="file:///etc/passwd">Quote</iwc-quotefig>

<!-- Malformed URLs -->
<iwc-quotefig cite="http://">Quote</iwc-quotefig>
<iwc-quotefig cite="http:///example.com">Quote</iwc-quotefig>
<iwc-quotefig cite="http://exam ple.com">Quote</iwc-quotefig>
<iwc-quotefig cite="http://example.com:99999">Quote</iwc-quotefig>
<iwc-quotefig cite="http://256.256.256.256">Quote</iwc-quotefig>

<!-- Empty cite -->
<iwc-quotefig cite="">Quote</iwc-quotefig>

<!-- Whitespace cite -->
<iwc-quotefig cite="   ">Quote</iwc-quotefig>

<!-- Missing required cite attribute -->
<iwc-quotefig>Quote</iwc-quotefig>
<iwc-quotefig caption="Author">Quote</iwc-quotefig>

<!-- Relative URLs (may be invalid depending on rules) -->
<iwc-quotefig cite="/path/to/page">Quote</iwc-quotefig>
<iwc-quotefig cite="../../../page">Quote</iwc-quotefig>
<iwc-quotefig cite="#fragment">Quote</iwc-quotefig>

<!-- URL-like but broken -->
<iwc-quotefig cite="ht!tp://example.com">Quote</iwc-quotefig>
<iwc-quotefig cite="http//example.com">Quote</iwc-quotefig>
```

### Invalid Caption Content
```html
<!-- Empty caption -->
<iwc-quotefig cite="https://example.com" caption="">Quote</iwc-quotefig>

<!-- Whitespace-only caption -->
<iwc-quotefig cite="https://example.com" caption="   ">Quote</iwc-quotefig>

<!-- Unclosed HTML in caption -->
<iwc-quotefig cite="https://example.com" caption="<strong>Author">Quote</iwc-quotefig>

<!-- Invalid HTML in caption -->
<iwc-quotefig cite="https://example.com" caption="<notreal>Author</notreal>">Quote</iwc-quotefig>

<!-- Script in caption -->
<iwc-quotefig cite="https://example.com" caption="<script>alert(1)</script>">Quote</iwc-quotefig>

<!-- Caption without cite (invalid if cite is required) -->
<iwc-quotefig caption="Author Name">Quote</iwc-quotefig>
```

### Empty or Invalid Content
```html
<!-- No content -->
<iwc-quotefig cite="https://example.com"></iwc-quotefig>

<!-- Whitespace-only content -->
<iwc-quotefig cite="https://example.com">   </iwc-quotefig>
<iwc-quotefig cite="https://example.com">

</iwc-quotefig>

<!-- Content with only HTML comments -->
<iwc-quotefig cite="https://example.com"><!-- comment --></iwc-quotefig>
```

## iwc-image Semantic Errors (hypothetical)

### Invalid src Values
```html
<!-- Empty src -->
<iwc-image src="" alt="Description" />

<!-- Whitespace src -->
<iwc-image src="   " alt="Description" />

<!-- Invalid protocol -->
<iwc-image src="javascript:alert(1)" alt="Malicious" />
<iwc-image src="data:text/html,<script>alert(1)</script>" alt="XSS" />

<!-- Missing src -->
<iwc-image alt="Description" />

<!-- Malformed path -->
<iwc-image src="path with spaces.jpg" alt="Invalid" />
<iwc-image src="path\with\backslashes.jpg" alt="Invalid" />

<!-- Non-image extension -->
<iwc-image src="document.pdf" alt="Not an image" />
<iwc-image src="executable.exe" alt="Dangerous" />
```

### Invalid Dimension Values
```html
<!-- Negative dimensions -->
<iwc-image src="image.jpg" width="-100" alt="Invalid" />
<iwc-image src="image.jpg" height="-50" alt="Invalid" />

<!-- Zero dimensions -->
<iwc-image src="image.jpg" width="0" alt="Invalid" />
<iwc-image src="image.jpg" height="0" alt="Invalid" />

<!-- Non-numeric dimensions -->
<iwc-image src="image.jpg" width="abc" alt="Invalid" />
<iwc-image src="image.jpg" height="large" alt="Invalid" />

<!-- Extremely large dimensions -->
<iwc-image src="image.jpg" width="999999999" alt="Too large" />
<iwc-image src="image.jpg" height="999999999" alt="Too large" />

<!-- Float dimensions -->
<iwc-image src="image.jpg" width="100.5" alt="Float" />

<!-- Percentage without unit -->
<iwc-image src="image.jpg" width="50%" alt="Percentage" />

<!-- With units (may be invalid) -->
<iwc-image src="image.jpg" width="100px" alt="Units" />
<iwc-image src="image.jpg" width="50em" alt="Units" />
```

### Invalid Alt Text
```html
<!-- Missing alt -->
<iwc-image src="image.jpg" />

<!-- Empty alt (may be valid for decorative images) -->
<iwc-image src="image.jpg" alt="" />

<!-- Extremely long alt -->
<iwc-image src="image.jpg" alt="[10000 characters of text]" />

<!-- Alt with markup -->
<iwc-image src="image.jpg" alt="Description with <em>markup</em>" />
```

### Invalid Loading Values
```html
<!-- Misspelled -->
<iwc-image src="image.jpg" loading="lazi" alt="Typo" />
<iwc-image src="image.jpg" loading="eagar" alt="Typo" />

<!-- Wrong case -->
<iwc-image src="image.jpg" loading="Lazy" alt="Case" />

<!-- Invalid value -->
<iwc-image src="image.jpg" loading="immediate" alt="Invalid" />
<iwc-image src="image.jpg" loading="async" alt="Invalid" />
```

## iwc-link Semantic Errors (hypothetical)

### Invalid href Values
```html
<!-- Empty href -->
<iwc-link href="">Link text</iwc-link>

<!-- Whitespace href -->
<iwc-link href="   ">Link text</iwc-link>

<!-- Missing href -->
<iwc-link>Link text</iwc-link>

<!-- Invalid protocols -->
<iwc-link href="javascript:void(0)">Link</iwc-link>
<iwc-link href="data:text/html,<script>alert(1)</script>">Link</iwc-link>
<iwc-link href="vbscript:msgbox(1)">Link</iwc-link>

<!-- Malformed URLs -->
<iwc-link href="http://">Empty host</iwc-link>
<iwc-link href="http:///path">Triple slash</iwc-link>
<iwc-link href="ht!tp://example.com">Invalid protocol</iwc-link>
```

### Empty Link Content
```html
<!-- No content -->
<iwc-link href="https://example.com"></iwc-link>

<!-- Whitespace only -->
<iwc-link href="https://example.com">   </iwc-link>
```

### Invalid Target Values
```html
<!-- Invalid target -->
<iwc-link href="https://example.com" target="invalid">Link</iwc-link>
<iwc-link href="https://example.com" target="window">Link</iwc-link>

<!-- Case variations -->
<iwc-link href="https://example.com" target="_Blank">Link</iwc-link>
<iwc-link href="https://example.com" target="BLANK">Link</iwc-link>
```

### Invalid rel Values
```html
<!-- Typos -->
<iwc-link href="https://example.com" rel="nofolow">Link</iwc-link>
<iwc-link href="https://example.com" rel="noopner">Link</iwc-link>

<!-- Invalid combinations -->
<iwc-link href="https://example.com" rel="follow nofollow">Link</iwc-link>
```

## iwc-container Semantic Errors (hypothetical)

### Invalid Container Types
```html
<!-- Unknown type -->
<iwc-container type="unknown">Content</iwc-container>

<!-- Typo -->
<iwc-container type="secton">Content</iwc-container>

<!-- Wrong case -->
<iwc-container type="ARTICLE">Content</iwc-container>
```

### Empty Containers
```html
<!-- No content -->
<iwc-container></iwc-container>

<!-- Whitespace only -->
<iwc-container>   </iwc-container>
```

## iwc-button Semantic Errors (hypothetical)

### Invalid Type Values
```html
<!-- Misspelled -->
<iwc-button type="submitt">Click</iwc-button>
<iwc-button type="buton">Click</iwc-button>

<!-- Invalid type -->
<iwc-button type="link">Click</iwc-button>
<iwc-button type="primary">Click</iwc-button>
```

### Empty Button
```html
<!-- No content -->
<iwc-button></iwc-button>

<!-- Whitespace only -->
<iwc-button>   </iwc-button>
```

### Invalid disabled Values
```html
<!-- String instead of boolean -->
<iwc-button disabled="false">Click</iwc-button>
<iwc-button disabled="no">Click</iwc-button>
```

## iwc-video Semantic Errors (hypothetical)

### Invalid src Values
```html
<!-- Empty -->
<iwc-video src=""></iwc-video>

<!-- Not a video file -->
<iwc-video src="document.pdf"></iwc-video>
<iwc-video src="image.jpg"></iwc-video>

<!-- Invalid extension -->
<iwc-video src="video.avi"></iwc-video>
<iwc-video src="video.mov"></iwc-video>
```

### Invalid Autoplay Combinations
```html
<!-- Autoplay without muted -->
<iwc-video src="video.mp4" autoplay></iwc-video>
```

## iwc-include Semantic Errors (hypothetical)

### Path Traversal
```html
<!-- Directory traversal -->
<iwc-include file="../../etc/passwd" />
<iwc-include file="../../../secret.txt" />

<!-- Absolute paths -->
<iwc-include file="/etc/passwd" />
<iwc-include file="C:\Windows\System32\config\SAM" />

<!-- URL as file -->
<iwc-include file="https://evil.com/malicious.txt" />
```

### Circular Includes
```html
<!-- File including itself -->
<iwc-include file="current-file.html" />
```

### Non-Existent Files
```html
<!-- File doesn't exist -->
<iwc-include file="does-not-exist.html" />

<!-- Typo in filename -->
<iwc-include file="partail.html" />
```

## iwc-raw Semantic Errors

### Raw with Attributes
```html
<!-- Attributes on raw (may be invalid) -->
<iwc-raw format="html"><iwc-something /></iwc-raw>
<iwc-raw type="text"><iwc-something /></iwc-raw>
```

### Empty Raw
```html
<!-- Nothing to escape -->
<iwc-raw></iwc-raw>
```

### Nested Raw
```html
<!-- Raw inside raw -->
<iwc-raw>
  <iwc-raw><iwc-something /></iwc-raw>
</iwc-raw>
```

## iwc-code Semantic Errors (hypothetical)

### Invalid Language
```html
<!-- Non-existent language -->
<iwc-code lang="fakescript">code</iwc-code>
<iwc-code lang="javascrpt">code</iwc-code>

<!-- Misspelled -->
<iwc-code lang="pythn">code</iwc-code>
<iwc-code lang="jave">code</iwc-code>
```

### Empty Code Block
```html
<!-- No code -->
<iwc-code lang="javascript"></iwc-code>

<!-- Whitespace only -->
<iwc-code lang="javascript">   </iwc-code>
```

## iwc-table Semantic Errors (hypothetical)

### Invalid Table Structure
```html
<!-- No rows -->
<iwc-table></iwc-table>

<!-- Empty rows -->
<iwc-table>
  <iwc-row></iwc-row>
</iwc-table>

<!-- Inconsistent column count -->
<iwc-table>
  <iwc-row><iwc-cell>A</iwc-cell><iwc-cell>B</iwc-cell></iwc-row>
  <iwc-row><iwc-cell>C</iwc-cell></iwc-row>
</iwc-table>
```

## Cross-Shortcode Semantic Errors

### Invalid Nesting
```html
<!-- Block element inside inline -->
<iwc-link href="https://example.com">
  <iwc-container>Content</iwc-container>
</iwc-link>

<!-- Interactive inside interactive -->
<iwc-button>
  <iwc-link href="https://example.com">Link</iwc-link>
</iwc-button>

<iwc-link href="https://example.com">
  <iwc-button>Button</iwc-button>
</iwc-link>
```

### Circular References
```html
<!-- Template including itself -->
<iwc-template id="self">
  <iwc-use template="self" />
</iwc-template>

<!-- Mutual inclusion -->
<iwc-template id="a">
  <iwc-use template="b" />
</iwc-template>
<iwc-template id="b">
  <iwc-use template="a" />
</iwc-template>
```

## Context-Specific Errors

### Shortcodes in Wrong Context
```html
<!-- Block shortcode inside inline element -->
<p><iwc-container>Block content</iwc-container></p>

<!-- Shortcode inside script -->
<script>
var x = <iwc-buildtime format="iso-8601" />;
</script>

<!-- Shortcode inside style -->
<style>
.time:before {
  content: '<iwc-buildtime format="iso-8601" />';
}
</style>

<!-- Shortcode inside attribute value (HTML) -->
<div class="<iwc-classname />">Content</div>

<!-- Shortcode inside HTML comment -->
<!-- This should be rendered: <iwc-buildtime format="iso-8601" /> -->

<!-- Shortcode inside CDATA -->
<![CDATA[
<iwc-buildtime format="iso-8601" />
]]>
```

## Attribute Value Semantic Errors

### Out of Range Numbers
```html
<!-- Percentage over 100 -->
<iwc-progress value="150" max="100" />

<!-- Negative where not allowed -->
<iwc-image src="image.jpg" width="-100" />

<!-- Zero where not allowed -->
<iwc-grid columns="0">Content</iwc-grid>
```

### Invalid Enumerations
```html
<!-- Not in allowed set -->
<iwc-align position="middle">Content</iwc-align>
<iwc-button variant="danger">Click</iwc-button>
```

### Invalid Date/Time Formats
```html
<!-- Invalid dates as attribute values -->
<iwc-event date="2025-13-01" />
<iwc-event date="2025-02-30" />
<iwc-event date="32/12/2025" />
<iwc-event time="25:00:00" />
<iwc-event time="12:60:00" />
<iwc-event time="12:00:60" />
```

### Invalid Color Values
```html
<!-- Malformed hex -->
<iwc-box color="#GGGGGG" />
<iwc-box color="#12345" />
<iwc-box color="123456" />

<!-- Invalid named color -->
<iwc-box color="darkish-blue" />
<iwc-box color="redd" />

<!-- Invalid RGB -->
<iwc-box color="rgb(300, 0, 0)" />
<iwc-box color="rgb(0, 0)" />
```

## Security-Related Semantic Errors

### Potentially Dangerous Values
```html
<!-- Event handler in attributes -->
<iwc-image src="image.jpg" onerror="alert(1)" />
<iwc-link href="https://example.com" onclick="malicious()" />

<!-- Style with javascript -->
<iwc-box style="background: url('javascript:alert(1)')" />

<!-- Expression in attributes -->
<iwc-container data-value="#{7*7}" />
<iwc-container data-value="${{7*7}}" />

<!-- Import/require in content -->
<iwc-code>
const evil = require('malicious-package');
</iwc-code>
```

### External Resource Violations
```html
<!-- Linking to non-HTTPS in HTTPS context -->
<iwc-link href="http://example.com">Insecure link</iwc-link>
<iwc-image src="http://example.com/image.jpg" />

<!-- Mixed content -->
<iwc-video src="http://example.com/video.mp4"></iwc-video>
```

## Accessibility Semantic Errors

### Missing Required Accessibility Attributes
```html
<!-- Image without alt -->
<iwc-image src="image.jpg" />

<!-- Link with no text and no aria-label -->
<iwc-link href="https://example.com">
  <iwc-image src="icon.svg" alt="" />
</iwc-link>

<!-- Button with no accessible name -->
<iwc-button>
  <iwc-image src="icon.svg" alt="" />
</iwc-button>

<!-- Form field without label -->
<iwc-input name="email" />
```

### Invalid ARIA
```html
<!-- Invalid ARIA attributes -->
<iwc-button aria-pressed="maybe">Toggle</iwc-button>
<iwc-container aria-live="aggressive">Alert</iwc-container>

<!-- ARIA on elements where not allowed -->
<iwc-buildtime format="iso-8601" aria-label="Current time" />
```

## Internationalization Errors

### Invalid Language Codes
```html
<!-- Non-existent language -->
<iwc-content lang="xx">Text</iwc-content>

<!-- Malformed -->
<iwc-content lang="en_US">Text</iwc-content>
<iwc-content lang="English">Text</iwc-content>
```

### Text Direction Errors
```html
<!-- Invalid dir value -->
<iwc-content dir="left-to-right">Text</iwc-content>
<iwc-content dir="left">Text</iwc-content>
```

## Performance-Related Semantic Errors

### Resource Hints Misuse
```html
<!-- Prefetch with blocking -->
<iwc-prefetch href="style.css" blocking="render" />

<!-- Preload without type -->
<iwc-preload href="resource" />
```

### Lazy Loading Misuse
```html
<!-- Lazy loading above-the-fold content -->
<iwc-image src="hero.jpg" loading="lazy" priority="high" />
```
