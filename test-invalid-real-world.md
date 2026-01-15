# Real-World Invalid Input Examples

This file contains realistic invalid inputs that users might actually create, either by mistake or through copy-paste errors, autocomplete failures, or misunderstanding the syntax.

## Common Typos and User Errors

### Typos in Tag Names
```html
<!-- Missing hyphen -->
<iwcbuildtime format="iso-8601" />

<!-- Extra hyphen -->
<iwc--buildtime format="iso-8601" />

<!-- Swapped letters -->
<iwc-buidltime format="iso-8601" />
<iwc-bildutime format="iso-8601" />

<!-- Wrong prefix from muscle memory (React, Vue, etc.) -->
<x-buildtime format="iso-8601" />
<v-buildtime format="iso-8601" />
<ng-buildtime />
<app-buildtime />

<!-- Capitalization from other frameworks -->
<Iwc-buildtime />
<IwcBuildtime />
<IWCBuildtime />
```

### Copy-Paste Errors
```html
<!-- Partial paste -->
<iwc-buildtime format="iso-86

<!-- Double paste -->
<iwc-buildtime format="iso-8601" /><iwc-buildtime format="iso-8601" />

<!-- Pasted with formatting characters -->
<iwc-buildtime format="iso-8601" />

<!-- Pasted with hidden characters -->
<iwc-buildtime format="iso-8601" />

<!-- Pasted from Word/docs with smart quotes -->
<iwc-buildtime format="iso-8601" />

<!-- Pasted with non-breaking spaces -->
<iwc-buildtime format="iso-8601" />
```

### Autocomplete Failures
```html
<!-- IDE autocomplete left open -->
<iwc-buildtime format="

<!-- Autocomplete selected wrong option -->
<iwc-buildtime format="iso-8601-extended-plus-offset" />

<!-- Multiple autocomplete suggestions merged -->
<iwc-buildtime format="iso-8601"format="rfc-3339" />

<!-- Autocomplete with template variable -->
<iwc-buildtime format="${FORMAT}" />
<iwc-buildtime format="{{format}}" />
```

## Confusion with Other Syntaxes

### JSX/React Patterns
```html
<!-- JSX self-closing -->
<iwc-buildtime format={iso8601} />

<!-- JSX expressions in attributes -->
<iwc-buildtime format={"iso-8601"} />
<iwc-buildtime format={`iso-8601`} />

<!-- JSX spread operator -->
<iwc-buildtime {...props} />
<iwc-buildtime format="iso-8601" {...rest} />

<!-- React event handlers -->
<iwc-button onClick={handleClick} />
<iwc-button onClick="handleClick()" />

<!-- React className -->
<iwc-container className="wrapper" />

<!-- React style objects -->
<iwc-box style={{color: 'red'}} />

<!-- JSX comments -->
<iwc-buildtime format="iso-8601" {/* comment */} />
```

### Vue.js Patterns
```html
<!-- Vue directives -->
<iwc-buildtime v-if="show" />
<iwc-buildtime v-for="item in items" />
<iwc-buildtime v-bind:format="iso8601" />
<iwc-buildtime :format="iso8601" />
<iwc-buildtime @click="handler" />

<!-- Vue shorthand -->
<iwc-buildtime :format="variable" />

<!-- Vue modifiers -->
<iwc-input v-model.lazy="value" />
```

### Angular Patterns
```html
<!-- Angular directives -->
<iwc-buildtime *ngIf="show" />
<iwc-buildtime *ngFor="let item of items" />
<iwc-buildtime [format]="iso8601" />
<iwc-buildtime (click)="handler()" />

<!-- Angular two-way binding -->
<iwc-input [(ngModel)]="value" />

<!-- Angular structural directives -->
<iwc-container *ngSwitch="value">
```

### Svelte Patterns
```html
<!-- Svelte reactive declarations -->
<iwc-buildtime bind:format={iso8601} />
<iwc-buildtime on:click={handler} />

<!-- Svelte shorthand -->
<iwc-buildtime {format} />

<!-- Svelte directives -->
<iwc-buildtime use:action />
```

### Hugo Shortcode Confusion
```html
<!-- Hugo shortcode syntax (percent signs) -->
{{< iwc-buildtime format="iso-8601" >}}
{{< iwc-buildtime format="iso-8601" />}}

<!-- Hugo named parameters -->
{{< iwc-quotefig cite="example.com" >}}Quote{{< /iwc-quotefig >}}

<!-- Hugo with line breaks -->
{{< iwc-buildtime
  format="iso-8601"
  timezone="UTC"
>}}

<!-- Mixed syntax -->
<{{< iwc-buildtime />}}>
```

## Template Engine Confusion

### Handlebars/Mustache
```html
<!-- Handlebars helpers -->
<iwc-buildtime format="{{iso-8601}}" />
{{#iwc-buildtime}}content{{/iwc-buildtime}}

<!-- Handlebars expressions -->
<iwc-buildtime format="{{format}}" />
<iwc-buildtime format="{{{unescaped}}}" />
```

### Jinja2/Liquid
```html
<!-- Jinja2 variables -->
<iwc-buildtime format="{{ iso_8601 }}" />
<iwc-buildtime format="{% format %}" />

<!-- Liquid filters -->
<iwc-buildtime format="{{ 'iso-8601' | upcase }}" />

<!-- Template tags -->
{% iwc-buildtime format="iso-8601" %}
```

### EJS/ERB
```html
<!-- EJS -->
<iwc-buildtime format="<%= iso8601 %>" />
<%- include('iwc-buildtime', {format: 'iso-8601'}) %>

<!-- ERB -->
<iwc-buildtime format="<%= iso_8601 %>" />
```

## Markdown Integration Errors

### Markdown Confusion
```html
<!-- Markdown inside attributes -->
<iwc-quotefig caption="**Bold** caption">Quote</iwc-quotefig>

<!-- Markdown links in attributes -->
<iwc-quotefig caption="[Link](http://example.com)">Quote</iwc-quotefig>

<!-- Escaped Markdown thinking -->
<iwc-buildtime format=\`iso-8601\` />

<!-- Code fence confusion -->
```<iwc-buildtime />```

<!-- Inline code confusion -->
`<iwc-buildtime />`
```

### MDX Confusion
```html
<!-- MDX component syntax -->
<iwc-buildtime format={iso8601} />

<!-- MDX with imports -->
import { format } from 'date-fns'
<iwc-buildtime format={format} />

<!-- MDX expressions -->
<iwc-buildtime format={new Date().toISOString()} />
```

## HTML/XML Confusion

### XHTML Strictness
```html
<!-- XHTML attribute minimization -->
<iwc-buildtime format />

<!-- XHTML without quotes -->
<iwc-buildtime format=iso-8601 />

<!-- XML processing instruction -->
<?iwc-buildtime format="iso-8601"?>

<!-- XML CDATA in content -->
<iwc-quotefig><![CDATA[Quote with <tags>]]></iwc-quotefig>
```

### HTML5 Looseness Applied Wrong
```html
<!-- Unquoted attributes with spaces -->
<iwc-buildtime format=iso 8601 />

<!-- Omitting closing tags -->
<iwc-container>
  <iwc-box>Content
  <iwc-box>More content
</iwc-container>

<!-- Implied closing -->
<iwc-buildtime format="iso-8601">
<iwc-other />
```

## IDE and Editor Issues

### Editor Formatting Artifacts
```html
<!-- Auto-formatted with wrong rules -->
<iwc-buildtime
  format="iso-8601"
  />

<!-- Prettier-style formatting -->
<iwc-buildtime
  format="iso-8601"
/>

<!-- Editor added semicolons -->
<iwc-buildtime format="iso-8601";/>

<!-- Editor autoclosed incorrectly -->
<iwc-buildtime></iwc-buildtime>

<!-- Editor converted quotes -->
<iwc-buildtime format="iso-8601" />
```

### Vim/Emacs Macros Gone Wrong
```html
<!-- Repeated macro application -->
<iwc-buildtime format="iso-8601" /><iwc-buildtime format="iso-8601" />

<!-- Incorrect substitution -->
<iwc-buildtime format=iso-8601" />

<!-- Line-based operation broke tag -->
<iwc-buildtime
format="iso-8601" />
```

## Version Control Conflicts

### Git Merge Conflicts
```html
<<<<<<< HEAD
<iwc-buildtime format="iso-8601" />
=======
<iwc-buildtime format="rfc-3339" />
>>>>>>> branch

<!-- Unresolved conflict markers -->
<iwc-buildtime format="iso-8601" />
<<<<<<< HEAD
<iwc-quotefig cite="example.com">Quote</iwc-quotefig>
=======
<iwc-quotefig cite="other.com">Different quote</iwc-quotefig>
>>>>>>> branch
```

### Partial Conflict Resolution
```html
<!-- Left conflict markers -->
<iwc-buildtime format="iso-8601" />
=======

<!-- Mixed both versions -->
<iwc-buildtime format="iso-8601" />
<iwc-buildtime format="rfc-3339" />
```

## Build Tool and Preprocessor Errors

### Webpack/Build Tool Variables
```html
<!-- Environment variables -->
<iwc-buildtime format="%ENV_FORMAT%" />
<iwc-buildtime format="$ENV{FORMAT}" />

<!-- Build-time replacements not resolved -->
<iwc-buildtime format="__FORMAT__" />
<iwc-buildtime format="@@format@@" />
```

### CSS/SCSS Confusion
```html
<!-- SCSS variables -->
<iwc-buildtime format="$format" />

<!-- CSS variables -->
<iwc-buildtime format="var(--format)" />

<!-- SCSS nesting confusion -->
.container {
  <iwc-buildtime />
}
```

## Database and Backend Confusion

### SQL String Escaping Issues
```html
<!-- Escaped quotes from database -->
<iwc-buildtime format=\"iso-8601\" />

<!-- SQL string concatenation artifact -->
<iwc-buildtime format="' + 'iso-8601' + '" />

<!-- Database escape characters -->
<iwc-buildtime format=\'iso-8601\' />
```

### JSON Escaping Issues
```html
<!-- JSON escaped -->
<iwc-buildtime format=\"iso-8601\" \/>

<!-- JSON in HTML -->
<script>var data = "<iwc-buildtime />";</script>

<!-- Double-encoded -->
<iwc-buildtime format=\\"iso-8601\\" />
```

## Mobile and Touch Input Issues

### Touchscreen Typos
```html
<!-- Adjacent key press -->
<iwc-buildtine format="iso-8601" />
<iwc-nuildtime format="iso-8601" />

<!-- Double tap -->
<iwc-builddtime format="iso-8601" />

<!-- Autocorrect interference -->
<iwc-buildtime format="is-8601" />
<iwc-buildtime format="iOS-8601" />
```

## Internationalization Issues

### Non-English Keyboards
```html
<!-- Accidental diacritics -->
<iwc-bùildtime format="iso-8601" />
<iwc-büildtime format="iso-8601" />

<!-- Wrong keyboard layout -->
<iwc-buildtime format="iso\8601" />
<iwc-buildtime format='iso;8601' />

<!-- Non-Latin script -->
<iwc-буилдтиме />
```

## Copy From Documentation Errors

### Copied with Extra Characters
```html
<!-- Line numbers from docs -->
1. <iwc-buildtime format="iso-8601" />

<!-- Markdown code fence markers -->
```html
<iwc-buildtime format="iso-8601" />
```

<!-- Copy with prompt -->
$ <iwc-buildtime format="iso-8601" />

<!-- Copy with output -->
<iwc-buildtime format="iso-8601" />
<!-- Output: 2025-01-15T... -->
```

### Placeholder Not Replaced
```html
<!-- Example placeholders left in -->
<iwc-buildtime format="YOUR_FORMAT_HERE" />
<iwc-quotefig cite="https://example.com">YOUR_QUOTE_HERE</iwc-quotefig>

<!-- TODO comments left in -->
<iwc-buildtime format="iso-8601" /> <!-- TODO: verify format -->

<!-- Example data not changed -->
<iwc-buildtime format="iso-8601" />
```

## Browser DevTools Issues

### Inspected Element Copied
```html
<!-- == $0 from console -->
<iwc-buildtime format="iso-8601" />

<!-- With DevTools annotations -->
<iwc-buildtime format="iso-8601" /> <!--hover info-->

<!-- Copied with DOM properties -->
<iwc-buildtime format="iso-8601" __data__="..." />
```

## Screen Reader / Accessibility Tool Artifacts

### ARIA Confusion
```html
<!-- ARIA attributes on custom element -->
<iwc-buildtime format="iso-8601" aria-label="Build time" />

<!-- Role on shortcode -->
<iwc-button role="button">Click</iwc-button>

<!-- Tabindex -->
<iwc-link href="example.com" tabindex="0">Link</iwc-link>
```

## Email/Rich Text Editor Issues

### Rich Text Editor Artifacts
```html
<!-- Styled spans -->
<iwc-buildtime format="<span style='color:red'>iso-8601</span>" />

<!-- Non-breaking spaces from editors -->
<iwc-buildtime format="iso-8601"  />

<!-- Zero-width joiners -->
<iwc-build‌time format="iso-8601" />

<!-- Soft hyphens -->
<iwc-build­time format="iso-8601" />
```

## Security Scanner False Positives

### Security Tool Escaping
```html
<!-- HTML entity encoded by scanner -->
<iwc-buildtime format=&quot;iso-8601&quot; />

<!-- URL encoded -->
<iwc-buildtime%20format=%22iso-8601%22%20/>

<!-- Double encoded -->
<iwc-buildtime format=&amp;quot;iso-8601&amp;quot; />
```

## Testing and Debug Artifacts

### Debug Code Left In
```html
<!-- Console.log equivalent -->
<iwc-buildtime format="iso-8601" /> console.log('here')

<!-- Commented out partially -->
<!-- <iwc-buildtime format="iso-8601" />

<!-- Debug attributes -->
<iwc-buildtime format="iso-8601" debug="true" />
<iwc-buildtime format="iso-8601" data-test-id="time" />
```

## File System Issues

### Path Separators Wrong
```html
<!-- Windows paths on Unix -->
<iwc-include file="path\to\file" />

<!-- Unix paths on Windows -->
<iwc-include file="path/to/file" />

<!-- Mixed separators -->
<iwc-include file="path/to\file" />
```

### File Extensions Confusion
```html
<!-- File extension in tag name -->
<iwc-buildtime.html format="iso-8601" />

<!-- Query string thinking -->
<iwc-buildtime?format=iso-8601 />

<!-- Fragment thinking -->
<iwc-buildtime#format format="iso-8601" />
```

## Scripting Language Confusion

### Python String Formatting
```html
<!-- f-string style -->
<iwc-buildtime format=f"{iso_8601}" />

<!-- .format() style -->
<iwc-buildtime format="{0}".format("iso-8601") />

<!-- % formatting -->
<iwc-buildtime format="%s" % "iso-8601" />
```

### JavaScript Template Literals
```html
<!-- Template literal backticks -->
<iwc-buildtime format=`iso-8601` />

<!-- Template literal expressions -->
<iwc-buildtime format=`${format}` />

<!-- Tagged templates -->
<iwc-buildtime format=html`iso-8601` />
```

### Shell Variable Expansion
```html
<!-- Bash variable -->
<iwc-buildtime format="$FORMAT" />

<!-- Shell command substitution -->
<iwc-buildtime format="$(get_format)" />

<!-- Bash brace expansion -->
<iwc-buildtime format="iso-{8601}" />
```

## Common Misunderstandings

### HTML Form Confusion
```html
<!-- Form input attributes -->
<iwc-buildtime name="time" value="iso-8601" />

<!-- Form submission attributes -->
<iwc-button type="submit" />
<iwc-input required />
```

### Multimedia Element Confusion
```html
<!-- Video/audio attributes -->
<iwc-video src="video.mp4" controls />
<iwc-image src="pic.jpg" loading="lazy" />
```

### Table Element Confusion
```html
<!-- Table attributes -->
<iwc-table border="1" cellpadding="5">
```

## OCR and Speech-to-Text Errors

### OCR Misreads
```html
<!-- l vs I vs 1 -->
<iwc-bui1dtime format="iso-860l" />
<iwc-buiIdtime format="iso-860I" />

<!-- O vs 0 -->
<iwc-buildtime format="is0-8601" />
<iwc-buildtime format="iso-86O1" />

<!-- rn vs m -->
<iwc-buildtirne format="iso-8601" />
```

### Speech Recognition Errors
```html
<!-- Homophone -->
<iwc-build-time format="eye-ess-oh-8601" />

<!-- Misheard words -->
<iwc-build-thyme format="iso-8601" />
<iwc-guild-time format="iso-8601" />
```

## Version/API Migration Errors

### Old API Syntax
```html
<!-- Deprecated syntax still used -->
<shortcode-buildtime format="iso-8601" />

<!-- Old attribute names -->
<iwc-buildtime fmt="iso-8601" />

<!-- Removed attributes -->
<iwc-buildtime format="iso-8601" deprecated-attr="value" />
```

## Character Encoding Issues in Real Files

### UTF-8 BOM
```html
<!-- File starts with BOM -->
﻿<iwc-buildtime format="iso-8601" />
```

### Latin-1 Misinterpreted as UTF-8
```html
<!-- Mojibake -->
<iwc-buildtime format="iso-8601Â " />
<iwc-buildtime format=â€œiso-8601â€ />
```

### Windows-1252 Artifacts
```html
<!-- Smart quotes as Windows-1252 -->
<iwc-buildtime format="iso-8601" />

<!-- Em dash as Windows-1252 -->
<iwc-buildtime format="iso—8601" />
```
