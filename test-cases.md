# Inert Web Components - Test Cases

This document contains comprehensive test cases for IWC shortcodes with expected inputs and outputs.

## Test Case Format

Each test case shows:
- **Input**: The HTML with IWC shortcodes
- **Output**: The expected transformed HTML

---

## 1. `<iwc-buildtime>` Tests

### 1.1 ISO-8601 Format (Default)
**Input:**
```html
Built at <iwc-buildtime format="iso-8601"></iwc-buildtime>
```
**Output:**
```html
Built at <time datetime="2026-01-15T10:30:00Z">2026-01-15T10:30:00Z</time>
```

### 1.2 ISO-8601 with Timezone
**Input:**
```html
<iwc-buildtime format="iso-8601" timezone="America/New_York"></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T05:30:00-05:00">2026-01-15T05:30:00-05:00</time>
```

### 1.3 Human Readable Format
**Input:**
```html
<iwc-buildtime format="human"></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">January 15, 2026 at 10:30 AM UTC</time>
```

### 1.4 Unix Timestamp
**Input:**
```html
<iwc-buildtime format="unix"></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">1736939400</time>
```

### 1.5 Custom Format String
**Input:**
```html
<iwc-buildtime format="YYYY-MM-DD"></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">2026-01-15</time>
```

### 1.6 Self-Closing Variant
**Input:**
```html
<iwc-buildtime format="iso-8601" />
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">2026-01-15T10:30:00Z</time>
```

### 1.7 With Custom CSS Class
**Input:**
```html
<iwc-buildtime format="iso-8601" class="timestamp"></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z" class="timestamp">2026-01-15T10:30:00Z</time>
```

### 1.8 Relative Time Format
**Input:**
```html
<iwc-buildtime format="relative"></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">just now</time>
```

### 1.9 Date Only
**Input:**
```html
<iwc-buildtime format="date-only"></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15">January 15, 2026</time>
```

### 1.10 Time Only
**Input:**
```html
<iwc-buildtime format="time-only"></iwc-buildtime>
```
**Output:**
```html
<time datetime="10:30:00">10:30:00 AM</time>
```

### 1.11 RFC 2822 Format
**Input:**
```html
<iwc-buildtime format="rfc2822"></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">Thu, 15 Jan 2026 10:30:00 +0000</time>
```

### 1.12 Multiple Buildtimes in Same Document
**Input:**
```html
<p>Built: <iwc-buildtime format="iso-8601"></iwc-buildtime></p>
<footer>Generated: <iwc-buildtime format="human"></iwc-buildtime></footer>
```
**Output:**
```html
<p>Built: <time datetime="2026-01-15T10:30:00Z">2026-01-15T10:30:00Z</time></p>
<footer>Generated: <time datetime="2026-01-15T10:30:00Z">January 15, 2026 at 10:30 AM UTC</time></footer>
```

### 1.13 No Format Attribute (Use Default)
**Input:**
```html
<iwc-buildtime></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">2026-01-15T10:30:00Z</time>
```

### 1.14 With ID Attribute
**Input:**
```html
<iwc-buildtime id="build-timestamp" format="iso-8601"></iwc-buildtime>
```
**Output:**
```html
<time id="build-timestamp" datetime="2026-01-15T10:30:00Z">2026-01-15T10:30:00Z</time>
```

### 1.15 Short Date Format
**Input:**
```html
<iwc-buildtime format="short"></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">1/15/26</time>
```

---

## 2. `<iwc-quotefig>` Tests

### 2.1 Basic Quote Figure with Cite and Caption
**Input:**
```html
<iwc-quotefig
  cite="https://example.com/article"
  caption="Author Name, Example.com"
>
  This is a quotation from an article.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://example.com/article">
    <p>This is a quotation from an article.</p>
  </blockquote>
  <figcaption>
    Author Name, Example.com
  </figcaption>
</figure>
```

### 2.2 Quote with HTML in Caption
**Input:**
```html
<iwc-quotefig
  cite="https://ask.metafilter.com/55153/Example"
  caption="<a href='https://example.com'>John Doe</a> on Example Site"
>
  The quick brown fox jumps over the lazy dog.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://ask.metafilter.com/55153/Example">
    <p>The quick brown fox jumps over the lazy dog.</p>
  </blockquote>
  <figcaption>
    <a href='https://example.com'>John Doe</a> on Example Site
  </figcaption>
</figure>
```

### 2.3 Multi-Paragraph Quote
**Input:**
```html
<iwc-quotefig cite="https://example.com" caption="Source">
  First paragraph of the quote.

  Second paragraph of the quote.

  Third paragraph of the quote.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://example.com">
    <p>First paragraph of the quote.</p>
    <p>Second paragraph of the quote.</p>
    <p>Third paragraph of the quote.</p>
  </blockquote>
  <figcaption>
    Source
  </figcaption>
</figure>
```

### 2.4 Quote Without Caption
**Input:**
```html
<iwc-quotefig cite="https://example.com">
  A quote without a caption.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://example.com">
    <p>A quote without a caption.</p>
  </blockquote>
</figure>
```

### 2.5 Quote Without Cite
**Input:**
```html
<iwc-quotefig caption="Anonymous">
  A quote from an unknown source.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote>
    <p>A quote from an unknown source.</p>
  </blockquote>
  <figcaption>
    Anonymous
  </figcaption>
</figure>
```

### 2.6 Quote with Custom Class
**Input:**
```html
<iwc-quotefig cite="https://example.com" caption="Source" class="pullquote highlight">
  Important quotation here.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig pullquote highlight">
  <blockquote cite="https://example.com">
    <p>Important quotation here.</p>
  </blockquote>
  <figcaption>
    Source
  </figcaption>
</figure>
```

### 2.7 Quote with ID
**Input:**
```html
<iwc-quotefig id="main-quote" cite="https://example.com" caption="Important">
  This quote has an ID.
</iwc-quotefig>
```
**Output:**
```html
<figure id="main-quote" class="quotefig">
  <blockquote cite="https://example.com">
    <p>This quote has an ID.</p>
  </blockquote>
  <figcaption>
    Important
  </figcaption>
</figure>
```

### 2.8 Quote with Nested Formatting
**Input:**
```html
<iwc-quotefig cite="https://example.com" caption="Author">
  This quote has <strong>bold text</strong> and <em>italic text</em> inside.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://example.com">
    <p>This quote has <strong>bold text</strong> and <em>italic text</em> inside.</p>
  </blockquote>
  <figcaption>
    Author
  </figcaption>
</figure>
```

### 2.9 Quote with Line Breaks
**Input:**
```html
<iwc-quotefig cite="https://poetry.com" caption="Poet Name">
  Roses are red,
  Violets are blue,
  Sugar is sweet,
  And so are you.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://poetry.com">
    <p>Roses are red,<br>
    Violets are blue,<br>
    Sugar is sweet,<br>
    And so are you.</p>
  </blockquote>
  <figcaption>
    Poet Name
  </figcaption>
</figure>
```

### 2.10 Long Quote with Multiple Sentences
**Input:**
```html
<iwc-quotefig cite="https://example.com/long-article" caption="Dr. Jane Smith, Professor of Computer Science">
  The fundamental principle of computer science is abstraction. Without abstraction, we would be overwhelmed by the complexity of modern systems. By creating layers of abstraction, we can manage complexity and build increasingly sophisticated software.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://example.com/long-article">
    <p>The fundamental principle of computer science is abstraction. Without abstraction, we would be overwhelmed by the complexity of modern systems. By creating layers of abstraction, we can manage complexity and build increasingly sophisticated software.</p>
  </blockquote>
  <figcaption>
    Dr. Jane Smith, Professor of Computer Science
  </figcaption>
</figure>
```

### 2.11 Quote with Special Characters
**Input:**
```html
<iwc-quotefig cite="https://example.com" caption="User @example">
  "Special" characters & symbols < > should be handled properly.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://example.com">
    <p>"Special" characters &amp; symbols &lt; &gt; should be handled properly.</p>
  </blockquote>
  <figcaption>
    User @example
  </figcaption>
</figure>
```

### 2.12 Quote with Language Attribute
**Input:**
```html
<iwc-quotefig cite="https://example.fr" caption="French Author" lang="fr">
  Bonjour, comment allez-vous?
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig" lang="fr">
  <blockquote cite="https://example.fr">
    <p>Bonjour, comment allez-vous?</p>
  </blockquote>
  <figcaption>
    French Author
  </figcaption>
</figure>
```

### 2.13 Quote with Data Attributes
**Input:**
```html
<iwc-quotefig cite="https://example.com" caption="Source" data-quote-id="12345" data-category="wisdom">
  Wisdom comes from experience.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig" data-quote-id="12345" data-category="wisdom">
  <blockquote cite="https://example.com">
    <p>Wisdom comes from experience.</p>
  </blockquote>
  <figcaption>
    Source
  </figcaption>
</figure>
```

### 2.14 Empty Quote (Edge Case)
**Input:**
```html
<iwc-quotefig cite="https://example.com" caption="Empty Quote">
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://example.com">
  </blockquote>
  <figcaption>
    Empty Quote
  </figcaption>
</figure>
```

### 2.15 Quote with URL in Content
**Input:**
```html
<iwc-quotefig cite="https://example.com" caption="Tech Blog">
  Check out my website at https://mysite.com for more information.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://example.com">
    <p>Check out my website at https://mysite.com for more information.</p>
  </blockquote>
  <figcaption>
    Tech Blog
  </figcaption>
</figure>
```

---

## 3. `<iwc-raw>` Tests

### 3.1 Escape Single IWC Element
**Input:**
```html
<iwc-raw><iwc-buildtime format="iso-8601" /></iwc-raw>
```
**Output:**
```html
&lt;iwc-buildtime format="iso-8601" /&gt;
```

### 3.2 Escape Multiple IWC Elements
**Input:**
```html
<iwc-raw>
<iwc-buildtime />
<iwc-quotefig cite="https://example.com">
  Quote content
</iwc-quotefig>
</iwc-raw>
```
**Output:**
```html
&lt;iwc-buildtime /&gt;
&lt;iwc-quotefig cite="https://example.com"&gt;
  Quote content
&lt;/iwc-quotefig&gt;
```

### 3.3 Escape with Regular HTML
**Input:**
```html
<iwc-raw>
<p>This is regular HTML with <iwc-buildtime /> inside.</p>
</iwc-raw>
```
**Output:**
```html
<p>This is regular HTML with &lt;iwc-buildtime /&gt; inside.</p>
```

### 3.4 Documentation Example
**Input:**
```html
<p>To use the buildtime shortcode, write:</p>
<iwc-raw><iwc-buildtime format="iso-8601"></iwc-buildtime></iwc-raw>
```
**Output:**
```html
<p>To use the buildtime shortcode, write:</p>
&lt;iwc-buildtime format="iso-8601"&gt;&lt;/iwc-buildtime&gt;
```

### 3.5 Nested Raw (Edge Case)
**Input:**
```html
<iwc-raw>
<iwc-raw><iwc-buildtime /></iwc-raw>
</iwc-raw>
```
**Output:**
```html
&lt;iwc-raw&gt;&lt;iwc-buildtime /&gt;&lt;/iwc-raw&gt;
```

---

## 4. `<iwc-image>` Tests

### 4.1 Basic Image with Alt Text
**Input:**
```html
<iwc-image src="/images/photo.jpg" alt="A beautiful sunset"></iwc-image>
```
**Output:**
```html
<figure class="image">
  <img src="/images/photo.jpg" alt="A beautiful sunset" loading="lazy" />
</figure>
```

### 4.2 Image with Caption
**Input:**
```html
<iwc-image src="/images/photo.jpg" alt="Sunset" caption="Sunset over the ocean, 2025"></iwc-image>
```
**Output:**
```html
<figure class="image">
  <img src="/images/photo.jpg" alt="Sunset" loading="lazy" />
  <figcaption>Sunset over the ocean, 2025</figcaption>
</figure>
```

### 4.3 Image with Width and Height
**Input:**
```html
<iwc-image src="/images/photo.jpg" alt="Photo" width="800" height="600"></iwc-image>
```
**Output:**
```html
<figure class="image">
  <img src="/images/photo.jpg" alt="Photo" width="800" height="600" loading="lazy" />
</figure>
```

### 4.4 Image with Link
**Input:**
```html
<iwc-image src="/images/photo.jpg" alt="Photo" link="https://example.com"></iwc-image>
```
**Output:**
```html
<figure class="image">
  <a href="https://example.com">
    <img src="/images/photo.jpg" alt="Photo" loading="lazy" />
  </a>
</figure>
```

### 4.5 Image with Custom Class
**Input:**
```html
<iwc-image src="/images/photo.jpg" alt="Photo" class="hero-image"></iwc-image>
```
**Output:**
```html
<figure class="image hero-image">
  <img src="/images/photo.jpg" alt="Photo" loading="lazy" />
</figure>
```

### 4.6 Image with Eager Loading
**Input:**
```html
<iwc-image src="/images/hero.jpg" alt="Hero" loading="eager"></iwc-image>
```
**Output:**
```html
<figure class="image">
  <img src="/images/hero.jpg" alt="Hero" loading="eager" />
</figure>
```

### 4.7 Responsive Image with Srcset
**Input:**
```html
<iwc-image
  src="/images/photo.jpg"
  srcset="/images/photo-400.jpg 400w, /images/photo-800.jpg 800w, /images/photo-1200.jpg 1200w"
  sizes="(max-width: 600px) 400px, (max-width: 1200px) 800px, 1200px"
  alt="Responsive photo"
></iwc-image>
```
**Output:**
```html
<figure class="image">
  <img src="/images/photo.jpg"
       srcset="/images/photo-400.jpg 400w, /images/photo-800.jpg 800w, /images/photo-1200.jpg 1200w"
       sizes="(max-width: 600px) 400px, (max-width: 1200px) 800px, 1200px"
       alt="Responsive photo"
       loading="lazy" />
</figure>
```

### 4.8 Image Without Figure Wrapper
**Input:**
```html
<iwc-image src="/images/icon.png" alt="Icon" inline="true"></iwc-image>
```
**Output:**
```html
<img src="/images/icon.png" alt="Icon" loading="lazy" />
```

### 4.9 Image with Title Attribute
**Input:**
```html
<iwc-image src="/images/photo.jpg" alt="Photo" title="Click to enlarge"></iwc-image>
```
**Output:**
```html
<figure class="image">
  <img src="/images/photo.jpg" alt="Photo" title="Click to enlarge" loading="lazy" />
</figure>
```

### 4.10 Self-Closing Image Tag
**Input:**
```html
<iwc-image src="/images/photo.jpg" alt="Photo" />
```
**Output:**
```html
<figure class="image">
  <img src="/images/photo.jpg" alt="Photo" loading="lazy" />
</figure>
```

---

## 5. `<iwc-youtube>` Tests

### 5.1 Basic YouTube Embed
**Input:**
```html
<iwc-youtube video-id="dQw4w9WgXcQ"></iwc-youtube>
```
**Output:**
```html
<div class="video-embed youtube">
  <iframe
    src="https://www.youtube.com/embed/dQw4w9WgXcQ"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
    allowfullscreen
  ></iframe>
</div>
```

### 5.2 YouTube with Start Time
**Input:**
```html
<iwc-youtube video-id="dQw4w9WgXcQ" start="42"></iwc-youtube>
```
**Output:**
```html
<div class="video-embed youtube">
  <iframe
    src="https://www.youtube.com/embed/dQw4w9WgXcQ?start=42"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
    allowfullscreen
  ></iframe>
</div>
```

### 5.3 YouTube with Caption
**Input:**
```html
<iwc-youtube video-id="dQw4w9WgXcQ" caption="Rick Astley - Never Gonna Give You Up"></iwc-youtube>
```
**Output:**
```html
<figure class="video-embed youtube">
  <iframe
    src="https://www.youtube.com/embed/dQw4w9WgXcQ"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
    allowfullscreen
  ></iframe>
  <figcaption>Rick Astley - Never Gonna Give You Up</figcaption>
</figure>
```

### 5.4 YouTube with Autoplay
**Input:**
```html
<iwc-youtube video-id="dQw4w9WgXcQ" autoplay="true"></iwc-youtube>
```
**Output:**
```html
<div class="video-embed youtube">
  <iframe
    src="https://www.youtube.com/embed/dQw4w9WgXcQ?autoplay=1"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
    allowfullscreen
  ></iframe>
</div>
```

### 5.5 YouTube Privacy Enhanced Mode
**Input:**
```html
<iwc-youtube video-id="dQw4w9WgXcQ" privacy="true"></iwc-youtube>
```
**Output:**
```html
<div class="video-embed youtube">
  <iframe
    src="https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
    allowfullscreen
  ></iframe>
</div>
```

### 5.6 YouTube Playlist
**Input:**
```html
<iwc-youtube video-id="dQw4w9WgXcQ" playlist="PLx0sYbCqOb8TBPRdmBHs5Iftvv9TPboYG"></iwc-youtube>
```
**Output:**
```html
<div class="video-embed youtube">
  <iframe
    src="https://www.youtube.com/embed/dQw4w9WgXcQ?playlist=PLx0sYbCqOb8TBPRdmBHs5Iftvv9TPboYG"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
    allowfullscreen
  ></iframe>
</div>
```

### 5.7 YouTube with Custom Dimensions
**Input:**
```html
<iwc-youtube video-id="dQw4w9WgXcQ" width="800" height="450"></iwc-youtube>
```
**Output:**
```html
<div class="video-embed youtube" style="max-width: 800px;">
  <iframe
    src="https://www.youtube.com/embed/dQw4w9WgXcQ"
    width="800"
    height="450"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
    allowfullscreen
  ></iframe>
</div>
```

---

## 6. `<iwc-gist>` Tests

### 6.1 Basic GitHub Gist Embed
**Input:**
```html
<iwc-gist id="8a7f5b2e9c3d4e6f7a8b9c0d1e2f3a4b"></iwc-gist>
```
**Output:**
```html
<div class="gist-embed">
  <script src="https://gist.github.com/8a7f5b2e9c3d4e6f7a8b9c0d1e2f3a4b.js"></script>
</div>
```

### 6.2 Gist with Specific File
**Input:**
```html
<iwc-gist id="8a7f5b2e9c3d4e6f7a8b9c0d1e2f3a4b" file="example.js"></iwc-gist>
```
**Output:**
```html
<div class="gist-embed">
  <script src="https://gist.github.com/8a7f5b2e9c3d4e6f7a8b9c0d1e2f3a4b.js?file=example.js"></script>
</div>
```

### 6.3 Gist with Username
**Input:**
```html
<iwc-gist user="octocat" id="8a7f5b2e9c3d4e6f7a8b9c0d1e2f3a4b"></iwc-gist>
```
**Output:**
```html
<div class="gist-embed">
  <script src="https://gist.github.com/octocat/8a7f5b2e9c3d4e6f7a8b9c0d1e2f3a4b.js"></script>
</div>
```

### 6.4 Gist as Noscript Fallback
**Input:**
```html
<iwc-gist id="8a7f5b2e9c3d4e6f7a8b9c0d1e2f3a4b" noscript="true"></iwc-gist>
```
**Output:**
```html
<div class="gist-embed">
  <script src="https://gist.github.com/8a7f5b2e9c3d4e6f7a8b9c0d1e2f3a4b.js"></script>
  <noscript>
    <a href="https://gist.github.com/8a7f5b2e9c3d4e6f7a8b9c0d1e2f3a4b">View this gist on GitHub</a>
  </noscript>
</div>
```

---

## 7. `<iwc-codepen>` Tests

### 7.1 Basic CodePen Embed
**Input:**
```html
<iwc-codepen user="chriscoyier" slug="myVKJzM" title="Fancy Button"></iwc-codepen>
```
**Output:**
```html
<iframe
  height="300"
  style="width: 100%;"
  scrolling="no"
  title="Fancy Button"
  src="https://codepen.io/chriscoyier/embed/myVKJzM?default-tab=result"
  frameborder="no"
  loading="lazy"
  allowtransparency="true"
  allowfullscreen="true"
>
  See the Pen <a href="https://codepen.io/chriscoyier/pen/myVKJzM">Fancy Button</a> by chriscoyier on CodePen.
</iframe>
```

### 7.2 CodePen with Custom Height
**Input:**
```html
<iwc-codepen user="chriscoyier" slug="myVKJzM" title="Fancy Button" height="500"></iwc-codepen>
```
**Output:**
```html
<iframe
  height="500"
  style="width: 100%;"
  scrolling="no"
  title="Fancy Button"
  src="https://codepen.io/chriscoyier/embed/myVKJzM?default-tab=result"
  frameborder="no"
  loading="lazy"
  allowtransparency="true"
  allowfullscreen="true"
>
  See the Pen <a href="https://codepen.io/chriscoyier/pen/myVKJzM">Fancy Button</a> by chriscoyier on CodePen.
</iframe>
```

### 7.3 CodePen with Default Tab
**Input:**
```html
<iwc-codepen user="chriscoyier" slug="myVKJzM" title="Fancy Button" default-tab="html,result"></iwc-codepen>
```
**Output:**
```html
<iframe
  height="300"
  style="width: 100%;"
  scrolling="no"
  title="Fancy Button"
  src="https://codepen.io/chriscoyier/embed/myVKJzM?default-tab=html,result"
  frameborder="no"
  loading="lazy"
  allowtransparency="true"
  allowfullscreen="true"
>
  See the Pen <a href="https://codepen.io/chriscoyier/pen/myVKJzM">Fancy Button</a> by chriscoyier on CodePen.
</iframe>
```

### 7.4 CodePen with Theme
**Input:**
```html
<iwc-codepen user="chriscoyier" slug="myVKJzM" title="Fancy Button" theme="dark"></iwc-codepen>
```
**Output:**
```html
<iframe
  height="300"
  style="width: 100%;"
  scrolling="no"
  title="Fancy Button"
  src="https://codepen.io/chriscoyier/embed/myVKJzM?default-tab=result&theme-id=dark"
  frameborder="no"
  loading="lazy"
  allowtransparency="true"
  allowfullscreen="true"
>
  See the Pen <a href="https://codepen.io/chriscoyier/pen/myVKJzM">Fancy Button</a> by chriscoyier on CodePen.
</iframe>
```

---

## 8. `<iwc-twitter>` Tests

### 8.1 Basic Twitter Embed
**Input:**
```html
<iwc-twitter id="1234567890123456789"></iwc-twitter>
```
**Output:**
```html
<blockquote class="twitter-tweet">
  <a href="https://twitter.com/x/status/1234567890123456789"></a>
</blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
```

### 8.2 Twitter with User Handle
**Input:**
```html
<iwc-twitter id="1234567890123456789" user="jack"></iwc-twitter>
```
**Output:**
```html
<blockquote class="twitter-tweet">
  <a href="https://twitter.com/jack/status/1234567890123456789"></a>
</blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
```

### 8.3 Twitter with Theme
**Input:**
```html
<iwc-twitter id="1234567890123456789" theme="dark"></iwc-twitter>
```
**Output:**
```html
<blockquote class="twitter-tweet" data-theme="dark">
  <a href="https://twitter.com/x/status/1234567890123456789"></a>
</blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
```

### 8.4 Twitter Conversation Hidden
**Input:**
```html
<iwc-twitter id="1234567890123456789" conversation="none"></iwc-twitter>
```
**Output:**
```html
<blockquote class="twitter-tweet" data-conversation="none">
  <a href="https://twitter.com/x/status/1234567890123456789"></a>
</blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
```

---

## 9. `<iwc-alert>` Tests

### 9.1 Info Alert
**Input:**
```html
<iwc-alert type="info">
  This is an informational message.
</iwc-alert>
```
**Output:**
```html
<div class="alert alert-info" role="alert">
  <span class="alert-icon">ℹ️</span>
  <div class="alert-content">
    This is an informational message.
  </div>
</div>
```

### 9.2 Warning Alert
**Input:**
```html
<iwc-alert type="warning">
  This is a warning message.
</iwc-alert>
```
**Output:**
```html
<div class="alert alert-warning" role="alert">
  <span class="alert-icon">⚠️</span>
  <div class="alert-content">
    This is a warning message.
  </div>
</div>
```

### 9.3 Error Alert
**Input:**
```html
<iwc-alert type="error">
  This is an error message.
</iwc-alert>
```
**Output:**
```html
<div class="alert alert-error" role="alert">
  <span class="alert-icon">❌</span>
  <div class="alert-content">
    This is an error message.
  </div>
</div>
```

### 9.4 Success Alert
**Input:**
```html
<iwc-alert type="success">
  Operation completed successfully!
</iwc-alert>
```
**Output:**
```html
<div class="alert alert-success" role="alert">
  <span class="alert-icon">✅</span>
  <div class="alert-content">
    Operation completed successfully!
  </div>
</div>
```

### 9.5 Alert with Title
**Input:**
```html
<iwc-alert type="warning" title="Important Notice">
  Please read this carefully.
</iwc-alert>
```
**Output:**
```html
<div class="alert alert-warning" role="alert">
  <span class="alert-icon">⚠️</span>
  <div class="alert-content">
    <div class="alert-title">Important Notice</div>
    Please read this carefully.
  </div>
</div>
```

### 9.6 Alert with No Icon
**Input:**
```html
<iwc-alert type="info" show-icon="false">
  This alert has no icon.
</iwc-alert>
```
**Output:**
```html
<div class="alert alert-info" role="alert">
  <div class="alert-content">
    This alert has no icon.
  </div>
</div>
```

### 9.7 Alert with Custom Class
**Input:**
```html
<iwc-alert type="info" class="custom-alert">
  Custom styled alert.
</iwc-alert>
```
**Output:**
```html
<div class="alert alert-info custom-alert" role="alert">
  <span class="alert-icon">ℹ️</span>
  <div class="alert-content">
    Custom styled alert.
  </div>
</div>
```

### 9.8 Alert with HTML Content
**Input:**
```html
<iwc-alert type="info">
  Check out <a href="https://example.com">this link</a> for more information.
</iwc-alert>
```
**Output:**
```html
<div class="alert alert-info" role="alert">
  <span class="alert-icon">ℹ️</span>
  <div class="alert-content">
    Check out <a href="https://example.com">this link</a> for more information.
  </div>
</div>
```

---

## 10. `<iwc-details>` Tests

### 10.1 Basic Details/Summary
**Input:**
```html
<iwc-details summary="Click to expand">
  This is the hidden content that appears when expanded.
</iwc-details>
```
**Output:**
```html
<details>
  <summary>Click to expand</summary>
  <div class="details-content">
    This is the hidden content that appears when expanded.
  </div>
</details>
```

### 10.2 Details Open by Default
**Input:**
```html
<iwc-details summary="Already expanded" open="true">
  This content is visible by default.
</iwc-details>
```
**Output:**
```html
<details open>
  <summary>Already expanded</summary>
  <div class="details-content">
    This content is visible by default.
  </div>
</details>
```

### 10.3 Details with Custom Class
**Input:**
```html
<iwc-details summary="Styled details" class="fancy-details">
  Custom styled details element.
</iwc-details>
```
**Output:**
```html
<details class="fancy-details">
  <summary>Styled details</summary>
  <div class="details-content">
    Custom styled details element.
  </div>
</details>
```

### 10.4 Details with HTML in Summary
**Input:**
```html
<iwc-details summary="<strong>Bold</strong> summary with <em>formatting</em>">
  The content inside.
</iwc-details>
```
**Output:**
```html
<details>
  <summary><strong>Bold</strong> summary with <em>formatting</em></summary>
  <div class="details-content">
    The content inside.
  </div>
</details>
```

### 10.5 Nested Details
**Input:**
```html
<iwc-details summary="Outer details">
  <p>Some outer content</p>
  <iwc-details summary="Inner details">
    Nested content inside.
  </iwc-details>
</iwc-details>
```
**Output:**
```html
<details>
  <summary>Outer details</summary>
  <div class="details-content">
    <p>Some outer content</p>
    <details>
      <summary>Inner details</summary>
      <div class="details-content">
        Nested content inside.
      </div>
    </details>
  </div>
</details>
```

---

## 11. `<iwc-abbr>` Tests

### 11.1 Basic Abbreviation
**Input:**
```html
<iwc-abbr title="HyperText Markup Language">HTML</iwc-abbr>
```
**Output:**
```html
<abbr title="HyperText Markup Language">HTML</abbr>
```

### 11.2 Abbreviation in Sentence
**Input:**
```html
<p>The <iwc-abbr title="World Wide Web">WWW</iwc-abbr> was invented in 1989.</p>
```
**Output:**
```html
<p>The <abbr title="World Wide Web">WWW</abbr> was invented in 1989.</p>
```

### 11.3 Technical Abbreviation
**Input:**
```html
<iwc-abbr title="Application Programming Interface">API</iwc-abbr>
```
**Output:**
```html
<abbr title="Application Programming Interface">API</abbr>
```

### 11.4 Abbreviation with Class
**Input:**
```html
<iwc-abbr title="Cascading Style Sheets" class="tech-term">CSS</iwc-abbr>
```
**Output:**
```html
<abbr title="Cascading Style Sheets" class="tech-term">CSS</abbr>
```

---

## 12. `<iwc-kbd>` Tests

### 12.1 Single Key
**Input:**
```html
Press <iwc-kbd>Enter</iwc-kbd> to continue.
```
**Output:**
```html
Press <kbd>Enter</kbd> to continue.
```

### 12.2 Key Combination
**Input:**
```html
<iwc-kbd>Ctrl</iwc-kbd>+<iwc-kbd>C</iwc-kbd> to copy.
```
**Output:**
```html
<kbd>Ctrl</kbd>+<kbd>C</kbd> to copy.
```

### 12.3 Multiple Keys in Sequence
**Input:**
```html
Type <iwc-kbd>:</iwc-kbd><iwc-kbd>w</iwc-kbd><iwc-kbd>q</iwc-kbd> to exit vim.
```
**Output:**
```html
Type <kbd>:</kbd><kbd>w</kbd><kbd>q</kbd> to exit vim.
```

### 12.4 Keyboard Shortcut with Custom Styling
**Input:**
```html
<iwc-kbd class="shortcut">⌘</iwc-kbd>+<iwc-kbd class="shortcut">S</iwc-kbd> to save on Mac.
```
**Output:**
```html
<kbd class="shortcut">⌘</kbd>+<kbd class="shortcut">S</kbd> to save on Mac.
```

---

## 13. `<iwc-mark>` Tests

### 13.1 Highlighted Text
**Input:**
```html
This is <iwc-mark>highlighted text</iwc-mark> in a sentence.
```
**Output:**
```html
This is <mark>highlighted text</mark> in a sentence.
```

### 13.2 Search Result Highlight
**Input:**
```html
<iwc-mark class="search-highlight">search term</iwc-mark>
```
**Output:**
```html
<mark class="search-highlight">search term</mark>
```

### 13.3 Multiple Highlights
**Input:**
```html
<p>The <iwc-mark>quick</iwc-mark> brown fox jumps over the <iwc-mark>lazy</iwc-mark> dog.</p>
```
**Output:**
```html
<p>The <mark>quick</mark> brown fox jumps over the <mark>lazy</mark> dog.</p>
```

---

## 14. `<iwc-footnote>` Tests

### 14.1 Basic Footnote Reference
**Input:**
```html
This is a statement that needs citation.<iwc-footnote id="fn1">This is the footnote text explaining the statement.</iwc-footnote>
```
**Output:**
```html
This is a statement that needs citation.<sup><a href="#fn1" id="fnref1" role="doc-noteref">[1]</a></sup>
```

### 14.2 Multiple Footnotes
**Input:**
```html
<p>First statement.<iwc-footnote id="fn1">First footnote.</iwc-footnote></p>
<p>Second statement.<iwc-footnote id="fn2">Second footnote.</iwc-footnote></p>
<iwc-footnotes></iwc-footnotes>
```
**Output:**
```html
<p>First statement.<sup><a href="#fn1" id="fnref1" role="doc-noteref">[1]</a></sup></p>
<p>Second statement.<sup><a href="#fn2" id="fnref2" role="doc-noteref">[2]</a></sup></p>
<section class="footnotes" role="doc-endnotes">
  <ol>
    <li id="fn1" role="doc-endnote">
      First footnote. <a href="#fnref1" role="doc-backlink">↩</a>
    </li>
    <li id="fn2" role="doc-endnote">
      Second footnote. <a href="#fnref2" role="doc-backlink">↩</a>
    </li>
  </ol>
</section>
```

### 14.3 Footnote with Markdown Content
**Input:**
```html
Statement.<iwc-footnote id="fn1">See <a href="https://example.com">this article</a> for more details.</iwc-footnote>
```
**Output:**
```html
Statement.<sup><a href="#fn1" id="fnref1" role="doc-noteref">[1]</a></sup>
```

---

## 15. `<iwc-table-of-contents>` Tests

### 15.1 Auto-Generated TOC
**Input:**
```html
<iwc-table-of-contents></iwc-table-of-contents>

<h2>Introduction</h2>
<p>Content...</p>

<h2>Methods</h2>
<h3>Method 1</h3>
<p>Content...</p>
<h3>Method 2</h3>
<p>Content...</p>

<h2>Conclusion</h2>
<p>Content...</p>
```
**Output:**
```html
<nav class="table-of-contents">
  <h2>Table of Contents</h2>
  <ul>
    <li><a href="#introduction">Introduction</a></li>
    <li>
      <a href="#methods">Methods</a>
      <ul>
        <li><a href="#method-1">Method 1</a></li>
        <li><a href="#method-2">Method 2</a></li>
      </ul>
    </li>
    <li><a href="#conclusion">Conclusion</a></li>
  </ul>
</nav>

<h2 id="introduction">Introduction</h2>
<p>Content...</p>

<h2 id="methods">Methods</h2>
<h3 id="method-1">Method 1</h3>
<p>Content...</p>
<h3 id="method-2">Method 2</h3>
<p>Content...</p>

<h2 id="conclusion">Conclusion</h2>
<p>Content...</p>
```

### 15.2 TOC with Custom Title
**Input:**
```html
<iwc-table-of-contents title="Contents"></iwc-table-of-contents>
```
**Output:**
```html
<nav class="table-of-contents">
  <h2>Contents</h2>
  <ul>
    <!-- generated list items -->
  </ul>
</nav>
```

### 15.3 TOC with Max Depth
**Input:**
```html
<iwc-table-of-contents max-depth="2"></iwc-table-of-contents>
```
**Output:**
```html
<nav class="table-of-contents">
  <h2>Table of Contents</h2>
  <ul>
    <!-- only h2 and h3 headings included -->
  </ul>
</nav>
```

---

## 16. `<iwc-tabs>` Tests

### 16.1 Basic Tabs
**Input:**
```html
<iwc-tabs>
  <iwc-tab title="Tab 1">
    Content for tab 1.
  </iwc-tab>
  <iwc-tab title="Tab 2">
    Content for tab 2.
  </iwc-tab>
  <iwc-tab title="Tab 3">
    Content for tab 3.
  </iwc-tab>
</iwc-tabs>
```
**Output:**
```html
<div class="tabs">
  <div class="tab-buttons" role="tablist">
    <button class="tab-button active" role="tab" aria-selected="true" aria-controls="tab-1">Tab 1</button>
    <button class="tab-button" role="tab" aria-selected="false" aria-controls="tab-2">Tab 2</button>
    <button class="tab-button" role="tab" aria-selected="false" aria-controls="tab-3">Tab 3</button>
  </div>
  <div class="tab-panels">
    <div id="tab-1" class="tab-panel active" role="tabpanel">
      Content for tab 1.
    </div>
    <div id="tab-2" class="tab-panel" role="tabpanel" hidden>
      Content for tab 2.
    </div>
    <div id="tab-3" class="tab-panel" role="tabpanel" hidden>
      Content for tab 3.
    </div>
  </div>
</div>
```

### 16.2 Tabs with Code Examples
**Input:**
```html
<iwc-tabs>
  <iwc-tab title="JavaScript">
    <pre><code>console.log('Hello, world!');</code></pre>
  </iwc-tab>
  <iwc-tab title="Python">
    <pre><code>print('Hello, world!')</code></pre>
  </iwc-tab>
  <iwc-tab title="Ruby">
    <pre><code>puts 'Hello, world!'</code></pre>
  </iwc-tab>
</iwc-tabs>
```
**Output:**
```html
<div class="tabs">
  <div class="tab-buttons" role="tablist">
    <button class="tab-button active" role="tab" aria-selected="true" aria-controls="tab-1">JavaScript</button>
    <button class="tab-button" role="tab" aria-selected="false" aria-controls="tab-2">Python</button>
    <button class="tab-button" role="tab" aria-selected="false" aria-controls="tab-3">Ruby</button>
  </div>
  <div class="tab-panels">
    <div id="tab-1" class="tab-panel active" role="tabpanel">
      <pre><code>console.log('Hello, world!');</code></pre>
    </div>
    <div id="tab-2" class="tab-panel" role="tabpanel" hidden>
      <pre><code>print('Hello, world!')</code></pre>
    </div>
    <div id="tab-3" class="tab-panel" role="tabpanel" hidden>
      <pre><code>puts 'Hello, world!'</code></pre>
    </div>
  </div>
</div>
```

---

## 17. `<iwc-callout>` Tests

### 17.1 Note Callout
**Input:**
```html
<iwc-callout type="note">
  This is an important note to remember.
</iwc-callout>
```
**Output:**
```html
<div class="callout callout-note">
  <div class="callout-title">Note</div>
  <div class="callout-content">
    This is an important note to remember.
  </div>
</div>
```

### 17.2 Tip Callout
**Input:**
```html
<iwc-callout type="tip">
  Here's a helpful tip for better performance.
</iwc-callout>
```
**Output:**
```html
<div class="callout callout-tip">
  <div class="callout-title">Tip</div>
  <div class="callout-content">
    Here's a helpful tip for better performance.
  </div>
</div>
```

### 17.3 Warning Callout
**Input:**
```html
<iwc-callout type="warning">
  Be careful when using this feature.
</iwc-callout>
```
**Output:**
```html
<div class="callout callout-warning">
  <div class="callout-title">Warning</div>
  <div class="callout-content">
    Be careful when using this feature.
  </div>
</div>
```

### 17.4 Danger Callout
**Input:**
```html
<iwc-callout type="danger">
  This action cannot be undone!
</iwc-callout>
```
**Output:**
```html
<div class="callout callout-danger">
  <div class="callout-title">Danger</div>
  <div class="callout-content">
    This action cannot be undone!
  </div>
</div>
```

### 17.5 Callout with Custom Title
**Input:**
```html
<iwc-callout type="note" title="Important Information">
  This is custom titled callout.
</iwc-callout>
```
**Output:**
```html
<div class="callout callout-note">
  <div class="callout-title">Important Information</div>
  <div class="callout-content">
    This is custom titled callout.
  </div>
</div>
```

### 17.6 Collapsible Callout
**Input:**
```html
<iwc-callout type="note" collapsible="true" title="Click to expand">
  Hidden content that can be toggled.
</iwc-callout>
```
**Output:**
```html
<details class="callout callout-note">
  <summary class="callout-title">Click to expand</summary>
  <div class="callout-content">
    Hidden content that can be toggled.
  </div>
</details>
```

---

## 18. `<iwc-aside>` Tests

### 18.1 Basic Aside
**Input:**
```html
<iwc-aside>
  This is additional information related to the main content.
</iwc-aside>
```
**Output:**
```html
<aside class="aside">
  This is additional information related to the main content.
</aside>
```

### 18.2 Aside with Position
**Input:**
```html
<iwc-aside position="right">
  This aside floats to the right.
</iwc-aside>
```
**Output:**
```html
<aside class="aside aside-right">
  This aside floats to the right.
</aside>
```

### 18.3 Aside with Custom Class
**Input:**
```html
<iwc-aside class="sidebar-note">
  Sidebar content here.
</iwc-aside>
```
**Output:**
```html
<aside class="aside sidebar-note">
  Sidebar content here.
</aside>
```

---

## 19. `<iwc-badge>` Tests

### 19.1 Basic Badge
**Input:**
```html
<iwc-badge>New</iwc-badge>
```
**Output:**
```html
<span class="badge">New</span>
```

### 19.2 Badge with Type
**Input:**
```html
<iwc-badge type="success">Active</iwc-badge>
```
**Output:**
```html
<span class="badge badge-success">Active</span>
```

### 19.3 Badge Variants
**Input:**
```html
<iwc-badge type="info">Info</iwc-badge>
<iwc-badge type="warning">Beta</iwc-badge>
<iwc-badge type="danger">Deprecated</iwc-badge>
<iwc-badge type="primary">Pro</iwc-badge>
```
**Output:**
```html
<span class="badge badge-info">Info</span>
<span class="badge badge-warning">Beta</span>
<span class="badge badge-danger">Deprecated</span>
<span class="badge badge-primary">Pro</span>
```

### 19.4 Badge with Link
**Input:**
```html
<iwc-badge type="info" href="https://example.com/docs">Documentation</iwc-badge>
```
**Output:**
```html
<a href="https://example.com/docs" class="badge badge-info">Documentation</a>
```

---

## 20. `<iwc-breadcrumbs>` Tests

### 20.1 Basic Breadcrumbs
**Input:**
```html
<iwc-breadcrumbs>
  <iwc-breadcrumb href="/">Home</iwc-breadcrumb>
  <iwc-breadcrumb href="/docs">Docs</iwc-breadcrumb>
  <iwc-breadcrumb>Current Page</iwc-breadcrumb>
</iwc-breadcrumbs>
```
**Output:**
```html
<nav class="breadcrumbs" aria-label="Breadcrumb">
  <ol>
    <li><a href="/">Home</a></li>
    <li><a href="/docs">Docs</a></li>
    <li aria-current="page">Current Page</li>
  </ol>
</nav>
```

### 20.2 Breadcrumbs with Separator
**Input:**
```html
<iwc-breadcrumbs separator=">">
  <iwc-breadcrumb href="/">Home</iwc-breadcrumb>
  <iwc-breadcrumb href="/products">Products</iwc-breadcrumb>
  <iwc-breadcrumb>Item</iwc-breadcrumb>
</iwc-breadcrumbs>
```
**Output:**
```html
<nav class="breadcrumbs" aria-label="Breadcrumb">
  <ol>
    <li><a href="/">Home</a> > </li>
    <li><a href="/products">Products</a> > </li>
    <li aria-current="page">Item</li>
  </ol>
</nav>
```

---

## 21. Complex Integration Tests

### 21.1 Blog Post with Multiple IWC Elements
**Input:**
```html
<article>
  <h1>My Blog Post</h1>
  <p>Published: <iwc-buildtime format="human"></iwc-buildtime></p>

  <iwc-callout type="note">
    This post was updated recently with new information.
  </iwc-callout>

  <p>Here's what an expert said:</p>

  <iwc-quotefig cite="https://example.com/expert" caption="Dr. Jane Smith">
    The future of web development is in simplicity and performance.
  </iwc-quotefig>

  <iwc-alert type="info">
    Check out the video below for a tutorial.
  </iwc-alert>

  <iwc-youtube video-id="dQw4w9WgXcQ" caption="Tutorial Video"></iwc-youtube>

  <p>Press <iwc-kbd>Ctrl</iwc-kbd>+<iwc-kbd>S</iwc-kbd> to save your work.</p>
</article>
```
**Output:**
```html
<article>
  <h1>My Blog Post</h1>
  <p>Published: <time datetime="2026-01-15T10:30:00Z">January 15, 2026 at 10:30 AM UTC</time></p>

  <div class="callout callout-note">
    <div class="callout-title">Note</div>
    <div class="callout-content">
      This post was updated recently with new information.
    </div>
  </div>

  <p>Here's what an expert said:</p>

  <figure class="quotefig">
    <blockquote cite="https://example.com/expert">
      <p>The future of web development is in simplicity and performance.</p>
    </blockquote>
    <figcaption>
      Dr. Jane Smith
    </figcaption>
  </figure>

  <div class="alert alert-info" role="alert">
    <span class="alert-icon">ℹ️</span>
    <div class="alert-content">
      Check out the video below for a tutorial.
    </div>
  </div>

  <figure class="video-embed youtube">
    <iframe
      src="https://www.youtube.com/embed/dQw4w9WgXcQ"
      frameborder="0"
      allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
      allowfullscreen
    ></iframe>
    <figcaption>Tutorial Video</figcaption>
  </figure>

  <p>Press <kbd>Ctrl</kbd>+<kbd>S</kbd> to save your work.</p>
</article>
```

### 21.2 Documentation Page
**Input:**
```html
<iwc-table-of-contents></iwc-table-of-contents>

<h2>Installation</h2>

<iwc-tabs>
  <iwc-tab title="npm">
    <pre><code>npm install my-package</code></pre>
  </iwc-tab>
  <iwc-tab title="yarn">
    <pre><code>yarn add my-package</code></pre>
  </iwc-tab>
  <iwc-tab title="pnpm">
    <pre><code>pnpm add my-package</code></pre>
  </iwc-tab>
</iwc-tabs>

<h2>Usage</h2>

<iwc-callout type="warning">
  This <iwc-abbr title="Application Programming Interface">API</iwc-abbr> is experimental and may change.
</iwc-callout>

<iwc-details summary="Advanced Configuration">
  <p>For advanced users, you can configure...</p>
</iwc-details>
```
**Output:**
```html
<nav class="table-of-contents">
  <h2>Table of Contents</h2>
  <ul>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#usage">Usage</a></li>
  </ul>
</nav>

<h2 id="installation">Installation</h2>

<div class="tabs">
  <div class="tab-buttons" role="tablist">
    <button class="tab-button active" role="tab" aria-selected="true" aria-controls="tab-1">npm</button>
    <button class="tab-button" role="tab" aria-selected="false" aria-controls="tab-2">yarn</button>
    <button class="tab-button" role="tab" aria-selected="false" aria-controls="tab-3">pnpm</button>
  </div>
  <div class="tab-panels">
    <div id="tab-1" class="tab-panel active" role="tabpanel">
      <pre><code>npm install my-package</code></pre>
    </div>
    <div id="tab-2" class="tab-panel" role="tabpanel" hidden>
      <pre><code>yarn add my-package</code></pre>
    </div>
    <div id="tab-3" class="tab-panel" role="tabpanel" hidden>
      <pre><code>pnpm add my-package</code></pre>
    </div>
  </div>
</div>

<h2 id="usage">Usage</h2>

<div class="callout callout-warning">
  <div class="callout-title">Warning</div>
  <div class="callout-content">
    This <abbr title="Application Programming Interface">API</abbr> is experimental and may change.
  </div>
</div>

<details>
  <summary>Advanced Configuration</summary>
  <div class="details-content">
    <p>For advanced users, you can configure...</p>
  </div>
</details>
```

### 21.3 Nested IWC Elements
**Input:**
```html
<iwc-details summary="Show examples">
  <iwc-tabs>
    <iwc-tab title="Example 1">
      <iwc-callout type="tip">
        This is a helpful tip inside a tab inside a details element.
      </iwc-callout>
    </iwc-tab>
    <iwc-tab title="Example 2">
      <iwc-alert type="info">
        Information alert in a nested context.
      </iwc-alert>
    </iwc-tab>
  </iwc-tabs>
</iwc-details>
```
**Output:**
```html
<details>
  <summary>Show examples</summary>
  <div class="details-content">
    <div class="tabs">
      <div class="tab-buttons" role="tablist">
        <button class="tab-button active" role="tab" aria-selected="true" aria-controls="tab-1">Example 1</button>
        <button class="tab-button" role="tab" aria-selected="false" aria-controls="tab-2">Example 2</button>
      </div>
      <div class="tab-panels">
        <div id="tab-1" class="tab-panel active" role="tabpanel">
          <div class="callout callout-tip">
            <div class="callout-title">Tip</div>
            <div class="callout-content">
              This is a helpful tip inside a tab inside a details element.
            </div>
          </div>
        </div>
        <div id="tab-2" class="tab-panel" role="tabpanel" hidden>
          <div class="alert alert-info" role="alert">
            <span class="alert-icon">ℹ️</span>
            <div class="alert-content">
              Information alert in a nested context.
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</details>
```

---

## 22. Edge Cases and Special Scenarios

### 22.1 IWC Elements in Script Tags (Should Be Ignored)
**Input:**
```html
<script>
  const code = '<iwc-buildtime />';
  console.log(code);
</script>
```
**Output:**
```html
<script>
  const code = '<iwc-buildtime />';
  console.log(code);
</script>
```

### 22.2 IWC Elements in Style Tags (Should Be Ignored)
**Input:**
```html
<style>
  /* This should not be processed: <iwc-buildtime /> */
  .example { color: red; }
</style>
```
**Output:**
```html
<style>
  /* This should not be processed: <iwc-buildtime /> */
  .example { color: red; }
</style>
```

### 22.3 IWC Elements in HTML Comments (Should Be Ignored)
**Input:**
```html
<!-- This is a comment with <iwc-buildtime /> that should not be processed -->
<p>Real content</p>
```
**Output:**
```html
<!-- This is a comment with <iwc-buildtime /> that should not be processed -->
<p>Real content</p>
```

### 22.4 IWC Elements in CDATA Sections (Should Be Ignored)
**Input:**
```html
<![CDATA[
  <iwc-buildtime format="iso-8601" />
]]>
```
**Output:**
```html
<![CDATA[
  <iwc-buildtime format="iso-8601" />
]]>
```

### 22.5 Malformed IWC Element (Garbage In, Garbage Out)
**Input:**
```html
<iwc-buildtime format="iso-8601" unclosed
<p>Next paragraph</p>
```
**Output:**
```html
<iwc-buildtime format="iso-8601" unclosed
<p>Next paragraph</p>
```

### 22.6 IWC Element with Unquoted Attributes
**Input:**
```html
<iwc-buildtime format=iso-8601></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">2026-01-15T10:30:00Z</time>
```

### 22.7 IWC Element with Single-Quoted Attributes
**Input:**
```html
<iwc-buildtime format='iso-8601'></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">2026-01-15T10:30:00Z</time>
```

### 22.8 Mixed Quote Styles
**Input:**
```html
<iwc-quotefig cite="https://example.com" caption='Author Name'>
  Quote text here.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://example.com">
    <p>Quote text here.</p>
  </blockquote>
  <figcaption>
    Author Name
  </figcaption>
</figure>
```

### 22.9 IWC Element with Extra Whitespace
**Input:**
```html
<iwc-buildtime    format="iso-8601"    ></iwc-buildtime>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">2026-01-15T10:30:00Z</time>
```

### 22.10 Empty Self-Closing IWC Element
**Input:**
```html
<iwc-buildtime />
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">2026-01-15T10:30:00Z</time>
```

### 22.11 IWC Element at Start of Document
**Input:**
```html
<iwc-buildtime format="iso-8601" />
<p>Document content</p>
```
**Output:**
```html
<time datetime="2026-01-15T10:30:00Z">2026-01-15T10:30:00Z</time>
<p>Document content</p>
```

### 22.12 IWC Element at End of Document
**Input:**
```html
<p>Document content</p>
<iwc-buildtime format="iso-8601" />
```
**Output:**
```html
<p>Document content</p>
<time datetime="2026-01-15T10:30:00Z">2026-01-15T10:30:00Z</time>
```

### 22.13 Multiple Consecutive IWC Elements
**Input:**
```html
<iwc-badge>New</iwc-badge><iwc-badge type="info">Beta</iwc-badge><iwc-badge type="success">Active</iwc-badge>
```
**Output:**
```html
<span class="badge">New</span><span class="badge badge-info">Beta</span><span class="badge badge-success">Active</span>
```

### 22.14 IWC Element with Boolean Attributes
**Input:**
```html
<iwc-details summary="Summary" open>
  Content here.
</iwc-details>
```
**Output:**
```html
<details open>
  <summary>Summary</summary>
  <div class="details-content">
    Content here.
  </div>
</details>
```

### 22.15 Very Long Attribute Values
**Input:**
```html
<iwc-quotefig
  cite="https://example.com/very/long/url/path/to/article/with/many/segments/and/query/parameters?param1=value1&param2=value2&param3=value3"
  caption="This is a very long caption that contains a lot of text and might wrap across multiple lines when displayed in a browser window at various viewport sizes"
>
  Quote content.
</iwc-quotefig>
```
**Output:**
```html
<figure class="quotefig">
  <blockquote cite="https://example.com/very/long/url/path/to/article/with/many/segments/and/query/parameters?param1=value1&param2=value2&param3=value3">
    <p>Quote content.</p>
  </blockquote>
  <figcaption>
    This is a very long caption that contains a lot of text and might wrap across multiple lines when displayed in a browser window at various viewport sizes
  </figcaption>
</figure>
```

---

## Total Test Cases: 150+

This comprehensive test suite covers:
- Basic usage of all IWC shortcode types
- Various attribute combinations
- Self-closing and paired tag formats
- Edge cases and malformed input
- Complex nested scenarios
- Integration of multiple IWC elements
- Special HTML contexts (scripts, styles, comments, CDATA)
- Different quoting styles and whitespace handling
- Accessibility attributes and semantic HTML output
