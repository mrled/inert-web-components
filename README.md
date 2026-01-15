# inert-web-components

Inert Web Components is a concept for a library that parses HTML with custom elements and transforms it to HTML with standard components.

For example, when combined with Markdown, it might take this input:

```markdown
# Example post

Here's my post. It was built at <shortcode-buildtime format="iso-8601"></shortcode-buildtime>.

<shortcode-quotefig
  cite="https://ask.metafilter.com/55153/Whats-the-middle-ground-between-FU-and-Welcome#830421"
  caption="<a href='https://ask.metafilter.com/55153/Whats-the-middle-ground-between-FU-and-Welcome#tangerine'>tangerine on MetaFilter</a>"
>
  This is a classic case of Ask Culture meets Guess Culture....
</shortcode-quotefig>
```

And produce this output

```html
<h1>Example post</h1>

<p>Here's my post. It was built at <time datetime="2025-10-10T00:05:04-12:00">2025-10-10T00:05:04-12:00</time>.</p>

<figure class="quotefig">
  <blockquote cite="https://ask.metafilter.com/55153/Whats-the-middle-ground-between-FU-and-Welcome#830421">
    <p>This is a classic case of Ask Culture meets Guess Culture....</p>
  </blockquote>
  <figcaption>
    <a href='https://ask.metafilter.com/55153/Whats-the-middle-ground-between-FU-and-Welcome#tangerine'>tangerine on MetaFilter</a>
  </figcaption>
</figure>
```

(Note that Markdown processing is not part of the IWC idea, but it's presented here just as an example of combining the two together.)

The idea is something like "React Web Components" or "React Server Components", but done at compile time. It implies no JavaScript or CSS on the client (although nothing would stop a given IWC element from including <style> or <script> tags).

The general idea should be implemented as excellent tests with a reference implementation in some particularly well-suited language, maybe Go or something.

Originally conceived [here](https://micahrl.me/2025/10/10/idea-html-for-shortcodes/).
