---
layout: default
title: Tags
permalink: /tags
---

{% assign sorted_tags = site.tags | sort %}

<header class="tags-header">
    <h1 class="post-title">{{ page.title | escape }}</h1>
</header>

<div class="tags-list">
{% for tag in sorted_tags %}
<a class="post-tag" href="/tags#{{tag[0] | escape}}">{{tag[0] | escape}}</a>
{% endfor %}
</div>

{% for tag in sorted_tags %}
  <h3>{{ tag[0] }}<a name="{{ tag[0] }}"/></h3>
  <ul>
    {% assign sorted_posts = tag[1] | sort:'title' %}
    {% for post in sorted_posts %}
      <li><a href="{{ post.url }}">{{ post.title }}</a></li>
    {% endfor %}
  </ul>
{% endfor %}
