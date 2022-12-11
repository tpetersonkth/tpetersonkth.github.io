---
layout: default
title: Tags
permalink: /tags
---

{% assign sorted_tags = site.tags | sort %}

<header class="tags-header">
    <h1 class="post-title">{{ page.title | escape }}</h1>
</header>

<div class="filter-box-div">
    <input id="filter-box" class="filter-box" placeholder="Filter...">
</div>

<div id="tags-list" class="tags-list">
    {% for tag in sorted_tags %}
        <a class="post-tag" href="/tags#{{tag[0] | escape}}">{{tag[0] | escape}}</a>
    {% endfor %}
</div>

<div id="tag-headers">
  {% for tag in sorted_tags %}
    <div>
      <h3>{{ tag[0] }}<a name="{{ tag[0] }}"/></h3>
      <ul>
        {% assign sorted_posts = tag[1] | sort:'title' %}
        {% for post in sorted_posts %}
          <li><a href="{{ post.url }}">{{ post.title }}</a></li>
        {% endfor %}
      </ul>
    </div>
  {% endfor %}
</div>

<script>
function filterTags() {
	var value = document.getElementById("filter-box").value.toLowerCase();

	var tags = document.getElementById("tags-list").children; 
	for (var i = 0; i < tags.length; i++) {
		var tag = tags[i];
		if (tag.innerText.toLowerCase().indexOf(value) == -1) {
			tag.style.display = "none";
        	} else{
			tag.style.display = "";
		}
	}

	var tagHeaders = document.getElementById("tag-headers").children;
	for (var i = 0; i < tagHeaders.length; i++) {
		var tagH = tagHeaders[i];
		if (tagH.children[0].innerText.toLowerCase().indexOf(value) == -1) {
			var display = "none";
        	} else{
			var display = "";
		}

		tagH.style.display = display;		
	}
}


(function() {
	document.getElementById("filter-box").addEventListener("keyup", filterTags);
})();

</script>
