window.onload = function() {
	const preBlocks = document.getElementsByTagName("pre");
	const len = preBlocks.length;
	for (let i = 0; i < len; i++) {
		var block = document.getElementsByTagName("pre")[i];

		while (block.innerHTML.indexOf("@@@") !== -1){
			block.innerHTML = block.innerHTML.replace("@@@","<span class=\"highlight-attention\">").replace("@@@","</span>");
		}

		while (block.innerHTML.indexOf("@@") !== -1){
			block.innerHTML = block.innerHTML.replace("@@","<span class=\"highlight-input\">").replace("@@","</span>");
		}
	}
};
