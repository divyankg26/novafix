(function(){
  const frame = document.getElementById('wellnessMusicFrame');
  if (!frame) return;
  const src = 'https://open.spotify.com/embed/playlist/0AVhM00sk7M5TKVFgK5xKd?utm_source=generator&theme=0&si=386ebabff83247cd';
  if (frame.getAttribute('src') !== src) {
    frame.setAttribute('src', src);
  }
})();
