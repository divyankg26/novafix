(function(){
  const frame = document.getElementById('wellnessMusicFrame');
  if (!frame) return;
  const src = 'https://open.spotify.com/embed/playlist/7JKDTbcB00R2kwBpLRo72r';
  if (frame.getAttribute('src') !== src) {
    frame.setAttribute('src', src);
  }
})();
