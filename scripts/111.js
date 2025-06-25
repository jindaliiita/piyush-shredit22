document.querySelectorAll('script, style, input[type=hidden]').forEach(el => {
  console.log('Element:', el.outerHTML);
});
