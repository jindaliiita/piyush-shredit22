for (let k in window) {
  try {
    if (typeof window[k] === 'string' && window[k].match(/CTF|flag/i)) {
      console.log(k, window[k]);
    }
  } catch {}
}
