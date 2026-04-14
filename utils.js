window.PwUtils = (() => {
  function debounce(fn, delay = 400) {
    let timer = null

    return (...args) => {
      clearTimeout(timer)
      timer = setTimeout(() => fn(...args), delay)
    }
  }

  function getSiteName() {
    const host = window.location.hostname || ''
    return host.replace(/^www\./, '').split('.')[0] || ''
  }

  function getOriginKey() {
    return window.location.hostname || window.location.origin || 'unknown-site'
  }

  function isVisibleElement(el) {
    if (!el) return false

    const style = window.getComputedStyle(el)
    const rect = el.getBoundingClientRect()

    return !(
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      Number(style.opacity) === 0 ||
      rect.width <= 0 ||
      rect.height <= 0
    )
  }

  function isPasswordInput(el) {
    return (
      el &&
      el.tagName === 'INPUT' &&
      el.type === 'password' &&
      isVisibleElement(el)
    )
  }

  async function sha1Hex(text) {
    const encoder = new TextEncoder()
    const data = encoder.encode(text)
    const hashBuffer = await crypto.subtle.digest('SHA-1', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase()
  }

  function normalizePassword(text) {
    return String(text || '')
      .trim()
      .toLowerCase()
  }

  function buildPatternSignature(text) {
    const normalized = normalizePassword(text)

    if (!normalized) {
      return 'empty'
    }

    return normalized
      .replace(/[a-z]/g, 'a')
      .replace(/[0-9]/g, '9')
      .replace(/[^a-z0-9]/gi, '!')
  }

  function buildPasswordProfile(text) {
    const normalized = normalizePassword(text)

    return {
      length: normalized.length,
      signature: buildPatternSignature(normalized),
      hasUpper: /[A-Z]/.test(String(text || '')),
      hasLower: /[a-z]/.test(String(text || '')),
      hasNumber: /[0-9]/.test(String(text || '')),
      hasSpecial: /[^A-Za-z0-9]/.test(String(text || '')),
      repeated: /(.)\1\1/.test(String(text || '')),
    }
  }

  function areProfilesSimilar(profileA, profileB) {
    if (!profileA || !profileB) return false

    const sameSignature = profileA.signature === profileB.signature
    const closeLength = Math.abs(profileA.length - profileB.length) <= 2
    const sameCharacterMix =
      profileA.hasUpper === profileB.hasUpper &&
      profileA.hasLower === profileB.hasLower &&
      profileA.hasNumber === profileB.hasNumber &&
      profileA.hasSpecial === profileB.hasSpecial

    return sameSignature || (closeLength && sameCharacterMix)
  }

  return {
    debounce,
    getSiteName,
    getOriginKey,
    isVisibleElement,
    isPasswordInput,
    sha1Hex,
    normalizePassword,
    buildPatternSignature,
    buildPasswordProfile,
    areProfilesSimilar,
  }
})()
