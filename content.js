;(() => {
  const {
    debounce,
    getSiteName,
    getOriginKey,
    isPasswordInput,
    sha1Hex,
    buildPasswordProfile,
    areProfilesSimilar,
  } = window.PwUtils
  const { evaluatePassword } = window.PwAnalyzer

  const PANEL_ID = 'pw-helper-panel'
  const PANEL_WIDTH = 320
  const PANEL_GAP = 12
  const STORAGE_KEY = 'pwHelperPasswordHistory'
  const MAX_HISTORY_SIZE = 50

  let panel = null
  let activeInput = null
  let latestAsyncState = {
    reused: false,
    similarReused: false,
    leaked: false,
    reuseCount: 0,
    similarReuseCount: 0,
  }
  let capsLockOn = false

  function getStorageArea() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return chrome.storage.local
    }

    return null
  }

  async function getPasswordHistory() {
    const storage = getStorageArea()
    if (!storage) return []

    const stored = await storage.get(STORAGE_KEY)
    return Array.isArray(stored[STORAGE_KEY]) ? stored[STORAGE_KEY] : []
  }

  async function setPasswordHistory(history) {
    const storage = getStorageArea()
    if (!storage) return

    await storage.set({ [STORAGE_KEY]: history })
  }

  async function savePasswordRecord(password) {
    if (!password) return

    const passwordHash = await sha1Hex(password)
    const siteKey = getOriginKey()
    const siteLabel = getSiteName() || siteKey
    const profile = buildPasswordProfile(password)

    const history = await getPasswordHistory()
    const withoutCurrentSite = history.filter((item) => item.siteKey !== siteKey)

    withoutCurrentSite.unshift({
      siteKey,
      siteLabel,
      passwordHash,
      profile,
      updatedAt: Date.now(),
    })

    await setPasswordHistory(withoutCurrentSite.slice(0, MAX_HISTORY_SIZE))
  }

  async function findReuseState(password) {
    if (!password) {
      return {
        reused: false,
        similarReused: false,
        reuseCount: 0,
        similarReuseCount: 0,
      }
    }

    const passwordHash = await sha1Hex(password)
    const currentProfile = buildPasswordProfile(password)
    const currentSiteKey = getOriginKey()
    const history = await getPasswordHistory()
    const otherSites = history.filter((item) => item.siteKey !== currentSiteKey)

    const exactMatches = otherSites.filter((item) => item.passwordHash === passwordHash)
    const similarMatches = otherSites.filter((item) => {
      if (item.passwordHash === passwordHash) return false
      return areProfilesSimilar(currentProfile, item.profile)
    })

    return {
      reused: exactMatches.length > 0,
      similarReused: similarMatches.length > 0,
      reuseCount: exactMatches.length,
      similarReuseCount: similarMatches.length,
    }
  }

  function createPanel() {
    const el = document.createElement('div')
    el.id = PANEL_ID
    el.style.display = 'none'
    el.innerHTML = `
      <div class="pw-panel-header">
        <div class="pw-panel-title">비밀번호 보안 분석</div>
        <div class="pw-panel-badge">실시간</div>
      </div>

      <div class="pw-panel-row">
        <span class="pw-label">점수</span>
        <strong id="pw-score-value">0</strong>
        <span class="pw-unit">/100</span>
      </div>

      <div class="pw-panel-row">
        <span class="pw-label">상태</span>
        <strong id="pw-status-value" class="pw-status waiting">입력 대기</strong>
      </div>

      <div class="pw-panel-section-title">확인 항목</div>
      <ul id="pw-warning-list" class="pw-warning-list">
        <li>비밀번호 입력 시 분석 시작</li>
      </ul>

      <div id="pw-extra-info" class="pw-extra-info"></div>
      <div id="pw-capslock-warning" class="pw-capslock-warning"></div>
    `
    document.body.appendChild(el)
    return el
  }

  function getPanel() {
    if (!panel) {
      panel = createPanel()
    }
    return panel
  }

  function showPanel() {
    getPanel().style.display = 'block'
  }

  function hidePanel() {
    if (panel) {
      panel.style.display = 'none'
    }
  }

  function renderResult(result, extra = {}) {
    const panelEl = getPanel()

    const scoreEl = panelEl.querySelector('#pw-score-value')
    const statusEl = panelEl.querySelector('#pw-status-value')
    const warningList = panelEl.querySelector('#pw-warning-list')
    const extraInfoEl = panelEl.querySelector('#pw-extra-info')
    const capsLockEl = panelEl.querySelector('#pw-capslock-warning')

    scoreEl.textContent = result.score
    statusEl.textContent = result.status
    statusEl.className = `pw-status ${result.statusClass}`

    warningList.innerHTML = ''
    result.warnings.forEach((text) => {
      const li = document.createElement('li')
      li.textContent = text
      warningList.appendChild(li)
    })

    const extras = []

    if (extra.reuseCount > 0) {
      extras.push(`동일 비밀번호 재사용: ${extra.reuseCount}개 사이트`)
    }

    if (extra.similarReuseCount > 0) {
      extras.push(`유사 비밀번호 반복: ${extra.similarReuseCount}개 사이트`)
    }

    if (extra.leaked === true) {
      extras.push('유출 의심: 확인 필요')
    }

    extraInfoEl.textContent = extras.join(' · ')

    if (extra.capsLockOn) {
      capsLockEl.textContent = 'Caps Lock이 켜져 있습니다.'
      capsLockEl.style.display = 'block'
    } else {
      capsLockEl.textContent = ''
      capsLockEl.style.display = 'none'
    }
  }

  function positionPanel(input) {
    const panelEl = getPanel()
    if (!input || !isPasswordInput(input)) {
      hidePanel()
      return
    }

    showPanel()

    panelEl.style.width = `${PANEL_WIDTH}px`

    const rect = input.getBoundingClientRect()
    const scrollX = window.scrollX || window.pageXOffset
    const scrollY = window.scrollY || window.pageYOffset

    const panelHeight = panelEl.offsetHeight || 180

    let left = rect.right + scrollX + PANEL_GAP
    let top = rect.top + scrollY

    const viewportRight = scrollX + window.innerWidth
    const fitsRight = left + PANEL_WIDTH <= viewportRight - 12

    if (!fitsRight) {
      left = rect.left + scrollX
      top = rect.top + scrollY - panelHeight - PANEL_GAP

      if (top < scrollY + 12) {
        top = rect.bottom + scrollY + PANEL_GAP
      }
    }

    if (left < 12) left = 12
    const maxLeft = scrollX + window.innerWidth - PANEL_WIDTH - 12
    if (left > maxLeft) left = maxLeft

    panelEl.style.left = `${left}px`
    panelEl.style.top = `${top}px`
  }

  function renderForPassword(password) {
    const result = evaluatePassword(password, {
      siteName: getSiteName(),
      reused: latestAsyncState.reused,
      similarReused: latestAsyncState.similarReused,
      leaked: latestAsyncState.leaked,
    })

    renderResult(result, {
      reuseCount: latestAsyncState.reuseCount || 0,
      similarReuseCount: latestAsyncState.similarReuseCount || 0,
      leaked: latestAsyncState.leaked,
      capsLockOn,
    })
  }

  async function runFutureChecks(password) {
    if (!password) {
      latestAsyncState = {
        reused: false,
        similarReused: false,
        leaked: false,
        reuseCount: 0,
        similarReuseCount: 0,
      }
      renderForPassword(password)
      return
    }

    const reuseState = await findReuseState(password)

    latestAsyncState = {
      ...reuseState,
      leaked: false,
    }

    renderForPassword(password)
  }

  const debouncedFutureChecks = debounce(runFutureChecks, 500)

  function activateInput(input) {
    if (!isPasswordInput(input)) return

    activeInput = input
    positionPanel(input)
    renderForPassword(input.value || '')
    debouncedFutureChecks(input.value || '')
  }

  function handleFocusIn(event) {
    const target = event.target
    if (!isPasswordInput(target)) return

    activateInput(target)
  }

  function updateCapsLockState(event) {
    const target = event.target
    if (!isPasswordInput(target)) return

    if (typeof event.getModifierState === 'function') {
      capsLockOn = event.getModifierState('CapsLock')
      renderForPassword(target.value || '')
      positionPanel(target)
    }
  }

  function handleInput(event) {
    const target = event.target
    if (!isPasswordInput(target)) return

    activeInput = target
    latestAsyncState = {
      reused: false,
      similarReused: false,
      leaked: false,
      reuseCount: 0,
      similarReuseCount: 0,
    }

    renderForPassword(target.value || '')
    positionPanel(target)
    debouncedFutureChecks(target.value || '')
  }

  function maybePersistPassword(target) {
    if (!isPasswordInput(target)) return

    const password = target.value || ''
    if (password.length < 8) return

    savePasswordRecord(password).catch(() => {})
  }

  function handleFocusOut(event) {
    const target = event.target
    if (!target || target.tagName !== 'INPUT' || target.type !== 'password') {
      return
    }

    maybePersistPassword(target)

    setTimeout(() => {
      if (!isPasswordInput(document.activeElement)) {
        hidePanel()
        activeInput = null
        capsLockOn = false
      }
    }, 80)
  }

  function handleSubmit(event) {
    const form = event.target
    if (!form || typeof form.querySelectorAll !== 'function') return

    const passwordInputs = Array.from(form.querySelectorAll('input[type="password"]'))
    passwordInputs.forEach((input) => {
      maybePersistPassword(input)
    })
  }

  function handleViewportChange() {
    if (activeInput && isPasswordInput(activeInput)) {
      positionPanel(activeInput)
    }
  }

  function init() {
    getPanel()

    document.addEventListener('focusin', handleFocusIn, true)
    document.addEventListener('input', handleInput, true)
    document.addEventListener('focusout', handleFocusOut, true)
    document.addEventListener('keydown', updateCapsLockState, true)
    document.addEventListener('keyup', updateCapsLockState, true)
    document.addEventListener('submit', handleSubmit, true)

    window.addEventListener('resize', handleViewportChange)
    window.addEventListener('scroll', handleViewportChange, true)
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true })
  } else {
    init()
  }
})()
