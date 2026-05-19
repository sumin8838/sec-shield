/**
 * content.js
 * 비밀번호 보안 분석 패널 메인 컨트롤러
 * 수정 사항: 주민번호 입력 필드 감지 및 처리 제외 로직 추가
 */

// ─── 브릿지 함수들 (외부 JS 의존성 연결) ──────────────────────────────────────
const getSiteName = () => {
  const host = window.location.hostname || ''
  const parts = host.replace(/^www\./, '').split('.')
  return parts.length >= 2 ? parts[parts.length - 2] : parts[0]
}

const isVisiblePasswordInput = (el) =>
  window.PwUtils?.isPasswordInput(el) ?? el?.type === 'password'

const normalizeAnalyzerResult = (result) => ({
  score: result?.score || 0,
  status: result?.statusClass || 'danger',
  warnings: result?.warnings || [],
})

;(function () {
  'use strict'

  // ─── 상수 및 상태 관리 ────────────────────────────────────────────────────────
  const PANEL_ID = 'pwguard-panel'
  const DEBOUNCE_DELAY = 300
  const REUSE_DELAY = 800

  let activeInput = null
  let panel = null
  let strengthDebounceTimer = null
  let reuseDebounceTimer = null
  let leakDebounceTimer = null      // [추가] 유출 검사용 디바운스 타이머
  let isDetailOpen = false
  let isMinimized = false

  // [추가] 유출 검사 결과 캐시 (동일 비밀번호 중복 API 호출 방지)
  const leakCache = new Map()
  const LEAK_DELAY = 700          // 입력 멈춘 후 0.7초 뒤 검사

  // 로그인 성공 판단을 위한 임시 상태 변수
  let lastTypedPassword = ''

  // 드래그 상태 변수
  let isDragging = false
  let offset = { x: 0, y: 0 }

  // [추가] 주민번호 입력창인지 확인하는 함수
  function isJuminInput(el) {
    if (!el) return false
    const keywords = ['jumin', 'rrn', 'ssn', 'regno', 'resident', 'residentno']
    const attrs = [
      el.id,
      el.name,
      el.getAttribute('title'),
      el.getAttribute('placeholder'),
      el.className,
    ]

    return attrs.some((attr) => {
      if (!attr) return false
      const lowerAttr = attr.toLowerCase()
      return keywords.some((key) => lowerAttr.includes(key))
    })
  }

  // ─── 패널 생성 및 초기화 ──────────────────────────────────────────────────────
  function createPanel() {
    if (document.getElementById(PANEL_ID)) {
      panel = document.getElementById(PANEL_ID)
      return
    }

    panel = document.createElement('div')
    panel.id = PANEL_ID
    panel.className = 'pwguard-panel'
    panel.style.cssText =
      'position: absolute; z-index: 2147483647; display: none;'

    panel.innerHTML = `
      <div class="pwguard-header" style="cursor: move;" title="드래그 이동 / 더블클릭 최소화">
        <span class="pwguard-title">🔒 비밀번호 보안 분석</span>
        <div class="pwguard-controls">
          <button class="pwguard-minimize-btn" title="최소화">-</button>
          <button class="pwguard-close" aria-label="닫기">✕</button>
        </div>
      </div>
      <div class="pwguard-body">
        <div class="pwguard-score-row">
          <span class="pwguard-status-badge">—</span>
          <span class="pwguard-score-text">입력 대기 중</span>
        </div>
        <div class="pwguard-strength-bar-wrap">
          <div class="pwguard-strength-bar" style="width:0%"></div>
        </div>
        <ul class="pwguard-warnings"></ul>

        <div class="pwguard-reuse-section" style="display:none">
          <div class="pwguard-reuse-header">
            <span class="pwguard-reuse-badge">⚠️ 재사용 감지</span>
            <button class="pwguard-detail-toggle">자세히 보기 ▾</button>
          </div>
          <ul class="pwguard-reuse-warnings"></ul>
          <ul class="pwguard-reuse-details" style="display:none"></ul>
        </div>

        <div class="pwguard-longuse-section" style="display:none">
          <span class="pwguard-longuse-badge">🕐 장기 사용 감지</span>
          <ul class="pwguard-longuse-warnings"></ul>
        </div>

        <div class="pwguard-leak-section pwguard-leak-row" style="display:none">
          <span class="pwguard-leak-dot"></span>
          <span class="pwguard-leak-label">유출 이력 있음</span>
          <span class="pwguard-leak-sub pwguard-leak-count"></span>
        </div>

        <div class="pwguard-leak-safe-section pwguard-leak-row" style="display:none">
          <span class="pwguard-leak-dot"></span>
          <span class="pwguard-leak-label">유출 이력 없음</span>
        </div>

        <div class="pwguard-leak-checking pwguard-leak-row" style="display:none">
          <span class="pwguard-leak-dot"></span>
          <span class="pwguard-leak-label">유출 여부 확인 중...</span>
        </div>
      </div>
    `

    document.body.appendChild(panel)
    setupPanelEvents()
  }

  function setupPanelEvents() {
    const header = panel.querySelector('.pwguard-header')

    header.addEventListener('mousedown', (e) => {
      if (e.target.tagName === 'BUTTON') return
      isDragging = true
      const rect = panel.getBoundingClientRect()
      offset.x = e.clientX - rect.left
      offset.y = e.clientY - rect.top
      document.addEventListener('mousemove', onMouseMove)
      document.addEventListener('mouseup', onMouseUp)
    })

    header.addEventListener('dblclick', (e) => {
      if (e.target.tagName !== 'BUTTON') toggleMinimize()
    })

    panel.querySelector('.pwguard-minimize-btn').onclick = (e) => {
      e.stopPropagation()
      toggleMinimize()
    }

    panel.querySelector('.pwguard-close').onclick = (e) => {
      e.stopPropagation()
      hidePanel()
    }

    panel.querySelector('.pwguard-detail-toggle').onclick = (e) => {
      isDetailOpen = !isDetailOpen
      const detailList = panel.querySelector('.pwguard-reuse-details')
      detailList.style.display = isDetailOpen ? 'block' : 'none'
      e.target.textContent = isDetailOpen ? '접기 ▴' : '자세히 보기 ▾'
    }
  }

  // ─── 드래그 및 위치 제어 ──────────────────────────────────────────────────────
  function onMouseMove(e) {
    if (!isDragging || !panel) return
    panel.style.left = e.clientX - offset.x + window.scrollX + 'px'
    panel.style.top = e.clientY - offset.y + window.scrollY + 'px'
  }

  function onMouseUp() {
    isDragging = false
    document.removeEventListener('mousemove', onMouseMove)
    document.removeEventListener('mouseup', onMouseUp)
  }

  function positionPanel(inputEl) {
    if (!panel || !inputEl || isDragging) return
    const rect = inputEl.getBoundingClientRect()
    const panelWidth = 280
    let left = rect.right + window.scrollX + 12
    let top = rect.top + window.scrollY

    if (left + panelWidth > window.innerWidth + window.scrollX - 12) {
      left = rect.left + window.scrollX - panelWidth - 12
      if (left < 10) {
        left = rect.left + window.scrollX
        top = rect.bottom + window.scrollY + 12
      }
    }
    panel.style.left = left + 'px'
    panel.style.top = top + 'px'
  }

  function toggleMinimize() {
    isMinimized = !isMinimized
    panel.classList.toggle('minimized', isMinimized)
    panel.querySelector('.pwguard-minimize-btn').textContent = isMinimized
      ? '+'
      : '-'
  }

  function hidePanel() {
    if (panel) panel.style.display = 'none'
    isDetailOpen = false
  }

  // ─── 렌더링 엔진 (통합 업데이트) ──────────────────────────────────────────────
  function renderStrength(result) {
    if (!panel) return
    const badge = panel.querySelector('.pwguard-status-badge')
    const scoreText = panel.querySelector('.pwguard-score-text')
    const bar = panel.querySelector('.pwguard-strength-bar')
    const warningList = panel.querySelector('.pwguard-warnings')

    const statusMap = {
      danger: { label: '위험', cls: 'status-danger' },
      normal: { label: '보통', cls: 'status-normal' },
      safe: { label: '안전', cls: 'status-safe' },
    }
    const s = statusMap[result.status] || statusMap.danger

    badge.textContent = s.label
    badge.className = `pwguard-status-badge ${s.cls}`
    scoreText.textContent = `점수: ${result.score}점`
    bar.style.width = Math.min(100, Math.max(0, result.score)) + '%'
    bar.className = `pwguard-strength-bar bar-${result.status}`
    warningList.innerHTML = (result.warnings || [])
      .map((w) => `<li class="pwguard-warning-item">${w}</li>`)
      .join('')
  }

  function renderReuse(reuseResult) {
    if (!panel) return

    const msgs = window.buildReuseMessages
      ? window.buildReuseMessages(reuseResult)
      : { warnings: [], details: [], allSites: [] }
    const { warnings = [], details = [], allSites = [] } = msgs

    const reuseSection = panel.querySelector('.pwguard-reuse-section')
    const reuseWarnList = panel.querySelector('.pwguard-reuse-warnings')
    const reuseDetailList = panel.querySelector('.pwguard-reuse-details')

    if (reuseResult.isReused) {
      reuseSection.style.display = 'block'
      reuseWarnList.innerHTML = warnings
        .filter((w) => !w.includes('일째'))
        .map((w) => `<li>${w}</li>`)
        .join('')

      reuseDetailList.innerHTML = ''
      details.forEach((d) => {
        const li = document.createElement('li')
        li.className = 'pwguard-detail-item'
        li.textContent = d
        reuseDetailList.appendChild(li)
      })

      if (allSites && allSites.length > 0) {
        const PREVIEW_LIMIT = 3
        const preview = allSites.slice(0, PREVIEW_LIMIT)
        const extra = allSites.slice(PREVIEW_LIMIT)

        const previewLi = document.createElement('li')
        previewLi.className = 'pwguard-detail-item'
        previewLi.textContent = `사용된 사이트: ${preview.join(', ')}`
        reuseDetailList.appendChild(previewLi)

        if (extra.length > 0) {
          const moreLi = document.createElement('li')
          moreLi.className = 'pwguard-detail-item'
          const moreBtn = document.createElement('button')
          moreBtn.className = 'pwguard-site-more-btn'
          moreBtn.textContent = `외 ${extra.length}개 더 보기 ▾`

          const extraUl = document.createElement('ul')
          extraUl.className = 'pwguard-site-extra-list'
          extraUl.style.display = 'none'
          extra.forEach((s) => {
            const li = document.createElement('li')
            li.textContent = s
            extraUl.appendChild(li)
          })

          moreBtn.onclick = () => {
            const isOpen = extraUl.style.display === 'block'
            extraUl.style.display = isOpen ? 'none' : 'block'
            moreBtn.textContent = isOpen
              ? `외 ${extra.length}개 더 보기 ▾`
              : '접기 ▴'
          }

          moreLi.appendChild(moreBtn)
          moreLi.appendChild(extraUl)
          reuseDetailList.appendChild(moreLi)
        }
      }
      reuseDetailList.style.display = isDetailOpen ? 'block' : 'none'
    } else {
      reuseSection.style.display = 'none'
    }

    const longSec = panel.querySelector('.pwguard-longuse-section')
    if (reuseResult.isLongUsed) {
      longSec.style.display = 'block'
      panel.querySelector('.pwguard-longuse-warnings').innerHTML = warnings
        .filter((w) => w.includes('일째'))
        .map((w) => `<li>${w}</li>`)
        .join('')
    } else {
      longSec.style.display = 'none'
    }
  }

  // ─── 유출 검사 렌더링 ────────────────────────────────────────────────────────
  function renderLeakChecking(isChecking) {
    if (!panel) return
    const checkingEl      = panel.querySelector('.pwguard-leak-checking')
    const leakSection     = panel.querySelector('.pwguard-leak-section')
    const leakSafeSection = panel.querySelector('.pwguard-leak-safe-section')
    if (!checkingEl) return

    if (isChecking) {
      leakSection.style.display     = 'none'
      leakSafeSection.style.display = 'none'
      checkingEl.style.display      = 'flex'
    } else {
      checkingEl.style.display = 'none'
    }
  }

  function renderLeak(leakResult) {
    if (!panel) return

    const leakSection    = panel.querySelector('.pwguard-leak-section')
    const leakSafeSection = panel.querySelector('.pwguard-leak-safe-section')
    const checkingEl     = panel.querySelector('.pwguard-leak-checking')
    const countEl        = panel.querySelector('.pwguard-leak-count')

    // 셋 다 일단 숨김
    leakSection.style.display    = 'none'
    leakSafeSection.style.display = 'none'
    checkingEl.style.display     = 'none'

    if (leakResult === null) return   // 검사 전 → 모두 숨김

    if (leakResult.leaked) {
      leakSection.style.display = 'flex'
      // 유출 횟수가 있으면 서브텍스트로 표시
      if (countEl) {
        countEl.textContent = leakResult.count
          ? `(${leakResult.count.toLocaleString()}회 노출)`
          : ''
      }
    } else {
      leakSafeSection.style.display = 'flex'
    }
  }

  // ─── 이벤트 핸들러 ──────────────────────────────────────────────────────────
  function handleInput(e) {
    const input = e.target
    const value = input.value
    const domain = getSiteName()

    // [수정] 나중에 로그인 성공 시 사용하기 위해 입력값 보관
    lastTypedPassword = value

    // 주민번호 필드인 경우 분석 패널 업데이트 중단
    if (isJuminInput(input)) return

    positionPanel(input)

    clearTimeout(strengthDebounceTimer)
    strengthDebounceTimer = setTimeout(() => {
      const raw = window.PwAnalyzer?.evaluatePassword(value, {
        siteName: domain,
        reuseCount: 0,
      })
      renderStrength(normalizeAnalyzerResult(raw))
    }, DEBOUNCE_DELAY)

    clearTimeout(reuseDebounceTimer)
    if (value.length >= 4) {
      reuseDebounceTimer = setTimeout(async () => {
        try {
          const reuseResult = await window.analyzeReuse(value, domain)
          renderReuse(reuseResult)
          const updatedRaw = window.PwAnalyzer?.evaluatePassword(value, {
            siteName: domain,
            reuseCount: reuseResult.reuseCount,
          })
          renderStrength(normalizeAnalyzerResult(updatedRaw))
        } catch (err) {
          console.warn('[PwGuard] Analysis delay:', err)
        }
      }, REUSE_DELAY)
    }

    // ─── 유출 검사 (입력 멈춘 후 LEAK_DELAY ms 뒤 실행) ────────────────────
    clearTimeout(leakDebounceTimer)
    if (value.length >= 4) {
      // 입력 중엔 이전 결과 초기화 + 로딩 표시
      renderLeak(null)
      leakDebounceTimer = setTimeout(async () => {
        // 캐시 확인 (동일 비밀번호 반복 입력 시 API 재호출 방지)
        if (leakCache.has(value)) {
          const cached = leakCache.get(value)
          renderLeak(cached)
          // 유출된 경우 점수에도 반영
          if (cached.leaked) {
            const leakedRaw = window.PwAnalyzer?.evaluatePassword(value, {
              siteName: domain,
              reuseCount: 0,
              leaked: true,
            })
            renderStrength(normalizeAnalyzerResult(leakedRaw))
          }
          return
        }

        try {
          renderLeakChecking(true)
          const sha1Hash = await window.PwUtils?.sha1Hex(value)
          if (!sha1Hash) return

          const leakResult = await chrome.runtime.sendMessage({
            action: 'checkLeaked',
            payload: { sha1Hash },
          })

          leakCache.set(value, leakResult)   // 결과 캐싱
          renderLeak(leakResult)

          // 유출된 경우 강도 점수에 반영 (analyzer.js의 leaked 플래그 활용)
          if (leakResult.leaked) {
            const leakedRaw = window.PwAnalyzer?.evaluatePassword(value, {
              siteName: domain,
              reuseCount: 0,
              leaked: true,
            })
            renderStrength(normalizeAnalyzerResult(leakedRaw))
          }
        } catch (err) {
          renderLeakChecking(false)
          console.warn('[PwGuard] 유출 검사 오류:', err)
        }
      }, LEAK_DELAY)
    } else {
      renderLeak(null)  // 4자 미만이면 유출 섹션 숨김
    }
  }

  // 로그인 시도를 추적하는 로직
  function trackLoginAttempt() {
    // 주민번호 필드인 경우 서버 저장을 원천 차단
    if (activeInput && isJuminInput(activeInput)) {
      console.log('[PwGuard] 주민번호 필드로 감지되어 기록을 생략합니다.')
      return
    }

    if (lastTypedPassword.length < 4) return

    const domain = getSiteName()
    window.PwUtils?.sha1Hex(lastTypedPassword).then((hash) => {
      chrome.runtime.sendMessage({
        action: 'attemptLogin',
        payload: { hash, domain },
      })
    })
  }

  function attachEvents(root) {
    const selector = 'input[type="password"]'
    const inputs = root.querySelectorAll ? root.querySelectorAll(selector) : []
    inputs.forEach((input) => {
      if (input.dataset.pwguardAttached) return
      input.dataset.pwguardAttached = 'true'
      input.addEventListener('focus', (e) => {
        // [수정] 주민번호 필드라면 분석 패널을 아예 띄우지 않음
        if (isJuminInput(e.target)) return

        activeInput = e.target
        createPanel()
        positionPanel(e.target)
        panel.style.display = 'block'
      })
      input.addEventListener('input', handleInput)
      input.addEventListener('blur', () => {
        setTimeout(() => {
          if (!isDragging && !panel?.contains(document.activeElement))
            hidePanel()
        }, 150)
      })

      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') trackLoginAttempt()
      })
    })

    const submitButtons = root.querySelectorAll(
      'button[type="submit"], input[type="submit"], .login-btn, #login-btn',
    )
    submitButtons.forEach((btn) => {
      btn.addEventListener('click', trackLoginAttempt)
    })
  }

  // ─── 초기화 ──────────────────────────────────────────────────────────────────
  function init() {
    createPanel()
    attachEvents(document)
    new MutationObserver((m) =>
      m.forEach((r) =>
        r.addedNodes.forEach((n) => {
          if (n.nodeType === 1)
            attachEvents(
              n.matches('input[type="password"]') ? n.parentElement : n,
            )
        }),
      ),
    ).observe(document.body, { childList: true, subtree: true })
  }

  if (document.readyState === 'loading')
    document.addEventListener('DOMContentLoaded', init)
  else init()
})()