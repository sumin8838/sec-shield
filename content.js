/**
 * content.js
 * 비밀번호 입력 감지, 분석 패널 생성 및 결과 표시를 담당하는 메인 컨트롤러.
 * analyzer.js (강도 분석) + reuse.js (재사용 탐지) + utils.js (공통 유틸)에 의존합니다.
 */

// ─── utils.js / analyzer.js 브릿지 ──────────────────────────────────────────
// utils.js가 window.PwUtils 네임스페이스로 노출되므로 전역 함수로 연결합니다.
function debounce(fn, delay) {
  return window.PwUtils.debounce(fn, delay)
}
function getSiteName() {
  const host = window.location.hostname || ''
  const parts = host.replace(/^www\./, '').split('.')
  return parts.length >= 2 ? parts[parts.length - 2] : parts[0]
}
function isVisiblePasswordInput(el) {
  return window.PwUtils.isPasswordInput(el)
}
async function sha1(text) {
  return window.PwUtils.sha1Hex(text)
}
// analyzer.js가 window.PwAnalyzer 네임스페이스로 노출되므로 전역 함수로 연결합니다.
function analyzePassword(password, siteName, reuseCount = 0) {
  return window.PwAnalyzer.evaluatePassword(password, { siteName, reuseCount })
}

// ─── renderStrength 상태값 변환 브릿지 ──────────────────────────────────────
// analyzer.js는 statusClass('danger'/'normal'/'safe')를 반환하고
// renderStrength는 status 키를 사용하므로 맞춰줍니다.
function normalizeAnalyzerResult(result) {
  return {
    score: result.score,
    status: result.statusClass || 'danger',
    warnings: result.warnings || [],
  }
}

;(function () {
  'use strict'

  // ─── 상수 ────────────────────────────────────────────────────────────────────
  const PANEL_ID = 'pwguard-panel'
  const PANEL_CLASS = 'pwguard-panel'
  const DEBOUNCE_DELAY = 300
  const REUSE_DELAY = 800

  // ─── 상태 ────────────────────────────────────────────────────────────────────
  let activeInput = null
  let panel = null
  let strengthDebounceTimer = null
  let reuseDebounceTimer = null
  let isDetailOpen = false

  // ─── 패널 생성 ───────────────────────────────────────────────────────────────
  function createPanel() {
    if (document.getElementById(PANEL_ID)) {
      panel = document.getElementById(PANEL_ID)
      return
    }

    panel = document.createElement('div')
    panel.id = PANEL_ID
    panel.className = PANEL_CLASS
    panel.setAttribute('role', 'status')
    panel.setAttribute('aria-live', 'polite')

    panel.innerHTML = `
      <div class="pwguard-header">
        <span class="pwguard-title">🔒 비밀번호 보안 분석</span>
        <button class="pwguard-close" aria-label="닫기">✕</button>
      </div>
      <div class="pwguard-body">
        <div class="pwguard-score-row">
          <span class="pwguard-status-badge">—</span>
          <span class="pwguard-score-text">입력 대기 중</span>
        </div>
        <div class="pwguard-strength-bar-wrap">
          <div class="pwguard-strength-bar" style="width:0%"></div>
        </div>
        <ul class="pwguard-warnings" aria-label="경고 목록"></ul>

        <div class="pwguard-reuse-section" style="display:none">
          <div class="pwguard-reuse-header">
            <span class="pwguard-reuse-badge">⚠ 재사용 감지</span>
            <button class="pwguard-detail-toggle" aria-expanded="false">자세히 보기 ▾</button>
          </div>
          <ul class="pwguard-reuse-warnings" aria-label="재사용 경고"></ul>
          <ul class="pwguard-reuse-details" aria-label="재사용 상세 정보" style="display:none"></ul>
        </div>

        <div class="pwguard-longuse-section" style="display:none">
          <span class="pwguard-longuse-badge">🕐 장기 사용 감지</span>
          <ul class="pwguard-longuse-warnings" aria-label="장기 사용 경고"></ul>
        </div>
      </div>
    `

    document.body.appendChild(panel)

    panel.querySelector('.pwguard-close').addEventListener('click', () => {
      hidePanel()
    })

    panel
      .querySelector('.pwguard-detail-toggle')
      .addEventListener('click', () => {
        isDetailOpen = !isDetailOpen
        const detailList = panel.querySelector('.pwguard-reuse-details')
        const toggleBtn = panel.querySelector('.pwguard-detail-toggle')
        detailList.style.display = isDetailOpen ? 'block' : 'none'
        toggleBtn.textContent = isDetailOpen ? '접기 ▴' : '자세히 보기 ▾'
        toggleBtn.setAttribute('aria-expanded', String(isDetailOpen))
      })
  }

  // ─── 패널 위치 계산 ──────────────────────────────────────────────────────────
  function positionPanel(inputEl) {
    if (!panel || !inputEl) return

    const rect = inputEl.getBoundingClientRect()
    const panelWidth = 280
    const panelHeight = panel.offsetHeight || 200
    const vpWidth = window.innerWidth
    const vpHeight = window.innerHeight

    let left, top

    if (rect.right + panelWidth + 12 <= vpWidth) {
      left = rect.right + 12
      top = rect.top
    } else if (rect.left - panelWidth - 12 >= 0) {
      left = rect.left - panelWidth - 12
      top = rect.top
    } else {
      left = rect.left
      top = rect.bottom + 8
    }

    if (top + panelHeight > vpHeight) {
      top = vpHeight - panelHeight - 12
    }
    top = Math.max(top, 8)
    left = Math.max(left, 8)

    panel.style.left = left + 'px'
    panel.style.top = top + 'px'
  }

  function showPanel(inputEl) {
    if (!panel) createPanel()
    panel.style.display = 'block'
    positionPanel(inputEl)
  }

  function hidePanel() {
    if (panel) panel.style.display = 'none'
    isDetailOpen = false
  }

  // ─── 강도 분석 UI 업데이트 ───────────────────────────────────────────────────
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
    badge.className = 'pwguard-status-badge ' + s.cls

    scoreText.textContent = `점수: ${result.score}점`

    const pct = Math.min(100, Math.max(0, result.score))
    bar.style.width = pct + '%'
    bar.className = 'pwguard-strength-bar bar-' + result.status

    warningList.innerHTML = ''
    ;(result.warnings || []).forEach((w) => {
      const li = document.createElement('li')
      li.className = 'pwguard-warning-item'
      li.textContent = w
      warningList.appendChild(li)
    })
  }

  // ─── 재사용 탐지 UI 업데이트 ─────────────────────────────────────────────────
  function renderReuse(reuseResult) {
    if (!panel) return

    const { warnings, details, allSites } = buildReuseMessages(reuseResult)

    const reuseSection = panel.querySelector('.pwguard-reuse-section')
    const reuseWarnList = panel.querySelector('.pwguard-reuse-warnings')
    const reuseDetailList = panel.querySelector('.pwguard-reuse-details')

    if (reuseResult.isReused) {
      reuseSection.style.display = 'block'

      // 경고 메시지
      reuseWarnList.innerHTML = ''
      warnings
        .filter((w) => !w.includes('일째'))
        .forEach((w) => {
          const li = document.createElement('li')
          li.className = 'pwguard-warning-item'
          li.textContent = w
          reuseWarnList.appendChild(li)
        })

      // 상세 정보 + 사이트 목록 토글
      reuseDetailList.innerHTML = ''

      // 기본 상세 항목 (사이트 수, 횟수)
      details.forEach((d) => {
        const li = document.createElement('li')
        li.className = 'pwguard-detail-item'
        li.textContent = d
        reuseDetailList.appendChild(li)
      })

      // 사이트 목록 토글 (3개 이하면 바로 표시, 초과면 "더 보기" 토글)
      if (allSites.length > 0) {
        const PREVIEW = 3
        const previewSites = allSites.slice(0, PREVIEW)
        const extraSites = allSites.slice(PREVIEW)

        // 미리보기 3개
        const sitePreviewLi = document.createElement('li')
        sitePreviewLi.className = 'pwguard-detail-item'
        sitePreviewLi.textContent = `사용된 사이트: ${previewSites.join(', ')}`
        reuseDetailList.appendChild(sitePreviewLi)

        // 초과 사이트가 있으면 토글 추가
        if (extraSites.length > 0) {
          // "외 N개 더 보기" 버튼
          const moreLi = document.createElement('li')
          moreLi.className = 'pwguard-detail-item'

          const moreBtn = document.createElement('button')
          moreBtn.className = 'pwguard-site-more-btn'
          moreBtn.textContent = `외 ${extraSites.length}개 더 보기 ▾`
          moreLi.appendChild(moreBtn)
          reuseDetailList.appendChild(moreLi)

          // 숨겨진 사이트 목록
          const extraUl = document.createElement('ul')
          extraUl.className = 'pwguard-site-extra-list'
          extraUl.style.display = 'none'
          extraSites.forEach((site) => {
            const li = document.createElement('li')
            li.className = 'pwguard-detail-item'
            li.textContent = site
            extraUl.appendChild(li)
          })
          reuseDetailList.appendChild(extraUl)

          // 토글 동작
          let siteListOpen = false
          moreBtn.addEventListener('click', () => {
            siteListOpen = !siteListOpen
            extraUl.style.display = siteListOpen ? 'block' : 'none'
            moreBtn.textContent = siteListOpen
              ? `접기 ▴`
              : `외 ${extraSites.length}개 더 보기 ▾`
          })
        }
      }

      reuseDetailList.style.display = isDetailOpen ? 'block' : 'none'
    } else {
      reuseSection.style.display = 'none'
    }

    // 장기 사용 섹션
    const longUseSection = panel.querySelector('.pwguard-longuse-section')
    const longUseList = panel.querySelector('.pwguard-longuse-warnings')

    if (reuseResult.isLongUsed) {
      longUseSection.style.display = 'block'
      longUseList.innerHTML = ''
      warnings
        .filter((w) => w.includes('일째'))
        .forEach((w) => {
          const li = document.createElement('li')
          li.className = 'pwguard-warning-item'
          li.textContent = w
          longUseList.appendChild(li)
        })
    } else {
      longUseSection.style.display = 'none'
    }
  }

  // ─── 입력 이벤트 핸들러 ──────────────────────────────────────────────────────
  function handleInput(e) {
    const input = e.target
    const value = input.value
    const domain = getSiteName()

    positionPanel(input)

    // 1. 강도 분석 - 재사용 횟수 없이 먼저 빠르게 표시
    clearTimeout(strengthDebounceTimer)
    strengthDebounceTimer = setTimeout(() => {
      const raw = analyzePassword(value, domain, 0)
      renderStrength(normalizeAnalyzerResult(raw))
    }, DEBOUNCE_DELAY)

    // 2. 재사용 탐지 후 → 재사용 횟수 반영해서 점수 재계산
    clearTimeout(reuseDebounceTimer)
    if (value.length >= 4) {
      reuseDebounceTimer = setTimeout(async () => {
        try {
          const reuseResult = await analyzeReuse(value, domain)
          renderReuse(reuseResult)

          // 재사용 횟수를 반영하여 점수 재계산
          const raw = analyzePassword(value, domain, reuseResult.reuseCount)
          renderStrength(normalizeAnalyzerResult(raw))
        } catch (err) {
          console.warn('[PwGuard] reuse analysis error:', err)
        }
      }, REUSE_DELAY)
    } else {
      renderReuse({
        isReused: false,
        isLongUsed: false,
        otherSites: [],
        reuseCount: 0,
        daysOnSite: 0,
      })
    }
  }

  function handleFocus(e) {
    const input = e.target
    if (!isVisiblePasswordInput(input)) return
    activeInput = input
    showPanel(input)
  }

  function handleBlur() {
    setTimeout(() => {
      if (
        document.activeElement &&
        panel &&
        panel.contains(document.activeElement)
      )
        return
      hidePanel()
      activeInput = null
    }, 150)
  }

  // ─── 비밀번호 입력창 감지 ────────────────────────────────────────────────────
  function attachToPasswordInputs(root) {
    const inputs = root.querySelectorAll('input[type="password"]')
    inputs.forEach((input) => {
      if (input.dataset.pwguardAttached) return
      input.dataset.pwguardAttached = 'true'
      input.addEventListener('focus', handleFocus)
      input.addEventListener('blur', handleBlur)
      input.addEventListener('input', handleInput)
    })
  }

  // ─── MutationObserver ────────────────────────────────────────────────────────
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue
        if (node.matches && node.matches('input[type="password"]')) {
          attachToPasswordInputs(node.parentElement || document)
        } else if (node.querySelector) {
          attachToPasswordInputs(node)
        }
      }
    }
  })

  // ─── 창 크기/스크롤 대응 ─────────────────────────────────────────────────────
  window.addEventListener(
    'resize',
    debounce(() => {
      if (activeInput && panel && panel.style.display !== 'none') {
        positionPanel(activeInput)
      }
    }, 200),
  )

  window.addEventListener(
    'scroll',
    debounce(() => {
      if (activeInput && panel && panel.style.display !== 'none') {
        positionPanel(activeInput)
      }
    }, 100),
    true,
  )

  // ─── 초기화 ──────────────────────────────────────────────────────────────────
  function init() {
    createPanel()
    hidePanel()
    attachToPasswordInputs(document)
    observer.observe(document.body, { childList: true, subtree: true })
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init)
  } else {
    init()
  }
})()
